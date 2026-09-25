#!/usr/bin/env bash
# =====================================================================================
# run_local_subset.sh - the local-model experiment: evaluation of dataset/local_subset with an LLM served
# by LM Studio on this computer (no code, chain or prompt leaves the machine).
#
#   1. loads the model with a context long enough for the longest prompt of the subset (~16.7k tokens plus
#      the answer), with 4, else 2, else 1 parallel predictions. LM Studio silently shrinks the context
#      to what fits in GPU memory, so the loaded context is read back and checked;
#   2. sends a ~16k-token test prompt and stops if it is rejected (nothing is evaluated with a short context);
#   3. evaluates the malware and benign subset for every RAG mode -> results/<version>_<mode>_lmstudio/.
# Resumable: stop it at any point (Ctrl+C) and run it again; finished packages are skipped.
# The computer is kept awake while it runs (leave a laptop plugged in with the lid open).
#
#   bash results/run_local_subset.sh [MODE ...]      (default: sum llm)
#   python3 results/progress.py --watch 60            (progress, in a second terminal)
#
# Settings (environment): LM_STUDIO_MODEL (google/gemma-4-26b-a4b), LM_CONTEXT (20480), MIN_CONTEXT (18000).
# On a 24 GB Mac the 15 GB model leaves no room for a long context under the default GPU memory limit;
# raise it first (the setting resets on reboot):   sudo sysctl iogpu.wired_limit_mb=20480
# =====================================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="python3"
LMS="$HOME/.lmstudio/bin/lms"; command -v lms >/dev/null 2>&1 && LMS=lms
URL="${LM_STUDIO_URL:-http://localhost:1234/v1}"
CONTEXT="${LM_CONTEXT:-20480}"; MIN_CONTEXT="${MIN_CONTEXT:-18000}"
MODES=("$@"); [ ${#MODES[@]} -gt 0 ] || MODES=(sum llm)
# local provider; the embedding model is read from the local cache without any network check
export LLM_PROVIDER=lmstudio LM_STUDIO_MODEL="${LM_STUDIO_MODEL:-google/gemma-4-26b-a4b}" LM_STUDIO_URL="$URL"
export HF_HUB_OFFLINE=1
log() { echo "[$(date +%H:%M:%S)] $*"; }
cd "$ROOT" || exit 1

# keep the computer awake for as long as this script runs
caffeinate -is -w $$ &

loaded_context() {  # context length of the loaded model (0 if it is not loaded)
  curl -s "${URL%/v1}/api/v0/models" | "$PY" -c 'import json, os, sys
m = [x for x in json.load(sys.stdin)["data"] if x["id"] == os.environ["LM_STUDIO_MODEL"] and x.get("state") == "loaded"]
print(m[0].get("loaded_context_length", 0) if m else 0)' 2>/dev/null || echo 0
}

# 1. load the model with the largest parallelism whose context is long enough
curl -s -o /dev/null "${URL%/v1}/api/v0/models" || { "$LMS" server start >/dev/null 2>&1; sleep 3; }
parallel=0
for p in 4 2 1; do
  "$LMS" unload --all >/dev/null 2>&1
  log "loading $LM_STUDIO_MODEL (context $CONTEXT, $p parallel)"
  "$LMS" load "$LM_STUDIO_MODEL" -c "$CONTEXT" --parallel "$p" -y >/dev/null 2>&1
  ctx=$(loaded_context)
  log "  loaded context: $ctx tokens"
  if [ "$ctx" -ge "$MIN_CONTEXT" ]; then parallel=$p; break; fi
done
if [ "$parallel" -eq 0 ]; then
  log "[!] the context stays below $MIN_CONTEXT tokens: not enough GPU memory. Raise the limit and run again:"
  log "    sudo sysctl iogpu.wired_limit_mb=20480"
  exit 1
fi

# 2. a prompt as long as the longest of the subset must be accepted
"$PY" - <<'EOF' || { log "[!] the ~16k-token test prompt was rejected - nothing was evaluated"; exit 1; }
import os, time
from openai import OpenAI
client = OpenAI(base_url=os.environ["LM_STUDIO_URL"], api_key="lm-studio")
start = time.time()
r = client.chat.completions.create(
    model=os.environ["LM_STUDIO_MODEL"], max_tokens=10, extra_body={"reasoning_effort": "none"},
    messages=[{"role": "user", "content": "The quick brown fox jumps over the lazy dog. " * 1650 + "\nReply OK."}])
print(f"[+] test prompt of {r.usage.prompt_tokens} tokens accepted ({time.time() - start:.0f} s)")
EOF

# 3. the evaluation (the subset folders are symlinks, recreated from local_subset.json if missing)
[ -d dataset/local_subset/malware ] || "$PY" dataset/preparation/select_local_subset.py
for m in "${MODES[@]}"; do
  for s in malware benign; do
    log "RAG_MODE=$m - dataset/local_subset/$s ($parallel parallel)"
    RAG_MODE="$m" LLM_MAX_WORKERS="$parallel" "$PY" results/check_test_set.py "dataset/local_subset/$s"
  done
done
log "done - summary: $PY results/progress.py"

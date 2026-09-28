#!/usr/bin/env bash
# =====================================================================================
# run_v14.sh - the v14 evaluation: every evaluation set with the Full system (sum) and without RAG (llm),
# with DeepSeek and prompt v12 -> results/v14_<mode>/. The configurations run in parallel.
#
#   sets: dataset/rag_test          v12 malware + new samples (dataset/preparation/add_test_samples.py)
#         dataset/benign_test_set   500 benign packages (select_extra_benign.py --extend + run_pipeline.sh benign)
#         dataset/obfuscated/{A,B}_{malware,benign}   obfuscated copies (build_obfuscated_set.py)
#
# Before: bash run_pipeline.sh deps  (dependency findings in the chains files, used by llm_evaluator.py).
# The index and the knowledge base are those of v12, so the packages of v12 are evaluated again under the
# same conditions: v12 vs v14 on them measures the repeatability of the decisions.
# Resumable: stop it at any point (Ctrl+C) and run it again; finished packages are skipped.
#
#   bash results/run_v14.sh [MODE ...]          (default: sum llm)
#   logs: logs/v14_<mode>_<set>.log
# =====================================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="python3"
MODES=("$@"); [ ${#MODES[@]} -gt 0 ] || MODES=(sum llm)
SETS=(dataset/rag_test dataset/benign_test_set
      dataset/obfuscated/A_malware dataset/obfuscated/A_benign dataset/obfuscated/B_malware dataset/obfuscated/B_benign)
export LLM_PROVIDER=deepseek
log() { echo "[$(date +%H:%M:%S)] $*"; }
cd "$ROOT" || exit 1
mkdir -p logs

# keep the computer awake for as long as this script runs
caffeinate -ims -w $$ &

for m in "${MODES[@]}"; do
  (
    for s in "${SETS[@]}"; do
      if [ ! -d "$s" ]; then log "v14_$m: $s is missing - skipped"; continue; fi
      log "v14_$m: $s"
      RESULTS_TAG="v14_$m" RAG_MODE="$m" "$PY" results/check_test_set.py "$s" > "logs/v14_${m}_$(basename "$s").log" 2>&1
    done
    log "v14_$m: done"
  ) &
done
wait
log "all done - progress/metrics: $PY results/evaluation_summary.py v14_sum v14_llm"

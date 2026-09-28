#!/usr/bin/env bash
# =====================================================================================
# run_pipeline.sh - automated, repeatable execution of the pipeline.
# Every stage resumes where it stopped (anything that already has a result is skipped).
# Instructions: PIPELINE.md
#
#   ./run_pipeline.sh setup        first installation: .env, venv + requirements, CodeQL packs
#   ./run_pipeline.sh check        check the prerequisites (venv, CodeQL, sources, LLM key)
#   ./run_pipeline.sh status       where the pipeline stands (analysed, failures, RAG, results)
#   ./run_pipeline.sh sources      clone missing sources + git pull the existing ones (new packages)
#   ./run_pipeline.sh collect      list of malware samples (malware_dataset*.json) + MalwareBench false positives
#   ./run_pipeline.sh analyze      CodeQL ONLY for malware without a result (WORKERS in parallel) + payload scan
#   ./run_pipeline.sh benign       CodeQL for the missing benign packages (sdists from PyPI)
#   ./run_pipeline.sh policy       rebuild the security knowledge base (NEW snapshot of its sources)
#   ./run_pipeline.sh rag          selection, family split, index + audit
#   ./run_pipeline.sh addtest      NEW malware samples -> evaluation set only (index and split unchanged)
#   ./run_pipeline.sh obfuscate    obfuscated copies of 100+100 evaluation packages (2 levels) + CodeQL
#   ./run_pipeline.sh deps         dependency graph of every evaluation package vs known malicious packages
#   ./run_pipeline.sh evaluate     LLM evaluation for every RAG_MODE in MODES
#   ./run_pipeline.sh update       sources -> collect -> analyze -> rag  (update with new packages)
#   ./run_pipeline.sh all          collect -> analyze -> benign -> rag -> evaluate
#   ./run_pipeline.sh pack         Behavior Chains, train/test, indexes, dataset JSON into files <=1.9GB
#   ./run_pipeline.sh unpack [DIR] restore them from the pack files (default dist/)
#
# Settings: in .env (see .env.example) or as environment variables (these override .env):
#   THESIS_SOURCES_DIR   folder with the clones of the sources (REQUIRED for sources/collect/analyze)
#   WORKERS=4            parallel CodeQL analyses for malware (BENIGN_WORKERS=2 for benign)
#   RETRY_FAILED=1       also retry malware that has already failed (default: no)
#   MODES="sum samples policy llm"   ablations for evaluate (RESULTS_SUFFIX for another folder)
#   PARALLEL_SETS=1      in evaluate: malware and benign test sets at the same time
#   CODEQL_QUERY_TIMEOUT / CODEQL_DB_TIMEOUT / BATCH_ANALYSIS_TIMEOUT (seconds)
# =====================================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PREP="$ROOT/dataset/preparation"
PIPE="$ROOT/inference/codeql_pipeline"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="python3"
LOGS="$ROOT/logs"
WORK="$ROOT/work"
# Local settings (sources location, API keys) from .env - see .env.example. Same rules as
# utils.load_env_file: anything already set in the shell wins, empty values are ignored.
load_env() {
  local line k v
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"; line="${line#export }"
    { [ -z "$line" ] || [ "${line:0:1}" = "#" ]; } && continue
    k="${line%%=*}"; v="${line#*=}"; [ "$k" = "$line" ] && continue
    k="${k%"${k##*[![:space:]]}"}"
    case "$v" in \"*\") v="${v#\"}"; v="${v%\"}" ;; \'*\') v="${v#\'}"; v="${v%\'}" ;; *) v="${v%% #*}"; v="${v%"${v##*[![:space:]]}"}" ;; esac
    [ -n "$v" ] && [ -z "${!k:-}" ] && export "$k=$v"
  done < "$1"
}
load_env "$ROOT/.env"
WORKERS="${WORKERS:-4}"
BENIGN_WORKERS="${BENIGN_WORKERS:-2}"
MODES="${MODES:-sum samples policy llm}"
[ -n "${THESIS_SOURCES_DIR:-}" ] && export THESIS_SOURCES_DIR
export CODEQL_NO_VENDOR=1
export CODEQL_QUERY_TIMEOUT="${CODEQL_QUERY_TIMEOUT:-600}"
export CODEQL_DB_TIMEOUT="${CODEQL_DB_TIMEOUT:-900}"
export BATCH_ANALYSIS_TIMEOUT="${BATCH_ANALYSIS_TIMEOUT:-1200}"
export BENIGN_ANALYSIS_TIMEOUT="${BENIGN_ANALYSIS_TIMEOUT:-2400}"

# logs/ and work/ are created only when needed (not e.g. for check/status)
cd "$ROOT" || exit 1

log() { mkdir -p "$LOGS"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGS/pipeline.log"; }
die() { log "ERROR: $*"; exit 1; }
run() { log "\$ $*"; "$@" || die "failed: $*"; }

# Keep the computer awake while the script runs (macOS). Do NOT use a bare `wait`: it would also wait
# for caffeinate -> deadlock. Always `wait "${pids[@]}"`.
keep_awake() { if command -v caffeinate >/dev/null 2>&1; then caffeinate -ims -w $$ & fi; }

# The stages that read the raw code need the location of the sources.
need_sources() {
  [ -n "${THESIS_SOURCES_DIR:-}" ] || die "THESIS_SOURCES_DIR is not set (write it in .env or run ./run_pipeline.sh setup)"
  [ -d "$THESIS_SOURCES_DIR" ] || die "sources folder $THESIS_SOURCES_DIR not found (is the disk connected?)"
}

# Which key the selected LLM provider needs (LLM_PROVIDER in .env, see inference/llm_providers.py)
llm_key_var() {
  case "${LLM_PROVIDER:-deepseek}" in
    deepseek) echo DEEPSEEK_API_KEY ;; gemini) echo GEMINI_API_KEY ;; openrouter) echo OPENROUTER_API_KEY ;;
    lmstudio) echo "" ;; *) die "unknown LLM_PROVIDER=${LLM_PROVIDER} (deepseek|gemini|lmstudio|openrouter)" ;;
  esac
}

# Clones of the sources inside THESIS_SOURCES_DIR (folder|repository)
SOURCE_REPOS="malicious-packages|https://github.com/ossf/malicious-packages.git
pypi_malregistry|https://github.com/lxyeternal/pypi_malregistry.git
pypi|https://github.com/MalwareBench/pypi.git
malicious-software-packages-dataset|https://github.com/DataDog/malicious-software-packages-dataset.git
maloss-samples|https://github.com/osssanitizer/maloss-samples.git"

# Private copy of the CodeQL pipeline per worker: parallel analyses never share intermediate files
# (results/, staging).
setup_worker() {
  rm -rf "$1"; mkdir -p "$1/pipeline"
  rsync -a --exclude results --exclude __pycache__ --exclude .DS_Store "$PIPE/" "$1/pipeline/"
  mkdir -p "$1/pipeline/results"
}

# ------------------------------------------------------------------------------ setup
cmd_setup() {
  if [ ! -f "$ROOT/.env" ]; then
    cp "$ROOT/.env.example" "$ROOT/.env"; chmod 600 "$ROOT/.env"
    local src="" key=""
    read -r -p "Folder with the malware sources (USB disk or a folder to clone into): " src
    [ -n "$src" ] && sed -i.bak "s|^THESIS_SOURCES_DIR=.*|THESIS_SOURCES_DIR=\"$src\"|" "$ROOT/.env"
    read -r -s -p "DEEPSEEK_API_KEY (Enter to skip - it can be added to .env later): " key; echo
    [ -n "$key" ] && sed -i.bak "s|^DEEPSEEK_API_KEY=.*|DEEPSEEK_API_KEY=$key|" "$ROOT/.env"
    rm -f "$ROOT/.env.bak"
    load_env "$ROOT/.env"
    log "wrote .env (THESIS_SOURCES_DIR=${src:-<empty>}, key: $([ -n "$key" ] && echo yes || echo no))"
  fi
  if [ ! -x "$ROOT/venv/bin/python" ]; then
    run python3 -m venv "$ROOT/venv"
  fi
  run "$ROOT/venv/bin/pip" install -q -r "$ROOT/requirements.txt"
  PY="$ROOT/venv/bin/python"
  command -v codeql >/dev/null 2>&1 || die "install the CodeQL CLI 2.27.0 (e.g. brew install codeql or https://github.com/github/codeql-action/releases) and run again"
  run codeql pack install "$PIPE/python_queries"
  run codeql pack install "$PIPE/js_queries"
  log "setup: OK - next steps: ./run_pipeline.sh check and (if sources are missing) ./run_pipeline.sh sources"
}

# ------------------------------------------------------------------------------ check
cmd_check() {
  local ok=1
  "$PY" -c "import numpy, sklearn, sentence_transformers, openai" 2>/dev/null \
    && log "venv: OK ($("$PY" --version 2>&1))" || { log "venv: missing packages (numpy/sklearn/sentence-transformers/openai)"; ok=0; }
  command -v codeql >/dev/null 2>&1 && log "CodeQL: $(codeql version --format=terse 2>/dev/null)" \
    || { log "CodeQL: not found in PATH"; ok=0; }
  if [ -n "${THESIS_SOURCES_DIR:-}" ] && [ -d "$THESIS_SOURCES_DIR" ]; then
    local line d
    while IFS= read -r line; do
      d="${line%%|*}"
      [ -d "$THESIS_SOURCES_DIR/$d" ] && log "source: $d OK" || log "source: $d MISSING (./run_pipeline.sh sources)"
    done <<< "$SOURCE_REPOS"
    [ -d "$THESIS_SOURCES_DIR/malware_samples" ] && log "source: malware_samples OK (Datadog samples, from collect)" \
      || log "source: malware_samples missing (created by ./run_pipeline.sh collect)"
  else
    log "sources: THESIS_SOURCES_DIR not set/found (needed only for sources/collect/analyze)"
  fi
  local key_var; key_var="$(llm_key_var)"
  if [ -z "$key_var" ]; then log "LLM: ${LLM_PROVIDER:-deepseek} (no key needed)"
  elif [ -n "${!key_var:-}" ]; then log "LLM: ${LLM_PROVIDER:-deepseek} - $key_var is set"
  else log "LLM: ${LLM_PROVIDER:-deepseek} - $key_var is NOT set in .env (needed only for evaluate)"; fi
  [ "$ok" = 1 ] && log "check: OK" || die "check: prerequisites are missing"
}

# ------------------------------------------------------------------------------ status
cmd_status() {
  "$PY" - <<'EOF'
import glob, json, os, collections
D = "dataset"
def jl(p, d=None):
    return json.load(open(p)) if os.path.exists(p) else d
names = lambda d: {f[:-5] for f in os.listdir(d) if f.endswith(".json") and not f.startswith("_")} if os.path.isdir(d) else set()
matched = {i["package_name"] for i in jl(f"{D}/malware_dataset_matched.json", []) if i.get("package_name")}
done = names(f"{D}/analyzed_chains")
fp = jl(f"{D}/excluded_malwarebench_false_positive.json", {})
fp = set(fp.get("false_positive", [])) | set(fp.get("mixed_versions", []))
failed = collections.Counter()
failed_pkgs = set()
for f in glob.glob(f"{D}/analyzed_chains/_rerun_failures*.json"):
    for reason, ps in json.load(open(f)).items():
        for p in ps:
            if p not in done and p not in failed_pkgs:
                failed_pkgs.add(p); failed[reason] += 1
todo = matched - done - fp - failed_pkgs
print(f"malware: {len(matched)} in the list | {len(done & matched)} analysed | {len(todo)} to analyse | "
      f"{len(failed_pkgs)} failed {dict(failed)} | {len(fp)} legitimate (MalwareBench false_positive)")
ps = jl(f"{D}/payload_scan.json", {})
print(f"payload scan: {len(ps.get('packages', {}))} scanned, {len(ps.get('no_payload', []))} without malicious code")
print(f"benign: {len(names(f'{D}/benign_test_set'))} analysed")
idx = jl(f"{D}/indexes/rag_index/metadata.json", [])
print(f"RAG: rag_train {len(names(f'{D}/rag_train'))} | rag_test {len(names(f'{D}/rag_test'))} | index {len(idx)} chains")
tests = names(f"{D}/rag_test") | names(f"{D}/benign_test_set")
for d in sorted(glob.glob("results/v*")):
    done_now = {os.path.basename(f)[7:-5] for f in glob.glob(f"{d}/report_*.json")}
    cov = f" - current test sets: {len(done_now & tests)}/{len(tests)}" if os.path.basename(d).startswith("v12") else ""
    print(f"results/{os.path.basename(d)}: {len(done_now)} reports{cov}")
EOF
}

# ------------------------------------------------------------------------------ sources
cmd_sources() {
  [ -n "${THESIS_SOURCES_DIR:-}" ] || die "THESIS_SOURCES_DIR is not set (.env)"
  mkdir -p "$THESIS_SOURCES_DIR"
  local line name url d
  while IFS= read -r line; do
    name="${line%%|*}"; url="${line#*|}"; d="$THESIS_SOURCES_DIR/$name"
    if [ -d "$d/.git" ]; then
      log "git pull: $name"
      git -C "$d" pull --ff-only || log "  [!] pull failed in $name - continuing"
    else
      log "git clone: $name ($url)"
      git clone "$url" "$d" || { log "  [!] clone of $name failed (private repository? see PIPELINE.md) - continuing"; continue; }
    fi
    if grep -qs "filter=lfs" "$d/.gitattributes"; then
      git lfs version >/dev/null 2>&1 && { git -C "$d" lfs pull || log "  [!] git lfs pull failed in $name"; } \
        || log "  [!] $name needs git-lfs (brew install git-lfs && git lfs install)"
    fi
  done <<< "$SOURCE_REPOS"
}

# ------------------------------------------------------------------------------ collect
cmd_collect() {
  need_sources
  local bk="$WORK/backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$bk"
  cp dataset/malware_dataset*.json dataset/excluded_malwarebench_false_positive.json "$bk/" 2>/dev/null
  log "backup of the lists -> $bk"
  run "$PY" "$PREP/prepare_dataset_diverse.py"
  run "$PY" "$PREP/collect_all_samples.py"
  run "$PY" "$PREP/extract_samples.py"
  run "$PY" "$PREP/malwarebench_false_positives.py"
}

# ------------------------------------------------------------------------------ analyze
cmd_analyze() {
  need_sources
  keep_awake
  mkdir -p "$WORK"
  local targets="$WORK/analyze_targets.json"
  RETRY_FAILED="${RETRY_FAILED:-0}" "$PY" - "$targets" <<'EOF' || die "the target list was not created"
import glob, json, os, sys
D = "dataset"
matched = [i["package_name"] for i in json.load(open(f"{D}/malware_dataset_matched.json")) if i.get("package_name")]
done = {f[:-5] for f in os.listdir(f"{D}/analyzed_chains") if f.endswith(".json")} if os.path.isdir(f"{D}/analyzed_chains") else set()
skip = set()
fpf = f"{D}/excluded_malwarebench_false_positive.json"
if os.path.exists(fpf):                    # legitimate packages: no analysis needed
    d = json.load(open(fpf)); skip |= set(d.get("false_positive", [])) | set(d.get("mixed_versions", []))
if os.environ.get("RETRY_FAILED") != "1":  # packages that already failed (oversized, timeout ...)
    for f in glob.glob(f"{D}/analyzed_chains/_rerun_failures*.json"):
        for ps in json.load(open(f)).values():
            skip |= set(ps)
todo = sorted(set(matched) - done - skip)
json.dump({"targets": todo}, open(sys.argv[1], "w"), indent=1)
print(f"to analyse: {len(todo)} (already analysed {len(done)}, skipped {len(skip & (set(matched) - done))})")
EOF
  local n
  n=$("$PY" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['targets']))" "$targets")
  if [ "$n" -gt 0 ]; then
    log "CodeQL for $n malware with $WORKERS workers (logs: $LOGS/analyze_w*.log)"
    local pids=() i w
    for ((i = 0; i < WORKERS; i++)); do
      w="$WORK/analyze/w$i"; setup_worker "$w"
      BATCH_STAGING_DIR="$w/temp_malware_analysis" "$PY" "$PREP/rerun_chains.py" --packages-file "$targets" --key targets \
        --out-dir "$ROOT/dataset/analyzed_chains" --pipeline-dir "$w/pipeline" --shard "$i/$WORKERS" \
        --log "$LOGS/analyze_w$i.log" > "$LOGS/analyze_w$i.out" 2>&1 &
      pids+=($!)
    done
    wait "${pids[@]}"
    rm -rf "$WORK/analyze"
    log "CodeQL finished: $(grep -h '=== DONE' "$LOGS"/analyze_w*.log | tail -n "$WORKERS" | tr '\n' ' ')"
  else
    log "no malware to analyse"
  fi
  run "$PY" "$PREP/payload_scan.py"     # resumable: scans only the new samples
}

# ------------------------------------------------------------------------------ benign
cmd_benign() {
  keep_awake
  local pids=() i w
  for ((i = 0; i < BENIGN_WORKERS; i++)); do
    w="$WORK/benign/b$i"; setup_worker "$w"
    "$PY" -u "$PREP/fetch_benign_test_set.py" --shard "$i/$BENIGN_WORKERS" --pipeline-dir "$w/pipeline" \
      > "$LOGS/benign_b$i.log" 2>&1 &
    pids+=($!)
  done
  wait "${pids[@]}"
  # final pass without --shard: retries whatever failed and updates expected_labels.json
  setup_worker "$WORK/benign/final"
  run "$PY" -u "$PREP/fetch_benign_test_set.py" --pipeline-dir "$WORK/benign/final/pipeline"
  rm -rf "$WORK/benign"
}

# ------------------------------------------------------------------------------ policy
cmd_policy() {
  log "NOTE: new snapshot of the knowledge base (current versions of MITRE/CWE/CAPEC and of the rules)."
  # GuardDog, Bandit, Semgrep rules + registry policies -> policy_sources/*.json (clones the repos if missing)
  run "$PY" "$PREP/harvest_policy_sources.py" "$WORK/policy_repos"
  run "$PY" "$PREP/build_policy_dataset.py"
  run "$PY" "$PREP/build_policy_index.py"
}

# ------------------------------------------------------------------------------ rag
cmd_rag() {
  run "$PY" "$PREP/rebuild_rag.py" "$@"
  run "$PY" "$PREP/audit_leakage.py" --out "$ROOT/dataset/audit_leakage.json"
}

# ------------------------------------------------------------------------------ evaluate
cmd_evaluate() {
  local key_var; key_var="$(llm_key_var)"
  [ -z "$key_var" ] || [ -n "${!key_var:-}" ] || die "$key_var is missing for LLM_PROVIDER=${LLM_PROVIDER:-deepseek}: write it in .env"
  keep_awake
  local mode
  for mode in $MODES; do
    log "evaluate: RAG_MODE=$mode${RESULTS_SUFFIX:+ (RESULTS_SUFFIX=$RESULTS_SUFFIX)}"
    if [ "${PARALLEL_SETS:-0}" = 1 ]; then
      RAG_MODE=$mode "$PY" results/check_test_set.py dataset/rag_test > "$LOGS/eval_${mode}_malware.log" 2>&1 & local p1=$!
      RAG_MODE=$mode "$PY" results/check_test_set.py dataset/benign_test_set > "$LOGS/eval_${mode}_benign.log" 2>&1 & local p2=$!
      wait "$p1" "$p2"
    else
      RAG_MODE=$mode "$PY" results/check_test_set.py dataset/rag_test 2>&1 | tee "$LOGS/eval_${mode}_malware.log"
      RAG_MODE=$mode "$PY" results/check_test_set.py dataset/benign_test_set 2>&1 | tee "$LOGS/eval_${mode}_benign.log"
    fi
    RAG_MODE=$mode run "$PY" results/evaluation_summary.py
  done
  run "$PY" results/results_analysis.py     # confusion matrix, CI, similarity strata, FP/FN -> results/analysis/
}

# ------------------------------------------------------------------------------ pack / unpack
# Everything needed to re-run rag/evaluate on another machine WITHOUT the malware sources:
# Behavior Chains (malware + benign), final train/test, indexes and the dataset JSON files.
# (final_diverse_subset/ is a copy of rag_train + rag_test and is recreated by rag.)
PACK_ITEMS="analyzed_chains benign_test_set rag_train rag_test indexes obfuscated"

cmd_pack() {
  mkdir -p dist
  local gz="gzip"; command -v pigz >/dev/null 2>&1 && gz="pigz"
  log "packing dataset/{$PACK_ITEMS}, dataset/*.json, results/v12*, v13* and v14*, expected_labels.json -> dist/ (with $gz)"
  rm -f dist/behavior_chains.tar.gz.part-*
  local items="" i j
  for i in $PACK_ITEMS; do [ -e "dataset/$i" ] && items="$items dataset/$i"; done
  for j in dataset/*.json; do [ -f "$j" ] && items="$items $j"; done
  # LLM reports of the final runs (not of the *_smoke test runs) - they are not in git
  for j in results/v12* results/v13* results/v14* results/v15*; do case "$j" in *smoke*) ;; *) [ -d "$j" ] && items="$items $j" ;; esac; done
  # shellcheck disable=SC2086
  tar -C "$ROOT" -cf - $items expected_labels.json | $gz -c | split -b 1900m - dist/behavior_chains.tar.gz.part-
  (cd dist && shasum -a 256 behavior_chains.tar.gz.part-* > SHA256SUMS)
  ls -lh dist/ | tee -a "$LOGS/pipeline.log"
}

cmd_unpack() {
  local src="${1:-dist}"
  (cd "$src" && shasum -a 256 -c SHA256SUMS) || die "checksum mismatch in the files of $src"
  [ -d dataset/analyzed_chains ] && [ -n "$(ls -A dataset/analyzed_chains 2>/dev/null)" ] \
    && die "dataset/analyzed_chains already exists - move it away first"
  cat "$src"/behavior_chains.tar.gz.part-* | tar -xzf - -C "$ROOT"
  log "restored: $(ls dataset/analyzed_chains | wc -l | tr -d ' ') malware, $(ls dataset/benign_test_set | wc -l | tr -d ' ') benign"
}

# ------------------------------------------------------------------------------ v14 additions
cmd_addtest() { need_sources; run "$PY" "$PREP/add_test_samples.py"; }
cmd_obfuscate() {
  need_sources; keep_awake
  setup_worker "$WORK/obfuscation"
  run "$PY" -u "$PREP/build_obfuscated_set.py" --pipeline-dir "$WORK/obfuscation/pipeline"
}
cmd_deps() {
  need_sources
  local sets="" s
  for s in dataset/rag_test dataset/benign_test_set dataset/obfuscated/*_malware dataset/obfuscated/*_benign; do
    [ -d "$s" ] && sets="$sets $s"
  done
  # shellcheck disable=SC2086
  run "$PY" "$PREP/dependency_findings.py" $sets
}

# ------------------------------------------------------------------------------ main
stage="${1:-}"; shift || true
case "$stage" in
  setup)    cmd_setup ;;
  check)    cmd_check ;;
  status)   cmd_status ;;
  sources)  cmd_sources ;;
  collect)  cmd_collect ;;
  analyze)  cmd_analyze ;;
  benign)   cmd_benign ;;
  policy)   cmd_policy ;;
  rag)      cmd_rag "$@" ;;
  addtest)  cmd_addtest ;;
  obfuscate) cmd_obfuscate ;;
  deps)     cmd_deps ;;
  evaluate) cmd_evaluate ;;
  update)   cmd_sources; cmd_collect; cmd_analyze; cmd_rag ;;
  all)      cmd_collect; cmd_analyze; cmd_benign; cmd_rag; cmd_evaluate ;;
  pack)     cmd_pack ;;
  unpack)   cmd_unpack "$@" ;;
  *)        sed -n '2,32p' "$0"; exit 1 ;;
esac

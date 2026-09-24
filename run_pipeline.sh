#!/usr/bin/env bash
# =====================================================================================
# run_pipeline.sh - αυτοματοποιημένη, επαναλήψιμη εκτέλεση του pipeline.
# Κάθε στάδιο συνεχίζει από εκεί που σταμάτησε (ό,τι έχει ήδη αποτέλεσμα παραλείπεται).
# Οδηγίες: PIPELINE.md
#
#   ./run_pipeline.sh setup        πρώτη εγκατάσταση: pipeline.env, venv + requirements, πακέτα CodeQL
#   ./run_pipeline.sh check        έλεγχος προαπαιτούμενων (venv, CodeQL, πηγές, κλειδί LLM)
#   ./run_pipeline.sh status       πού βρίσκεται το pipeline (αναλυμένα, αποτυχίες, RAG, αποτελέσματα)
#   ./run_pipeline.sh sources      clone των πηγών που λείπουν + git pull στις υπάρχουσες (νέα πακέτα)
#   ./run_pipeline.sh collect      λίστα δειγμάτων malware (malware_dataset*.json) + false positives MalwareBench
#   ./run_pipeline.sh analyze      CodeQL ΜΟΝΟ για τα malware χωρίς αποτέλεσμα (WORKERS παράλληλα) + payload scan
#   ./run_pipeline.sh benign       CodeQL για τα νόμιμα πακέτα που λείπουν (sdists από το PyPI)
#   ./run_pipeline.sh policy       ξαναχτίζει τη βάση γνώσης ασφάλειας (ΝΕΟ snapshot των πηγών)
#   ./run_pipeline.sh rag          επιλογή, διαχωρισμός ανά οικογένεια, ευρετήριο + audit
#   ./run_pipeline.sh evaluate     αξιολόγηση με LLM για κάθε RAG_MODE του MODES
#   ./run_pipeline.sh update       sources -> collect -> analyze -> rag  (ενημέρωση με νέα πακέτα)
#   ./run_pipeline.sh all          collect -> analyze -> benign -> rag -> evaluate
#   ./run_pipeline.sh pack         Behavior Chains, train/test, ευρετήρια, JSON του dataset σε αρχεία <=1.9GB
#   ./run_pipeline.sh unpack [DIR] επαναφορά τους από τα αρχεία του pack (προεπιλογή dist/)
#
# Ρυθμίσεις: στο pipeline.env (βλ. pipeline.env.example) ή ως μεταβλητές περιβάλλοντος:
#   THESIS_SOURCES_DIR   φάκελος με τους κλώνους των πηγών (ΥΠΟΧΡΕΩΤΙΚΟ για sources/collect/analyze)
#   WORKERS=4            παράλληλες αναλύσεις CodeQL για malware (BENIGN_WORKERS=2 για benign)
#   RETRY_FAILED=1       ξαναδοκιμάζει και όσα malware έχουν ήδη αποτύχει (προεπιλογή: όχι)
#   MODES="sum samples policy llm"   ablations για το evaluate (RESULTS_SUFFIX για άλλο φάκελο)
#   PARALLEL_SETS=1      στο evaluate: malware και benign test ταυτόχρονα
#   CODEQL_QUERY_TIMEOUT / CODEQL_DB_TIMEOUT / BATCH_ANALYSIS_TIMEOUT (δευτερόλεπτα)
# =====================================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PREP="$ROOT/dataset/preparation"
PIPE="$ROOT/inference/codeql_pipeline"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="python3"
LOGS="$ROOT/logs"
WORK="$ROOT/work"
# Τοπικές ρυθμίσεις του μηχανήματος (διαδρομές, κλειδιά) - βλ. pipeline.env.example
if [ -f "$ROOT/pipeline.env" ]; then set -a; . "$ROOT/pipeline.env"; set +a; fi
WORKERS="${WORKERS:-4}"
BENIGN_WORKERS="${BENIGN_WORKERS:-2}"
MODES="${MODES:-sum samples policy llm}"
[ -n "${THESIS_SOURCES_DIR:-}" ] && export THESIS_SOURCES_DIR
export CODEQL_NO_VENDOR=1
export CODEQL_QUERY_TIMEOUT="${CODEQL_QUERY_TIMEOUT:-600}"
export CODEQL_DB_TIMEOUT="${CODEQL_DB_TIMEOUT:-900}"
export BATCH_ANALYSIS_TIMEOUT="${BATCH_ANALYSIS_TIMEOUT:-1200}"
export BENIGN_ANALYSIS_TIMEOUT="${BENIGN_ANALYSIS_TIMEOUT:-2400}"

mkdir -p "$LOGS" "$WORK"
cd "$ROOT" || exit 1

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGS/pipeline.log"; }
die() { log "ΣΦΑΛΜΑ: $*"; exit 1; }
run() { log "\$ $*"; "$@" || die "απέτυχε: $*"; }

# Ο υπολογιστής να μην κοιμηθεί όσο τρέχει το script (macOS). ΜΗΝ χρησιμοποιείς σκέτο `wait`:
# θα περίμενε και το caffeinate -> αδιέξοδο. Πάντα `wait "${pids[@]}"`.
keep_awake() { if command -v caffeinate >/dev/null 2>&1; then caffeinate -ims -w $$ & fi; }

# Τα στάδια που διαβάζουν τον ακατέργαστο κώδικα χρειάζονται τη θέση των πηγών.
need_sources() {
  [ -n "${THESIS_SOURCES_DIR:-}" ] || die "δεν έχει οριστεί THESIS_SOURCES_DIR (γράψ' το στο pipeline.env ή τρέξε ./run_pipeline.sh setup)"
  [ -d "$THESIS_SOURCES_DIR" ] || die "δεν βρέθηκε ο φάκελος πηγών $THESIS_SOURCES_DIR (συνδεδεμένος ο δίσκος;)"
}

# Κλώνοι των πηγών μέσα στο THESIS_SOURCES_DIR (φάκελος|αποθετήριο)
SOURCE_REPOS="malicious-packages|https://github.com/ossf/malicious-packages.git
pypi_malregistry|https://github.com/lxyeternal/pypi_malregistry.git
pypi|https://github.com/MalwareBench/pypi.git
malicious-software-packages-dataset|https://github.com/DataDog/malicious-software-packages-dataset.git
maloss-samples|https://github.com/osssanitizer/maloss-samples.git"

# Ιδιωτικό αντίγραφο του CodeQL pipeline ανά worker: παράλληλες αναλύσεις δεν μοιράζονται
# ποτέ ενδιάμεσα αρχεία (results/, staging).
setup_worker() {
  rm -rf "$1"; mkdir -p "$1/pipeline"
  rsync -a --exclude results --exclude __pycache__ --exclude .DS_Store "$PIPE/" "$1/pipeline/"
  mkdir -p "$1/pipeline/results"
}

# ------------------------------------------------------------------------------ setup
cmd_setup() {
  if [ ! -f "$ROOT/pipeline.env" ]; then
    cp "$ROOT/pipeline.env.example" "$ROOT/pipeline.env"
    local src=""
    read -r -p "Φάκελος με τις πηγές malware (δίσκος USB ή φάκελος όπου θα γίνει clone): " src
    [ -n "$src" ] && sed -i.bak "s|^THESIS_SOURCES_DIR=.*|THESIS_SOURCES_DIR=$src|" "$ROOT/pipeline.env" && rm -f "$ROOT/pipeline.env.bak"
    log "γράφτηκε pipeline.env (THESIS_SOURCES_DIR=${src:-<κενό>})"
  fi
  if [ ! -x "$ROOT/venv/bin/python" ]; then
    run python3 -m venv "$ROOT/venv"
  fi
  run "$ROOT/venv/bin/pip" install -q -r "$ROOT/requirements.txt"
  PY="$ROOT/venv/bin/python"
  command -v codeql >/dev/null 2>&1 || die "εγκατάστησε το CodeQL CLI 2.27.0 (π.χ. brew install codeql ή https://github.com/github/codeql-action/releases) και ξανατρέξε"
  run codeql pack install "$PIPE/python_queries"
  run codeql pack install "$PIPE/js_queries"
  log "setup: OK - επόμενα βήματα: ./run_pipeline.sh check και (αν λείπουν πηγές) ./run_pipeline.sh sources"
}

# ------------------------------------------------------------------------------ check
cmd_check() {
  local ok=1
  "$PY" -c "import numpy, sklearn, sentence_transformers, openai" 2>/dev/null \
    && log "venv: OK ($("$PY" --version 2>&1))" || { log "venv: λείπουν πακέτα (numpy/sklearn/sentence-transformers/openai)"; ok=0; }
  command -v codeql >/dev/null 2>&1 && log "CodeQL: $(codeql version --format=terse 2>/dev/null)" \
    || { log "CodeQL: δεν βρέθηκε στο PATH"; ok=0; }
  if [ -n "${THESIS_SOURCES_DIR:-}" ] && [ -d "$THESIS_SOURCES_DIR" ]; then
    local line d
    while IFS= read -r line; do
      d="${line%%|*}"
      [ -d "$THESIS_SOURCES_DIR/$d" ] && log "πηγή: $d OK" || log "πηγή: $d ΛΕΙΠΕΙ (./run_pipeline.sh sources)"
    done <<< "$SOURCE_REPOS"
    [ -d "$THESIS_SOURCES_DIR/malware_samples" ] && log "πηγή: malware_samples OK (δείγματα Datadog, από το collect)" \
      || log "πηγή: malware_samples λείπει (το φτιάχνει το ./run_pipeline.sh collect)"
  else
    log "πηγές: δεν έχει οριστεί/βρεθεί THESIS_SOURCES_DIR (χρειάζεται μόνο για sources/collect/analyze)"
  fi
  [ -n "${DEEPSEEK_API_KEY:-}" ] && log "DEEPSEEK_API_KEY: ορισμένο" || log "DEEPSEEK_API_KEY: ΔΕΝ είναι ορισμένο (χρειάζεται μόνο για evaluate)"
  [ "$ok" = 1 ] && log "check: OK" || die "check: λείπουν προαπαιτούμενα"
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
print(f"malware: {len(matched)} στη λίστα | {len(done & matched)} αναλυμένα | {len(todo)} προς ανάλυση | "
      f"{len(failed_pkgs)} αποτυχημένα {dict(failed)} | {len(fp)} νόμιμα (MalwareBench false_positive)")
ps = jl(f"{D}/payload_scan.json", {})
print(f"payload scan: {len(ps.get('packages', {}))} σαρωμένα, {len(ps.get('no_payload', []))} χωρίς κακόβουλο κώδικα")
print(f"benign: {len(names(f'{D}/benign_test_set'))} αναλυμένα")
idx = jl(f"{D}/indexes/rag_index/metadata.json", [])
print(f"RAG: rag_train {len(names(f'{D}/rag_train'))} | rag_test {len(names(f'{D}/rag_test'))} | ευρετήριο {len(idx)} chains")
tests = names(f"{D}/rag_test") | names(f"{D}/benign_test_set")
for d in sorted(glob.glob("results/v*")):
    done_now = {os.path.basename(f)[7:-5] for f in glob.glob(f"{d}/report_*.json")}
    cov = f" - τωρινό test: {len(done_now & tests)}/{len(tests)}" if os.path.basename(d).startswith("v12") else ""
    print(f"results/{os.path.basename(d)}: {len(done_now)} αναφορές{cov}")
EOF
}

# ------------------------------------------------------------------------------ sources
cmd_sources() {
  [ -n "${THESIS_SOURCES_DIR:-}" ] || die "δεν έχει οριστεί THESIS_SOURCES_DIR (pipeline.env)"
  mkdir -p "$THESIS_SOURCES_DIR"
  local line name url d
  while IFS= read -r line; do
    name="${line%%|*}"; url="${line#*|}"; d="$THESIS_SOURCES_DIR/$name"
    if [ -d "$d/.git" ]; then
      log "git pull: $name"
      git -C "$d" pull --ff-only || log "  [!] αποτυχία pull στο $name - συνεχίζω"
    else
      log "git clone: $name ($url)"
      git clone "$url" "$d" || { log "  [!] αποτυχία clone του $name (ιδιωτικό αποθετήριο; βλ. PIPELINE.md) - συνεχίζω"; continue; }
    fi
    if grep -qs "filter=lfs" "$d/.gitattributes"; then
      git lfs version >/dev/null 2>&1 && { git -C "$d" lfs pull || log "  [!] αποτυχία git lfs pull στο $name"; } \
        || log "  [!] το $name χρειάζεται git-lfs (brew install git-lfs && git lfs install)"
    fi
  done <<< "$SOURCE_REPOS"
}

# ------------------------------------------------------------------------------ collect
cmd_collect() {
  need_sources
  local bk="$WORK/backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$bk"
  cp dataset/malware_dataset*.json dataset/excluded_malwarebench_false_positive.json "$bk/" 2>/dev/null
  log "backup των λιστών -> $bk"
  run "$PY" "$PREP/prepare_dataset_diverse.py"
  run "$PY" "$PREP/collect_all_samples.py"
  run "$PY" "$PREP/extract_samples.py"
  run "$PY" "$PREP/malwarebench_false_positives.py"
}

# ------------------------------------------------------------------------------ analyze
cmd_analyze() {
  need_sources
  keep_awake
  local targets="$WORK/analyze_targets.json"
  RETRY_FAILED="${RETRY_FAILED:-0}" "$PY" - "$targets" <<'EOF' || die "δεν φτιάχτηκε η λίστα"
import glob, json, os, sys
D = "dataset"
matched = [i["package_name"] for i in json.load(open(f"{D}/malware_dataset_matched.json")) if i.get("package_name")]
done = {f[:-5] for f in os.listdir(f"{D}/analyzed_chains") if f.endswith(".json")} if os.path.isdir(f"{D}/analyzed_chains") else set()
skip = set()
fpf = f"{D}/excluded_malwarebench_false_positive.json"
if os.path.exists(fpf):                    # νόμιμα πακέτα: δεν χρειάζονται ανάλυση
    d = json.load(open(fpf)); skip |= set(d.get("false_positive", [])) | set(d.get("mixed_versions", []))
if os.environ.get("RETRY_FAILED") != "1":  # όσα έχουν ήδη αποτύχει (oversized, timeout ...)
    for f in glob.glob(f"{D}/analyzed_chains/_rerun_failures*.json"):
        for ps in json.load(open(f)).values():
            skip |= set(ps)
todo = sorted(set(matched) - done - skip)
json.dump({"targets": todo}, open(sys.argv[1], "w"), indent=1)
print(f"προς ανάλυση: {len(todo)} (ήδη αναλυμένα {len(done)}, παραλείπονται {len(skip & (set(matched) - done))})")
EOF
  local n
  n=$("$PY" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['targets']))" "$targets")
  if [ "$n" -gt 0 ]; then
    log "CodeQL για $n malware με $WORKERS workers (logs: $LOGS/analyze_w*.log)"
    local pids=() i w
    for ((i = 0; i < WORKERS; i++)); do
      w="$WORK/analyze/w$i"; setup_worker "$w"
      BATCH_STAGING_DIR="$w/staging" "$PY" "$PREP/rerun_chains.py" --packages-file "$targets" --key targets \
        --out-dir "$ROOT/dataset/analyzed_chains" --pipeline-dir "$w/pipeline" --shard "$i/$WORKERS" \
        --log "$LOGS/analyze_w$i.log" > "$LOGS/analyze_w$i.out" 2>&1 &
      pids+=($!)
    done
    wait "${pids[@]}"
    rm -rf "$WORK/analyze"
    log "τέλος CodeQL: $(grep -h '=== DONE' "$LOGS"/analyze_w*.log | tail -n "$WORKERS" | tr '\n' ' ')"
  else
    log "κανένα malware προς ανάλυση"
  fi
  run "$PY" "$PREP/payload_scan.py"     # συνεχίζει: σαρώνει μόνο τα νέα
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
  # τελικό πέρασμα χωρίς --shard: ξαναδοκιμάζει ό,τι απέτυχε και ενημερώνει το expected_labels.json
  setup_worker "$WORK/benign/final"
  run "$PY" -u "$PREP/fetch_benign_test_set.py" --pipeline-dir "$WORK/benign/final/pipeline"
  rm -rf "$WORK/benign"
}

# ------------------------------------------------------------------------------ policy
cmd_policy() {
  log "ΠΡΟΣΟΧΗ: νέο snapshot της βάσης γνώσης (τρέχουσες εκδόσεις MITRE/CWE/CAPEC και κανόνων)."
  local r="$WORK/policy_repos"; mkdir -p "$r"
  local repo
  for repo in DataDog/guarddog PyCQA/bandit semgrep/semgrep-rules; do
    [ -d "$r/$(basename "$repo")" ] || run git clone --depth=1 "https://github.com/$repo.git" "$r/$(basename "$repo")"
  done
  run "$PY" "$PREP/harvest_guarddog_rules.py" "$r/guarddog"
  run "$PY" "$PREP/harvest_extra_policy_sources.py" "$r/guarddog" "$r/bandit"
  run "$PY" "$PREP/harvest_semgrep_python_rules.py" "$r/semgrep-rules"
  run "$PY" "$PREP/harvest_registry_policies.py"
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
  [ -n "${DEEPSEEK_API_KEY:-}" ] || die "όρισε πρώτα: export DEEPSEEK_API_KEY=..."
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
  run "$PY" results/confusion_matrix_by_category.py
}

# ------------------------------------------------------------------------------ pack / unpack
# Ό,τι χρειάζεται για να ξανατρέξει το rag/evaluate σε άλλο μηχάνημα ΧΩΡΙΣ τις πηγές malware:
# Behavior Chains (malware + benign), τελικό train/test, ευρετήρια και τα JSON του dataset.
# (Το final_diverse_subset/ είναι αντίγραφο των rag_train+rag_test και ξαναφτιάχνεται από το rag.)
PACK_ITEMS="analyzed_chains benign_test_set rag_train rag_test indexes"

cmd_pack() {
  mkdir -p dist
  local gz="gzip"; command -v pigz >/dev/null 2>&1 && gz="pigz"
  log "συσκευασία dataset/{$PACK_ITEMS}, dataset/*.json, expected_labels.json -> dist/ (με $gz)"
  rm -f dist/behavior_chains.tar.gz.part-*
  local items="" i j
  for i in $PACK_ITEMS; do [ -e "dataset/$i" ] && items="$items dataset/$i"; done
  for j in dataset/*.json; do [ -f "$j" ] && items="$items $j"; done
  # shellcheck disable=SC2086
  tar -C "$ROOT" -cf - $items expected_labels.json | $gz -c | split -b 1900m - dist/behavior_chains.tar.gz.part-
  (cd dist && shasum -a 256 behavior_chains.tar.gz.part-* > SHA256SUMS)
  ls -lh dist/ | tee -a "$LOGS/pipeline.log"
}

cmd_unpack() {
  local src="${1:-dist}"
  (cd "$src" && shasum -a 256 -c SHA256SUMS) || die "λάθος checksum στα αρχεία του $src"
  [ -d dataset/analyzed_chains ] && [ -n "$(ls -A dataset/analyzed_chains 2>/dev/null)" ] \
    && die "υπάρχει ήδη dataset/analyzed_chains - μετακίνησέ το πρώτα"
  cat "$src"/behavior_chains.tar.gz.part-* | tar -xzf - -C "$ROOT"
  log "επαναφέρθηκαν: $(ls dataset/analyzed_chains | wc -l | tr -d ' ') malware, $(ls dataset/benign_test_set | wc -l | tr -d ' ') benign"
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
  evaluate) cmd_evaluate ;;
  update)   cmd_sources; cmd_collect; cmd_analyze; cmd_rag ;;
  all)      cmd_collect; cmd_analyze; cmd_benign; cmd_rag; cmd_evaluate ;;
  pack)     cmd_pack ;;
  unpack)   cmd_unpack "$@" ;;
  *)        sed -n '2,34p' "$0"; exit 1 ;;
esac

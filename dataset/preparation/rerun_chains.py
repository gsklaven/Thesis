"""
rerun_chains.py

Re-runs the REAL CodeQL pipeline (analysis.py + build_behavior_chain.py, fixed
queries, no heuristic fallback) for a given list of packages and writes the
results to dataset/analyzed_chains/ (default; --out-dir for another folder). Packages that
already have a result there are skipped.

Resumable: a package whose result already exists in the output dir is skipped.

Safety check: if the package contains .py files but analysis.py had to skip the
Python pass (query timeout, compile error, DB creation failure, ...), the result
is NOT saved - such output is silently partial (e.g. no data-flow slice) - and
the package is logged as FAILED so it can be retried with larger timeouts.

Usage:
    python3 dataset/preparation/rerun_chains.py --packages-file LIST.json [--key KEY]
        [--out-dir DIR] [--limit N]
Recommended env for big runs:
    CODEQL_QUERY_TIMEOUT=1200 BATCH_ANALYSIS_TIMEOUT=3600 BATCH_BUILD_TIMEOUT=300
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

_ROOT = os.environ.get("THESIS_BASE_DIR",
                       os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import batch_analyzer as ba  # noqa: E402
from utils import resolve_source_path  # noqa: E402

DATASET_JSON = os.path.join(_ROOT, "dataset", "malware_dataset_matched.json")
LOG_PATH = os.path.join(_ROOT, "dataset", "preparation", "rerun_chains.log")
DEFER_FILE = os.path.join(_ROOT, "dataset", "preparation", "deferred_packages.json")
SKIP_MARK = "Παράλειψη γλώσσας 'python'"


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


VERSION_DIR_RE = re.compile(r"^\d+(\.\d+)+$")
MULTIVERSION_MIN_DIRS = 3  # πάνω από πόσους αριθμημένους υποφακέλους θεωρούμε "πολλαπλές εκδόσεις"


def pick_analysis_root(src_path):
    """
    Ορισμένα raw samples (κυρίως pypi/packages/ και malware_samples/) δεν είναι
    ένα πακέτο, αλλά ΟΛΟΚΛΗΡΟ το ιστορικό εκδόσεών του, μαζεμένο σε αριθμημένους
    υποφακέλους (π.χ. 1.0/, 1.1/, ..., 5.1/ - βλ. automslc: 41 εκδόσεις,
    ai-labs-snippets-sdk: 12). Αν αναλυθούν όλες μαζί, το CodeQL "βλέπει" έναν
    πολλαπλάσιο, τεχνητά διογκωμένο κώδικα (πολλαπλά σχεδόν-πανομοιότυπα
    αντίγραφα του ίδιου πακέτου), με αποτέλεσμα δεκάδες φορές περισσότερα
    anchors και τεράστια, αργά αρχεία (π.χ. automslc: 8,4GB - 2026-09-23).
    Αναλύουμε μόνο την πιο πρόσφατη έκδοση σε τέτοιες περιπτώσεις.
    """
    try:
        subs = os.listdir(src_path)
    except OSError:
        return src_path
    version_dirs = [s for s in subs if VERSION_DIR_RE.match(s)]
    if len(version_dirs) < MULTIVERSION_MIN_DIRS:
        return src_path
    latest = max(version_dirs, key=lambda v: tuple(int(x) for x in v.split(".")))
    return os.path.join(src_path, latest)


CODE_EXTS = (".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def code_size(path):
    """
    Μέγεθος ΜΟΝΟ των αρχείων κώδικα. Το όριο μεγέθους μετρούσε ΟΛΑ τα bytes, οπότε
    πακέτα με λίγο κώδικα αλλά μεγάλα binaries/δεδομένα (π.χ. driftdb: 416MB στον δίσκο,
    4,6MB κώδικας) αποκλείονταν ως "oversized", ενώ το CodeQL αναλύει μόνο τον κώδικα.
    """
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            if f.lower().endswith(CODE_EXTS):
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    return total


def has_python_files(path):
    for _, _, files in os.walk(path):
        if any(f.endswith(".py") for f in files):
            return True
    return False


def site_packages_root(path):
    """
    Ορισμένα samples είναι Windows bdist (.win-amd64.zip) όπου ΟΛΟΣ ο κώδικας βρίσκεται κάτω από
    "Program Files/Python311/Lib/site-packages/". Ο Python extractor του CodeQL θεωρεί τα
    site-packages κώδικα βιβλιοθήκης και τα παραλείπει -> "no source code seen" (exit 32) και
    python_pass_skipped σε ~5s (pydetectmouse, mousemovement, pyflakesy, pyvmdec - 2026-09-24).
    Αν όλα τα .py είναι μέσα σε ΕΝΑ site-packages, η ανάλυση ξεκινά από εκεί.
    """
    sp_dirs, outside = set(), False
    for root, _, files in os.walk(path):
        if not any(f.endswith(".py") for f in files):
            continue
        parts = os.path.relpath(root, path).split(os.sep)
        if "site-packages" in parts:
            sp_dirs.add(os.path.join(path, *parts[:parts.index("site-packages") + 1]))
        else:
            outside = True
    return sp_dirs.pop() if len(sp_dirs) == 1 and not outside else path


def process_one(src_path, out_path):
    src_path = pick_analysis_root(src_path)
    ba.clean_staging()
    ba.copy_recursive(src_path, ba.STAGING_DIR)
    ba.extract_archives(ba.STAGING_DIR)

    if code_size(ba.STAGING_DIR) > ba.MAX_STAGING_SIZE_BYTES:
        return "oversized", -1

    env = os.environ.copy()
    env["CODEQL_TARGET_DIR"] = site_packages_root(ba.STAGING_DIR)
    try:
        r1 = ba.run_with_hard_timeout(["python3", ba.ANALYSIS_SCRIPT], timeout=ba.ANALYSIS_TIMEOUT,
                                      env=env, cwd=ba.PIPELINE_DIR, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return "timeout_analysis", -1
    if r1.returncode != 0:
        return "codeql_error", -1

    if SKIP_MARK in (r1.stdout or "") and has_python_files(ba.STAGING_DIR):
        return "python_pass_skipped", -1

    try:
        r2 = ba.run_with_hard_timeout(["python3", ba.BUILD_SCRIPT], timeout=ba.BUILD_TIMEOUT,
                                      cwd=ba.PIPELINE_DIR, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return "timeout_build", -1
    if r2.returncode != 0 or not os.path.exists(ba.RESULTS_JSON):
        return "builder_error", -1

    with open(ba.RESULTS_JSON, "r", encoding="utf-8") as f:
        n = json.load(f).get("summary", {}).get("total_behavior_chains", -1)
    shutil.copy2(ba.RESULTS_JSON, out_path)
    return "ok", n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages-file", required=True)
    ap.add_argument("--key", help="key to read if the JSON file is a dict")
    ap.add_argument("--out-dir", default=os.path.join(_ROOT, "dataset", "analyzed_chains"))
    ap.add_argument("--limit", type=int)
    ap.add_argument("--pipeline-dir", help="private copy of inference/codeql_pipeline (own results/), "
                    "used by parallel workers so they never share intermediate files")
    ap.add_argument("--shard", help="I/N: process only every N-th package starting at I (0-based)")
    ap.add_argument("--log", help="log file (default rerun_chains.log)")
    ap.add_argument("--include-deferred", action="store_true",
                    help="μην παραλείπεις όσα είναι στο deferred_packages.json (τελευταία προσπάθεια)")
    args = ap.parse_args()

    global LOG_PATH
    if args.log:
        LOG_PATH = args.log
    if args.pipeline_dir:
        ba.PIPELINE_DIR = args.pipeline_dir
        ba.ANALYSIS_SCRIPT = os.path.join(args.pipeline_dir, "analysis.py")
        ba.BUILD_SCRIPT = os.path.join(args.pipeline_dir, "build_behavior_chain.py")
        ba.PIPELINE_RESULTS_DIR = os.path.join(args.pipeline_dir, "results")
        ba.RESULTS_JSON = os.path.join(ba.PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")
        os.makedirs(ba.PIPELINE_RESULTS_DIR, exist_ok=True)

    pk = json.load(open(args.packages_file, encoding="utf-8"))
    pkgs = pk[args.key] if args.key else pk
    with open(DATASET_JSON, encoding="utf-8") as f:
        pm = {i["package_name"]: i["source_code_path"] for i in json.load(f) if i.get("package_name")}
    os.makedirs(args.out_dir, exist_ok=True)

    deferred = set()
    if os.path.exists(DEFER_FILE) and not args.include_deferred:
        deferred = set(json.load(open(DEFER_FILE, encoding="utf-8")))

    todo, unmappable = [], []
    for p in pkgs:
        if p in deferred:
            continue
        src = pm.get(p)
        src = resolve_source_path(src)   # διαδρομή άλλου μηχανήματος -> THESIS_SOURCES_DIR
        if not src or not os.path.isdir(src):
            unmappable.append(p)
        elif not os.path.exists(os.path.join(args.out_dir, f"{p}.json")):
            todo.append((p, src))
    if args.shard:
        i, n = map(int, args.shard.split("/"))
        todo = todo[i::n]
    if args.limit:
        todo = todo[: args.limit]

    log(f"=== rerun_chains start: {len(todo)} to do ({len(pkgs) - len(todo) - len(unmappable) - len(deferred & set(pkgs))} already done, "
        f"{len(unmappable)} unmappable, {len(deferred & set(pkgs))} deferred) -> {args.out_dir} | query_timeout="
        f"{os.environ.get('CODEQL_QUERY_TIMEOUT', '300')}s analysis_timeout={ba.ANALYSIS_TIMEOUT}s ===")
    ok = zero = 0
    fails = {}
    t0 = time.time()
    for i, (pkg, src) in enumerate(todo, 1):
        t1 = time.time()
        status, n = process_one(src, os.path.join(args.out_dir, f"{pkg}.json"))
        dt = time.time() - t1
        if status == "ok":
            ok += 1
            zero += n == 0
            log(f"[{i}/{len(todo)}] {pkg:40s} OK -> {n} chains ({dt:.0f}s)")
        else:
            fails.setdefault(status, []).append(pkg)
            log(f"[{i}/{len(todo)}] {pkg:40s} FAILED: {status} ({dt:.0f}s)")
        if i % 25 == 0:
            avg = (time.time() - t0) / i
            log(f"  -- {i}/{len(todo)} | ok={ok} (0-chain: {zero}) failed={sum(map(len, fails.values()))} "
                f"| avg {avg:.0f}s/pkg | ETA {avg * (len(todo) - i) / 3600:.1f}h --")
    log(f"=== DONE ok={ok} (0-chain: {zero}) failed={ {k: len(v) for k, v in fails.items()} } ===")
    if fails:
        # Το όνομα της λίστας μπαίνει στο όνομα αρχείου: αλλιώς δύο διαφορετικές λίστες με
        # ίδιο sharding (π.χ. clean2 και heavy_size, και οι δύο --shard i/4) σβήνουν η μία
        # τις αποτυχίες της άλλης.
        tag = os.path.splitext(os.path.basename(args.packages_file))[0]
        fp = os.path.join(args.out_dir, f"_rerun_failures_{tag}.json" if not args.shard else
                          f"_rerun_failures_{tag}_%sof%s.json" % tuple(args.shard.split("/")))
        json.dump(fails, open(fp, "w"), indent=1, ensure_ascii=False)
        log(f"failed packages listed in {fp}")


if __name__ == "__main__":
    main()

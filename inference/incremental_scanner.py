"""
incremental_scanner.py - Continuous malware scanning of a Git repository, commit by commit.

The first scan analyses the whole repository; every later scan re-runs the static analysis (CodeQL on the
whole repository, so cross-file flows are complete) but sends to the LLM ONLY the Behavior Chains whose
fingerprint (chain_fingerprint.py) has not been evaluated before. Chains that are unchanged - including
code that only moved to other lines or was re-formatted - reuse their stored verdict. The repository
verdict is always computed over ALL current chains (stored + new), so a malicious chain introduced in an
earlier commit keeps the repository flagged for as long as it exists.

Pipeline per scan (the same components and settings as the thesis evaluation):
  copy of the repository -> CodeQL (no dependency installation, CODEQL_NO_VENDOR=1) -> Behavior Chains
  -> Hybrid RAG + prompt (query_rag.py) -> LLM (llm_providers.py, LLM_PROVIDER in .env; lmstudio keeps
  everything on the local machine) -> verdict per chain -> repository verdict (llm_evaluator.aggregate_verdicts)

State, kept in <repository>/.malware_scan/ (commit it, or cache it between CI runs):
  baseline.json         fingerprint -> verdict of every evaluated chain, plus the evaluation context
                        (prompt version, RAG mode, LLM, index size). If the context changes, everything
                        is evaluated again.
  last_scan.json        the latest scan report
  scans/<commit>.json   one report per scanned commit

Usage:
  python3 inference/incremental_scanner.py --target /path/to/repo --package NAME            # incremental
  python3 inference/incremental_scanner.py --target /path/to/repo --package NAME --mode full
  options: --commit SHA --prev-commit SHA (reported changed files; if no code file changed, the scan is
           skipped), --state-dir DIR, --fail-on-malicious (exit 2 on MALICIOUS, 3 on an incomplete
           evaluation - for CI), --keep-workdir
The scanned repository is never modified except for its state folder, and its code is never executed.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
_PIPELINE_DIR = os.path.join(_THESIS_ROOT, "inference", "codeql_pipeline")
_INFERENCE_DIR = os.path.join(_THESIS_ROOT, "inference")
sys.path.insert(0, _INFERENCE_DIR)
sys.path.insert(0, os.path.join(_THESIS_ROOT, "dataset", "preparation"))

from chain_fingerprint import chain_fingerprint, chain_touched_files  # noqa: E402
from query_rag import PROMPT_VERSION, RAG_MODE, RAGEngine  # noqa: E402
# The evaluator module selects the LLM provider on import (and checks its key).
import llm_evaluator as ev  # noqa: E402

SCAN_STATE_DIR = ".malware_scan"
BASELINE_FILE = "baseline.json"
LAST_SCAN_FILE = "last_scan.json"
SCANS_DIR = "scans"
BASELINE_FORMAT = 2
# file types whose change can alter a Behavior Chain (code, and install metadata)
CODE_EXTENSIONS = (".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".pth",
                   "setup.cfg", "pyproject.toml", "package.json")
# only these files are copied for the analysis (code and install metadata) - never data, binaries or
# the repository history, so scanning a large repository stays fast
COPY_SUFFIXES = CODE_EXTENSIONS + ("requirements.txt", "setup.py")
# third-party / generated folders that are not part of the repository's own code
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
             ".pytest_cache", ".eggs", "site-packages"}
# printed by analysis.py when the CodeQL pass of a language fails
SKIP_MARK = "Skipping language 'python'"
ANALYSIS_TIMEOUT = int(os.environ.get("SCAN_ANALYSIS_TIMEOUT", "3600"))
BUILD_TIMEOUT = int(os.environ.get("SCAN_BUILD_TIMEOUT", "600"))
EMPTY_SHA = "0" * 40  # GitHub's "before" value for a newly created branch


def now():
    """Current local time, ISO format (seconds)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Git helpers
# ─────────────────────────────────────────────────────────────────────────────

def _git(repo_dir, *args):
    """Output of a git command in repo_dir, or None if it fails (e.g. not a git repository)."""
    res = subprocess.run(["git", *args], cwd=repo_dir, capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else None


def git_changed_files(repo_dir, commit, prev_commit, state_dir_name=SCAN_STATE_DIR):
    """
    Files changed between prev_commit and commit (repository-relative paths, without the scanner's own
    state folder), or None if unknown.
    """
    if not prev_commit or prev_commit == EMPTY_SHA or not commit:
        return None
    out = _git(repo_dir, "diff", "--name-only", prev_commit, commit)
    if out is None:
        print(f"[!] git diff {prev_commit[:8]}..{commit[:8]} failed - changed files unknown")
        return None
    return sorted(line for line in out.splitlines()
                  if line.strip() and not line.startswith(state_dir_name + "/"))


def touches_code(changed_files):
    """True if at least one changed file can alter a Behavior Chain."""
    return any(f.lower().endswith(CODE_EXTENSIONS) for f in changed_files)


# ─────────────────────────────────────────────────────────────────────────────
# Static analysis (CodeQL) on a private copy
# ─────────────────────────────────────────────────────────────────────────────

def copy_code_files(target_dir, dest, state_dir_name):
    """Copy only the code / install-metadata files of the repository into dest; returns how many."""
    n = 0
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d != state_dir_name]  # prune in place
        for f in files:
            src = os.path.join(root, f)
            if f.lower().endswith(COPY_SUFFIXES) and not os.path.islink(src):
                out = os.path.join(dest, os.path.relpath(src, target_dir))
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(src, out)
                n += 1
    return n


def run_static_analysis(target_dir, work_dir, state_dir_name):
    """
    Copy the repository (without .git and the scanner state) and the CodeQL pipeline into work_dir,
    run analysis.py + build_behavior_chain.py there and return the parsed chains file. The CodeQL
    databases are also created inside work_dir, so nothing is written into or next to the repository.
    Dependencies are never installed (CODEQL_NO_VENDOR=1) and the scanned code is never executed.
    """
    import batch_analyzer as ba  # hard timeouts that kill CodeQL's whole process group

    src = os.path.join(work_dir, "src")
    copied = copy_code_files(target_dir, src, state_dir_name)
    print(f"[*] {copied} code files copied for analysis")
    pipeline = os.path.join(work_dir, "pipeline")
    shutil.copytree(_PIPELINE_DIR, pipeline, ignore=shutil.ignore_patterns("results", "__pycache__", ".DS_Store"))
    os.makedirs(os.path.join(pipeline, "results"))

    env = dict(os.environ, CODEQL_TARGET_DIR=src, CODEQL_NO_VENDOR="1", THESIS_BASE_DIR=_THESIS_ROOT)
    print(f"[CodeQL] analysing a copy of {target_dir} ...")
    r1 = ba.run_with_hard_timeout([sys.executable, "analysis.py"], timeout=ANALYSIS_TIMEOUT, env=env,
                                  cwd=pipeline, capture_output=True, text=True)
    if r1.returncode != 0:
        raise RuntimeError(f"analysis.py failed (exit {r1.returncode}): {(r1.stderr or '')[-300:]}")
    # a skipped Python pass on a repository that HAS Python code would be a silently partial result
    if SKIP_MARK in (r1.stdout or "") and any(f.endswith(".py") for _, _, fs in os.walk(src) for f in fs):
        raise RuntimeError("the CodeQL Python pass failed - the result would be incomplete")
    r2 = ba.run_with_hard_timeout([sys.executable, "build_behavior_chain.py"], timeout=BUILD_TIMEOUT, env=env,
                                  cwd=pipeline, capture_output=True, text=True)
    out = os.path.join(pipeline, "results", "sliced_behavior_chain.json")
    if r2.returncode != 0 or not os.path.exists(out):
        raise RuntimeError(f"build_behavior_chain.py failed (exit {r2.returncode})")
    with open(out, encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Baseline (fingerprint -> verdict) and evaluation context
# ─────────────────────────────────────────────────────────────────────────────

def evaluation_context(engine):
    """What a stored verdict depends on besides the chain itself: prompt, RAG mode, LLM and indexes."""
    engine._ensure_init()
    return {"prompt_version": PROMPT_VERSION, "rag_mode": RAG_MODE, "llm_provider": ev.PROVIDER,
            "llm_model": ev.MODEL, "malware_index_vectors": len(engine.malware_meta),
            "policy_index_vectors": len(engine.policy_meta)}


def load_baseline(state_dir):
    """The stored baseline, or an empty one."""
    path = os.path.join(state_dir, BASELINE_FILE)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("format") == BASELINE_FORMAT:
            return data
        print("[*] Baseline of an older format - it is rebuilt.")
    return {"format": BASELINE_FORMAT, "context": None, "fingerprints": {}}


def save_json(path, data):
    """Write data as JSON (creating the parent folder)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def ensure_state_gitignore(state_dir):
    """A .gitignore in the state folder: its JSON files are meant to be committed, temporary files not."""
    path = os.path.join(state_dir, ".gitignore")
    if not os.path.exists(path):
        os.makedirs(state_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Malware scanner state: commit baseline.json, last_scan.json and scans/ to keep it\n"
                    "# between CI runs (or cache the folder instead).\n*.tmp\n")


# ─────────────────────────────────────────────────────────────────────────────
# LLM evaluation of the new chains
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(results, indices):
    """
    Evaluate results[i] for i in indices with the configured LLM, in parallel, with the same retry
    rounds as llm_evaluator.py (chains that return ERROR/PARSE_ERROR are sent again).
    """
    pending = list(indices)
    with ThreadPoolExecutor(max_workers=ev.MAX_WORKERS) as executor:
        for round_no in range(1 + ev.CHAIN_RETRY_ROUNDS):
            if not pending:
                break
            if round_no:
                print(f"[*] Retry round {round_no}/{ev.CHAIN_RETRY_ROUNDS}: {len(pending)} chains failed, again...")
                time.sleep(ev.INITIAL_RETRY_DELAY * 2 ** round_no)
            futures = {executor.submit(ev._evaluate_one, i, results[i]): i for i in pending}
            for future in as_completed(futures):
                i = futures[future]
                try:
                    _, answer = future.result()
                except Exception as exc:  # noqa: BLE001
                    answer = {"verdict": "ERROR", "error": f"Thread exception: {exc}"}
                answer["attempts"] = round_no + 1
                results[i]["llm_evaluation"] = answer
                print(f"  [LLM] {results[i]['location']} ({results[i]['category']}): {answer.get('verdict')}")
            pending = [i for i in pending if results[i]["llm_evaluation"].get("verdict") in ev.FAILED_VERDICTS]


# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────

def scan(args):
    """Run one scan and return its report (also written to the state folder)."""
    target = os.path.abspath(args.target)
    state_dir = os.path.abspath(args.state_dir or os.path.join(target, SCAN_STATE_DIR))
    commit = args.commit or _git(target, "rev-parse", "HEAD") or "unknown"
    baseline = load_baseline(state_dir)
    changed = git_changed_files(target, commit, args.prev_commit, os.path.relpath(state_dir, target))

    report = {"package": args.package, "commit": commit, "prev_commit": args.prev_commit, "mode": args.mode,
              "scanned_at": now(), "changed_files": changed}

    # shortcut: nothing that could change a chain was modified since the previous scan
    last_path = os.path.join(state_dir, LAST_SCAN_FILE)
    if (args.mode == "incremental" and changed is not None and not touches_code(changed)
            and baseline["fingerprints"] and os.path.exists(last_path)):
        with open(last_path, encoding="utf-8") as f:
            last = json.load(f)
        print("[*] No code file changed since the previous scan - its verdict still holds.")
        report.update({"skipped": "no code changes", "repository_verdict": last.get("repository_verdict"),
                       "chains_total": last.get("chains_total"), "chains_evaluated_now": 0,
                       "chains_reused": last.get("chains_total"), "malicious_chains": last.get("malicious_chains", [])})
        return report, state_dir

    work_dir = tempfile.mkdtemp(prefix="malware_scan_")
    try:
        pkg_data = run_static_analysis(target, work_dir, os.path.basename(state_dir))
        chains = pkg_data.get("behavior_chains", [])
        # the file name is the package name shown to the LLM (as in the evaluation)
        chains_path = os.path.join(work_dir, f"{args.package}.json")
        save_json(chains_path, pkg_data)

        engine = RAGEngine()
        context = evaluation_context(engine)
        results = engine.analyze_package(chains_path)   # one prompt per non-vendor chain
    finally:
        if args.keep_workdir:
            print(f"[*] Work folder kept: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)

    reuse = args.mode == "incremental" and baseline.get("context") == context
    if args.mode == "incremental" and baseline["fingerprints"] and not reuse:
        print("[*] The evaluation context changed (prompt / RAG / LLM / index) - every chain is evaluated again.")
    known = baseline["fingerprints"] if reuse else {}

    # split the chains into already-evaluated (stored verdict) and new ones
    new_idx = []
    for i, r in enumerate(results):
        chain = chains[r["chain_index"]]
        r["fingerprint"] = chain_fingerprint(chain)
        r["touched_files"] = sorted(chain_touched_files(chain))
        stored = known.get(r["fingerprint"])
        if stored:
            r["llm_evaluation"] = {**stored["evaluation"], "reused_from_commit": stored.get("commit")}
        else:
            new_idx.append(i)
    print(f"[*] {len(results)} behavior chains: {len(results) - len(new_idx)} already evaluated, "
          f"{len(new_idx)} new -> LLM ({ev.PROVIDER}, {ev.MODEL})")
    evaluate(results, new_idx)

    # store the new verdicts (failed evaluations are not stored, so they are retried next time)
    if not reuse:
        baseline = {"format": BASELINE_FORMAT, "context": context, "fingerprints": {}}
    for i in new_idx:
        e = results[i]["llm_evaluation"]
        if e.get("verdict") in ev.FAILED_VERDICTS:
            continue
        baseline["fingerprints"][results[i]["fingerprint"]] = {
            "evaluation": {k: e.get(k) for k in ("verdict", "confidence", "ssvc_decision", "summary")},
            "category": results[i]["category"], "location": results[i]["location"],
            "sensitive_api": results[i]["sensitive_api"], "commit": commit, "evaluated_at": now()}
    baseline.update({"context": context, "last_commit": commit, "updated_at": now()})
    ensure_state_gitignore(state_dir)
    save_json(os.path.join(state_dir, BASELINE_FILE), baseline)

    verdict = ev.aggregate_verdicts(results) if results else "NO_CHAINS_FOUND"
    flagged = [{"location": r["location"], "category": r["category"], "sensitive_api": r["sensitive_api"],
                "ssvc_decision": r["llm_evaluation"].get("ssvc_decision"),
                "confidence": r["llm_evaluation"].get("confidence"),
                "summary": r["llm_evaluation"].get("summary"),
                "new_in_this_scan": i in new_idx,
                "touches_changed_files": bool(changed and set(r["touched_files"]) & set(changed))}
               for i, r in enumerate(results) if r["llm_evaluation"].get("verdict") in ("MALICIOUS", "SUSPICIOUS")]
    report.update({
        "repository_verdict": verdict, "evaluation_context": context,
        "chains_total": len(results), "chains_evaluated_now": len(new_idx),
        "chains_reused": len(results) - len(new_idx),
        "chains_failed": sum(1 for r in results if r["llm_evaluation"].get("verdict") in ev.FAILED_VERDICTS),
        "vendor_chains_excluded": getattr(engine, "last_vendor_excluded", 0),
        "malicious_chains": flagged,
        "chains": [{"location": r["location"], "category": r["category"], "sensitive_api": r["sensitive_api"],
                    "fingerprint": r["fingerprint"], "verdict": r["llm_evaluation"].get("verdict"),
                    "reused": i not in new_idx} for i, r in enumerate(results)],
    })
    return report, state_dir


def print_summary(report):
    """Human-readable summary of a scan report."""
    print(f"\n{'=' * 70}\nSCAN RESULT - {report['package']} @ {str(report['commit'])[:12]} ({report['mode']})\n{'=' * 70}")
    if report.get("changed_files") is not None:
        cf = report["changed_files"]
        print(f"Changed files: {len(cf)}" + (f" ({', '.join(cf[:5])}{' ...' if len(cf) > 5 else ''})" if cf else ""))
    if report.get("skipped"):
        print(f"Scan skipped: {report['skipped']}")
    print(f"Behavior chains: {report.get('chains_total')} | evaluated now: {report.get('chains_evaluated_now')} "
          f"| reused: {report.get('chains_reused')}")
    print(f"Repository verdict: {report.get('repository_verdict')}")
    for m in report.get("malicious_chains", []):
        tag = "NEW " if m.get("new_in_this_scan") else ""
        print(f"  -> {tag}[{m.get('ssvc_decision')}] {m['location']} | {m['category']} | {m['sensitive_api']}")
        if m.get("summary"):
            print(f"     {str(m['summary'])[:160]}")
    print("=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Parse the arguments, run the scan, write the reports and set the exit code."""
    parser = argparse.ArgumentParser(
        description="Continuous (per-commit) malware scanner for Git repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--target", required=True, help="Path to the repository/directory to scan")
    parser.add_argument("--package", required=True, help="Package name (shown to the LLM, used in the reports)")
    parser.add_argument("--mode", choices=["full", "incremental"], default="incremental",
                        help="'full' re-evaluates every chain; 'incremental' (default) only new fingerprints")
    parser.add_argument("--commit", default=None, help="Current commit SHA (default: HEAD of the target)")
    parser.add_argument("--prev-commit", default=None, dest="prev_commit",
                        help="Previous scanned commit (to report changed files and skip non-code commits)")
    parser.add_argument("--state-dir", default=None, help=f"State folder (default: <target>/{SCAN_STATE_DIR})")
    parser.add_argument("--fail-on-malicious", action="store_true",
                        help="exit code 2 if the repository is MALICIOUS, 3 if the evaluation is incomplete")
    parser.add_argument("--keep-workdir", action="store_true", help="keep the temporary analysis folder")
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"[!] Target directory does not exist: {args.target}")
        sys.exit(1)

    try:
        report, state_dir = scan(args)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"[!] Scan failed: {e}")
        sys.exit(1)

    save_json(os.path.join(state_dir, LAST_SCAN_FILE), report)
    save_json(os.path.join(state_dir, SCANS_DIR, f"{str(report['commit'])[:12]}.json"), report)
    print_summary(report)

    if args.fail_on_malicious:
        if report.get("repository_verdict") in ("MALICIOUS", "SUSPICIOUS"):
            sys.exit(2)
        if report.get("repository_verdict") in ("INCOMPLETE", "EVALUATION_FAILED", "UNKNOWN"):
            sys.exit(3)


if __name__ == "__main__":
    main()

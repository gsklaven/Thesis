"""
incremental_scanner.py — Incremental malware analysis για Git repositories.

ΛΕΙΤΟΥΡΓΙΕΣ:
  full        : Πλήρης ανάλυση όλου του repository (1ο push / baseline).
  incremental : Ανάλυση μόνο των chains που αφορούν changed files σε ένα commit.

FLOW:
  Full:
    CodeQL (full repo) → behavior chains → LLM (ALL chains)
    → .malware_scan/baseline.json (fingerprints)
    → .malware_scan/last_scan.json (full report)

  Incremental:
    git diff → changed files
    CodeQL (full repo, αλλά filter output) → behavior chains
    → φιλτράρισμα: chains που αγγίζουν changed files
    → cross-ref με baseline fingerprints → μόνο νέα chains
    → LLM (NEW chains only)
    → merge με baseline → ενημερωμένο report
    → .malware_scan/incremental/commit_<sha>.json

ΧΡΗΣΗ:
  # Πρώτο push — full scan
  python3 incremental_scanner.py \\
      --target /path/to/repo \\
      --package my-package \\
      --mode full

  # Επόμενο commit
  python3 incremental_scanner.py \\
      --target /path/to/repo \\
      --package my-package \\
      --mode incremental \\
      --commit abc1234 \\
      --prev-commit def5678

  # Αν τρέχει μέσα στο ίδιο repo (για GitHub Actions)
  python3 incremental_scanner.py \\
      --target . \\
      --package my-package \\
      --mode incremental \\
      --commit $GITHUB_SHA \\
      --prev-commit ${{ github.event.before }}
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

# Thesis root — adjustable via env
_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
_PIPELINE_DIR = os.path.join(_THESIS_ROOT, "inference", "codeql_pipeline")
_INFERENCE_DIR = os.path.join(_THESIS_ROOT, "inference")

sys.path.insert(0, _INFERENCE_DIR)
from chain_fingerprint import chain_fingerprint, chain_touched_files, fingerprint_all  # noqa
from query_rag import PROMPT_VERSION  # noqa

# Subdir inside the target repo where we store scan state
SCAN_STATE_DIR = ".malware_scan"
BASELINE_FILE = "baseline.json"
LAST_SCAN_FILE = "last_scan.json"
INCREMENTAL_DIR = "incremental"

# ─────────────────────────────────────────────────────────────────────────────
# CodeQL pipeline helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_codeql_pipeline(target_dir: str) -> str | None:
    """
    Τρέχει analysis.py + build_behavior_chain.py με CODEQL_TARGET_DIR=target_dir.
    Επιστρέφει το path του παραγόμενου sliced_behavior_chain.json, ή None αν απέτυχε.
    """
    env = os.environ.copy()
    env["CODEQL_TARGET_DIR"] = os.path.abspath(target_dir)
    env["THESIS_BASE_DIR"] = _THESIS_ROOT

    results_dir = os.path.join(_PIPELINE_DIR, "results")

    # Καθαρισμός προηγούμενων αποτελεσμάτων (αποφυγή stale-CSV bug)
    for pattern in [
        "final_codeql_results_*.csv",
        "call_graph_*.csv",
        "backward_slice_*.csv",
        "control_deps_*.csv",
    ]:
        import glob
        for f in glob.glob(os.path.join(results_dir, pattern)):
            os.remove(f)

    chain_json = os.path.join(results_dir, "sliced_behavior_chain.json")
    if os.path.exists(chain_json):
        os.remove(chain_json)

    print(f"[CodeQL] Ανάλυση: {target_dir}")
    for script in ["analysis.py", "build_behavior_chain.py"]:
        script_path = os.path.join(_PIPELINE_DIR, script)
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=_PIPELINE_DIR,
            env=env,
        )
        if result.returncode != 0:
            print(f"[!] Αποτυχία: {script} (exit code {result.returncode})")
            return None

    if not os.path.exists(chain_json):
        print("[!] Δεν παράχθηκε sliced_behavior_chain.json")
        return None

    return chain_json


def _load_chains(chain_json_path: str) -> tuple[list, dict]:
    """Φορτώνει chains και επιστρέφει (chains_list, full_pkg_data)."""
    with open(chain_json_path, encoding="utf-8") as f:
        pkg_data = json.load(f)
    return pkg_data.get("behavior_chains", []), pkg_data


# ─────────────────────────────────────────────────────────────────────────────
# Git helpers
# ─────────────────────────────────────────────────────────────────────────────

def _git_changed_files(repo_dir: str, commit: str, prev_commit: str) -> set:
    """
    Επιστρέφει set με τα αρχεία που άλλαξαν μεταξύ prev_commit και commit.
    Paths είναι relative ως προς τη ρίζα του repo.
    """
    result = subprocess.run(
        ["git", "diff", "--name-only", prev_commit, commit],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[!] git diff απέτυχε: {result.stderr.strip()}")
        return set()

    files = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    print(f"[git] Changed files ({len(files)}): {', '.join(sorted(files)[:10])}"
          + (" ..." if len(files) > 10 else ""))
    return files


def _git_current_sha(repo_dir: str) -> str:
    """Επιστρέφει το τρέχον commit SHA (short)."""
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=repo_dir, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# LLM evaluation
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate_chains(chain_json_path: str, evaluator_script: str) -> dict | None:
    """
    Καλεί το llm_evaluator.py για ένα chain JSON (πάροχος LLM από το .env).
    Επιστρέφει το report dict ή None αν απέτυχε.
    """
    result = subprocess.run(
        [sys.executable, evaluator_script, chain_json_path],
        cwd=_INFERENCE_DIR,
    )
    if result.returncode != 0:
        return None

    # Βρες το report που έγραψε ο evaluator
    pkg_name = os.path.basename(chain_json_path).replace(".json", "")
    report_path = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION,
                               f"report_{pkg_name}.json")
    if os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as f:
            return json.load(f)
    return None


def _evaluate_subset(all_chains: list, new_chain_indices: list,
                     pkg_data: dict, package_name: str,
                     evaluator_script: str) -> dict | None:
    """
    Δημιουργεί ένα temporary JSON με ΜΟΝΟ τα new chains και το στέλνει στο LLM.
    Επιστρέφει το report dict για αυτά τα chains.
    """
    import tempfile

    subset_data = dict(pkg_data)
    subset_data["behavior_chains"] = [all_chains[i] for i in new_chain_indices]
    subset_data["_incremental_note"] = (
        f"Partial analysis: {len(new_chain_indices)} new/changed chains "
        f"out of {len(all_chains)} total"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix=f"{package_name}_incremental_",
        delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(subset_data, tmp, ensure_ascii=False, indent=2)
        tmp_path = tmp.name

    try:
        report = _evaluate_chains(tmp_path, evaluator_script)
    finally:
        os.unlink(tmp_path)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Baseline helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scan_state_dir(target_dir: str) -> str:
    return os.path.join(os.path.abspath(target_dir), SCAN_STATE_DIR)


def _load_baseline(target_dir: str) -> dict:
    """
    Φορτώνει το baseline από .malware_scan/baseline.json.
    Επιστρέφει empty dict αν δεν υπάρχει.

    Δομή baseline:
    {
      "prompt_version": "v11",
      "last_full_scan": "2024-01-01T12:00:00",
      "fingerprints": {
        "<fp_hex>": {
          "verdict": "BENIGN",
          "confidence": 0.9,
          "category": "network",
          "location": "src/downloader.py:42",
          "scanned_at": "2024-01-01T12:00:00"
        }
      }
    }
    """
    baseline_path = os.path.join(_scan_state_dir(target_dir), BASELINE_FILE)
    if not os.path.exists(baseline_path):
        return {"fingerprints": {}}
    with open(baseline_path, encoding="utf-8") as f:
        return json.load(f)


def _save_baseline(target_dir: str, baseline: dict) -> None:
    state_dir = _scan_state_dir(target_dir)
    os.makedirs(state_dir, exist_ok=True)
    baseline_path = os.path.join(state_dir, BASELINE_FILE)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)

    # Δημιούργησε .gitignore μέσα στο .malware_scan/ για να κρατάμε
    # τα baseline αρχεία αλλά να αγνοούμε τα temp αρχεία
    gitignore = os.path.join(state_dir, ".gitignore")
    if not os.path.exists(gitignore):
        with open(gitignore, "w") as f:
            f.write("# Malware Scanner State\n")
            f.write("# Commit baseline.json και last_scan.json στο git\n")
            f.write("# για να διατηρείται το state μεταξύ CI runs.\n")
            f.write("*.tmp\n")
            f.write("*.bak\n")


def _update_baseline_from_report(baseline: dict, chains: list, report: dict) -> dict:
    """
    Ενημερώνει το baseline με τα αποτελέσματα ενός report.
    Κάθε chain verdict αποθηκεύεται με fingerprint ως key.
    """
    chain_details = report.get("chain_details", [])
    for chain_detail in chain_details:
        chain_idx = chain_detail.get("chain_index", -1)
        if chain_idx < 0 or chain_idx >= len(chains):
            continue
        chain = chains[chain_idx]
        fp = chain_fingerprint(chain)
        llm_eval = chain_detail.get("llm_evaluation", {})
        baseline["fingerprints"][fp] = {
            "verdict": llm_eval.get("verdict", "UNKNOWN"),
            "confidence": llm_eval.get("confidence", 0),
            "category": chain.get("category", ""),
            "location": chain.get("location", ""),
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "prompt_version": PROMPT_VERSION,
        }
    baseline["prompt_version"] = PROMPT_VERSION
    return baseline


# ─────────────────────────────────────────────────────────────────────────────
# Main modes
# ─────────────────────────────────────────────────────────────────────────────

def mode_full(args):
    """
    Πλήρης ανάλυση — τρέχει CodeQL σε ολόκληρο το target repo,
    αναλύει ΟΛΑ τα chains, αποθηκεύει baseline.
    """
    print(f"\n{'='*70}")
    print(f"FULL SCAN — {args.package} @ {args.target}")
    print(f"{'='*70}\n")

    # 1. CodeQL pipeline
    chain_json = _run_codeql_pipeline(args.target)
    if chain_json is None:
        print("[!] CodeQL pipeline απέτυχε.")
        sys.exit(1)

    chains, pkg_data = _load_chains(chain_json)
    print(f"[*] Chains βρέθηκαν: {len(chains)}")

    if not chains:
        print("[*] Δεν βρέθηκαν behavior chains — το repo είναι clean.")
        baseline = _load_baseline(args.target)
        baseline["last_full_scan"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        baseline["prompt_version"] = PROMPT_VERSION
        _save_baseline(args.target, baseline)
        return

    # Αντιγραφή JSON στο test_set με το όνομα του package
    pkg_json = os.path.join(_THESIS_ROOT, "test_set", f"{args.package}.json")
    shutil.copy2(chain_json, pkg_json)
    print(f"[*] Chain JSON → {pkg_json}")

    # 2. LLM evaluation
    print(f"\n[*] LLM ανάλυση όλων των {len(chains)} chains...")
    report = _evaluate_chains(pkg_json, args.evaluator)
    if report is None:
        print("[!] LLM evaluation απέτυχε.")
        sys.exit(1)

    # 3. Update baseline
    baseline = _load_baseline(args.target)
    baseline = _update_baseline_from_report(baseline, chains, report)
    baseline["last_full_scan"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    _save_baseline(args.target, baseline)

    # 4. Save last_scan
    state_dir = _scan_state_dir(args.target)
    os.makedirs(state_dir, exist_ok=True)
    with open(os.path.join(state_dir, LAST_SCAN_FILE), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    _print_summary(report, mode="full", chains_total=len(chains),
                   chains_analyzed=len(chains))


def mode_incremental(args):
    """
    Incremental ανάλυση — τρέχει CodeQL στο full repo αλλά αναλύει
    μόνο chains που αφορούν changed files και δεν έχουν ίδιο fingerprint
    με ήδη αναλυμένα chains.
    """
    print(f"\n{'='*70}")
    print(f"INCREMENTAL SCAN — {args.package} | commit {args.commit[:8] if args.commit else 'HEAD'}")
    print(f"{'='*70}\n")

    if not args.commit or not args.prev_commit:
        print("[!] Incremental mode απαιτεί --commit και --prev-commit.")
        sys.exit(1)

    # 1. Changed files
    changed_files = _git_changed_files(args.target, args.commit, args.prev_commit)
    if not changed_files:
        print("[*] Δεν βρέθηκαν changed files. Τίποτα να αναλυθεί.")
        return

    # 2. CodeQL (full repo)
    chain_json = _run_codeql_pipeline(args.target)
    if chain_json is None:
        print("[!] CodeQL pipeline απέτυχε.")
        sys.exit(1)

    chains, pkg_data = _load_chains(chain_json)
    print(f"[*] Σύνολο chains στο repo: {len(chains)}")

    # 3. Φιλτράρισμα: chains που αγγίζουν changed files
    relevant_indices = []
    for i, chain in enumerate(chains):
        touched = chain_touched_files(chain)
        # Normalize: αφαίρεσε leading slash, vendor prefix κτλ.
        touched_normalized = {f.lstrip("/").lstrip("./") for f in touched}
        if any(
            cf in touched_normalized or any(t.endswith(cf) or cf.endswith(t)
                                            for t in touched_normalized)
            for cf in changed_files
        ):
            relevant_indices.append(i)

    print(f"[*] Chains που αφορούν changed files: {len(relevant_indices)}/{len(chains)}")

    if not relevant_indices:
        print("[*] Κανένα chain δεν αφορά τα changed files. Τίποτα να αναλυθεί.")
        return

    # 4. Cross-ref με baseline fingerprints
    baseline = _load_baseline(args.target)
    known_fps = set(baseline.get("fingerprints", {}).keys())

    new_indices = []
    skipped_count = 0
    for i in relevant_indices:
        fp = chain_fingerprint(chains[i])
        if fp in known_fps:
            skipped_count += 1
        else:
            new_indices.append(i)

    print(f"[*] Ήδη αναλυμένα (ίδιο fingerprint): {skipped_count}")
    print(f"[*] Νέα chains για ανάλυση: {len(new_indices)}")

    if not new_indices:
        print("[✓] Όλα τα affected chains έχουν ήδη αναλυθεί — repo clean.")
        return

    # 5. LLM evaluation μόνο στα νέα chains
    print(f"\n[*] Αποστολή {len(new_indices)} νέων chains στο LLM...")
    report = _evaluate_subset(chains, new_indices, pkg_data,
                              args.package, args.evaluator)
    if report is None:
        print("[!] LLM evaluation απέτυχε.")
        sys.exit(1)

    # 6. Update baseline
    # Για τα νέα chains, χρησιμοποιούμε τους original indices
    # αλλά το report έχει chain_index 0,1,2... (από το subset JSON)
    # Mapping: report chain_index i → original chains[new_indices[i]]
    chain_details = report.get("chain_details", [])
    for detail in chain_details:
        subset_idx = detail.get("chain_index", -1)
        if 0 <= subset_idx < len(new_indices):
            original_chain = chains[new_indices[subset_idx]]
            fp = chain_fingerprint(original_chain)
            llm_eval = detail.get("llm_evaluation", {})
            baseline["fingerprints"][fp] = {
                "verdict": llm_eval.get("verdict", "UNKNOWN"),
                "confidence": llm_eval.get("confidence", 0),
                "category": original_chain.get("category", ""),
                "location": original_chain.get("location", ""),
                "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "prompt_version": PROMPT_VERSION,
                "commit": args.commit,
            }

    baseline["last_incremental_scan"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    baseline["last_commit"] = args.commit
    _save_baseline(args.target, baseline)

    # 7. Save incremental report
    sha_short = args.commit[:8] if len(args.commit) >= 8 else args.commit
    state_dir = _scan_state_dir(args.target)
    inc_dir = os.path.join(state_dir, INCREMENTAL_DIR)
    os.makedirs(inc_dir, exist_ok=True)
    inc_report_path = os.path.join(inc_dir, f"commit_{sha_short}.json")

    incremental_report = {
        "commit": args.commit,
        "prev_commit": args.prev_commit,
        "package": args.package,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "prompt_version": PROMPT_VERSION,
        "changed_files": sorted(changed_files),
        "chains_total": len(chains),
        "chains_relevant": len(relevant_indices),
        "chains_skipped_known": skipped_count,
        "chains_analyzed": len(new_indices),
        "final_verdict": report.get("final_verdict", "UNKNOWN"),
        "chain_details": chain_details,
    }
    with open(inc_report_path, "w", encoding="utf-8") as f:
        json.dump(incremental_report, f, indent=2, ensure_ascii=False)

    _print_summary(report, mode="incremental", chains_total=len(chains),
                   chains_analyzed=len(new_indices), chains_skipped=skipped_count,
                   changed_files=changed_files)
    print(f"\n[✓] Incremental report → {inc_report_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(report: dict, mode: str, chains_total: int,
                   chains_analyzed: int, chains_skipped: int = 0,
                   changed_files: set = None):
    verdict = report.get("final_verdict", "UNKNOWN")
    mal_chains = report.get("malicious_chains", 0)
    sus_chains = report.get("suspicious_chains", 0)

    print(f"\n{'='*70}")
    print(f"ΑΠΟΤΕΛΕΣΜΑ {'FULL' if mode == 'full' else 'INCREMENTAL'} SCAN")
    print(f"{'='*70}")
    if mode == "incremental" and changed_files:
        print(f"Changed files: {', '.join(sorted(changed_files)[:5])}"
              + (" ..." if len(changed_files) > 5 else ""))
        print(f"Chains skipped (known fingerprint): {chains_skipped}")
    print(f"Chains analyzed: {chains_analyzed}/{chains_total}")
    print(f"Final verdict:   {verdict}")
    print(f"Malicious chains: {mal_chains} | Suspicious: {sus_chains}")

    # Εκτύπωση MALICIOUS chains με location
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        print(f"\n{'⚠️  ALERT' if verdict == 'MALICIOUS' else '⚡ WARNING'}: "
              f"{'Malicious' if verdict == 'MALICIOUS' else 'Suspicious'} behavior detected!")
        for detail in report.get("chain_details", []):
            llm = detail.get("llm_evaluation", {})
            if llm.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
                loc = detail.get("location", "unknown location")
                cat = detail.get("category", "?")
                conf = llm.get("confidence", 0)
                print(f"  → [{llm['verdict']}] {loc} | category={cat} | confidence={conf:.2f}")
                reasoning = llm.get("reasoning", {})
                print(f"     {str(reasoning.get('code_intent', ''))[:120]}")
    else:
        print(f"\n✓ No malicious behavior detected in analyzed chains.")
    print(f"{'='*70}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Incremental malware scanner for Git repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", required=True,
                        help="Path to the repository/directory to scan")
    parser.add_argument("--package", required=True,
                        help="Package name (used for report naming)")
    parser.add_argument("--mode", choices=["full", "incremental"], default="full",
                        help="Scan mode: 'full' (baseline) or 'incremental' (diff-only)")
    parser.add_argument("--commit", default=None,
                        help="[incremental] Current commit SHA")
    parser.add_argument("--prev-commit", default=None, dest="prev_commit",
                        help="[incremental] Previous commit SHA")
    parser.add_argument("--evaluator",
                        default=os.path.join(_INFERENCE_DIR, "llm_evaluator.py"),
                        help="Path to LLM evaluator script")

    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"[!] Target directory δεν υπάρχει: {args.target}")
        sys.exit(1)

    if not os.path.isfile(args.evaluator):
        print(f"[!] Evaluator script δεν υπάρχει: {args.evaluator}")
        sys.exit(1)

    if args.mode == "full":
        mode_full(args)
    else:
        mode_incremental(args)


if __name__ == "__main__":
    main()

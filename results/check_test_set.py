"""
Run inference/llm_evaluator.py on EVERY *.json of an evaluation folder (chains files produced by the
CodeQL pipeline, one per package, e.g. dataset/rag_test or dataset/benign_test_set) and collect the
verdicts into a final table and a summary JSON.

Usage:
    RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test [expected_labels.json]

The file name MUST be the package name: llm_evaluator.py names the report after it
(results/<RESULTS_TAG>/report_<package>.json).

Resumable: packages that already have a complete report are skipped; EVALUATION_FAILED / INCOMPLETE /
UNKNOWN reports are evaluated again. With expected_labels.json ({"paramiko": "benign",
"some-malware": "malicious", ...}) the false positives / negatives are scored as well.

To produce a chains file by hand:
    export CODEQL_TARGET_DIR=/path/to/extracted/package/source
    cd inference/codeql_pipeline
    rm -f results/final_codeql_results_*.csv results/call_graph_*.csv \
          results/backward_slice_*.csv results/control_deps_*.csv \
          results/sliced_behavior_chain.json
    python3 analysis.py
    python3 build_behavior_chain.py
    cp results/sliced_behavior_chain.json /path/to/evaluation_folder/<package>.json
(The clean-up before analysis.py is NOT optional: otherwise a package on which CodeQL finds no code
"inherits" the behaviour of the previous package from its stale CSV files.)
"""

import json
import os
import subprocess
import sys

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION, RESULTS_TAG  # noqa: E402

DEFAULT_TEST_SET_DIR = os.path.join(_THESIS_ROOT, "dataset", "rag_test")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")

INFERENCE_DIR = os.path.join(_THESIS_ROOT, "inference")
# The LLM provider (deepseek/gemini/lmstudio/openrouter) is selected in .env - see inference/llm_providers.py
LLM_EVALUATOR = os.path.join(INFERENCE_DIR, "llm_evaluator.py")
LLM_RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", RESULTS_TAG)
# Verdicts that mean there is NO complete evaluation: retried on the next run and not scored (neither
# as correct nor as wrong).
RETRY_VERDICTS = ("EVALUATION_FAILED", "INCOMPLETE", "UNKNOWN")


def main():
    """Evaluate every package of the folder (skipping finished ones), print the table and write the summary."""
    # The folder is an argument, so the SAME script serves the malware and the benign sets. Absolute paths:
    # the evaluator runs with cwd=inference/, so a relative path (e.g. dataset/rag_test) would find nothing.
    test_set_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TEST_SET_DIR)
    labels_file = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else EXPECTED_LABELS_FILE)

    if not os.path.exists(test_set_dir):
        print(f"[!] Not found: {test_set_dir}")
        sys.exit(1)

    expected_labels = {}
    if os.path.exists(labels_file):
        with open(labels_file, "r", encoding="utf-8") as f:
            expected_labels = json.load(f)
        print(f"[*] {len(expected_labels)} expected labels loaded from {labels_file}")
    else:
        print(f"[*] {labels_file} not found - only the verdicts will be printed, without a score.")

    json_files = sorted(f for f in os.listdir(test_set_dir) if f.endswith(".json"))
    packages = [f[:-5] for f in json_files]
    print(f"[*] {len(packages)} packages in {test_set_dir}")

    reports = {}
    skipped = 0
    for fname, pkg_name in zip(json_files, packages):
        report_path = os.path.join(LLM_RESULTS_DIR, f"report_{pkg_name}.json")

        # Resume: a VALID existing report that was not a failure is not run again. An
        # "EVALUATION_FAILED" (e.g. exhausted quota) does NOT count as done - it needs a real retry.
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                if existing.get("final_verdict") in RETRY_VERDICTS:
                    print(f"[*] Retrying (previous result was {existing.get('final_verdict')}): {pkg_name}")
                else:
                    reports[pkg_name] = existing
                    print(f"[{len(reports)}/{len(packages)}] Skipped (already evaluated): {pkg_name}")
                    skipped += 1
                    continue
            except Exception:
                pass  # corrupted report - evaluate again

        json_path = os.path.join(test_set_dir, fname)
        print(f"\n{'=' * 70}\n=== {pkg_name} ===\n{'=' * 70}")

        # sys.executable: the same Python (venv) as this script - a plain "python3" outside the venv would
        # fail on every package (no numpy/sentence_transformers) while the run carried on unevaluated.
        res = subprocess.run([sys.executable, LLM_EVALUATOR, json_path], cwd=INFERENCE_DIR)
        if res.returncode != 0:
            print(f"  [!] LLM evaluator error for {pkg_name} - skipped.")
            continue

        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                reports[pkg_name] = json.load(f)
        else:
            print(f"  [!] The expected report was not found: {report_path}")

    if skipped:
        print(f"\n[*] Total skipped (already evaluated by a previous run): {skipped}")

    # --- Final table ---
    print(f"\n\n{'=' * 90}")
    print("SUMMARY OF RESULTS")
    print(f"{'=' * 90}")
    print(f"{'Package':30s} {'Verdict':22s} {'Chains':8s} {'Expected':14s} {'Correct?':8s}")
    print("-" * 90)

    correct = 0
    scored = 0
    false_positives = []
    false_negatives = []          # really evaluated, the LLM said BENIGN
    static_analysis_misses = []   # NO_CHAINS_FOUND on known malware - CodeQL found nothing to evaluate
    benign_no_chains = []         # NO_CHAINS_FOUND on benign: correct end-to-end, but NOT a decision of the LLM
    inconclusive = []

    for pkg_name in packages:
        r = reports.get(pkg_name)
        verdict = r.get("final_verdict", "NOT_RUN") if r else "NOT_RUN"
        n_chains = r.get("total_chains_analyzed", "-") if r else "-"
        expected = expected_labels.get(pkg_name, "")

        if verdict in RETRY_VERDICTS or verdict == "NOT_RUN":
            inconclusive.append(pkg_name)
            print(f"{pkg_name:30s} {verdict:22s} {str(n_chains):8s} {expected:14s} {'? unclear':10s}")
            continue

        # NO_CHAINS_FOUND (CodeQL found NO sensitive behaviour) is not the same as "the LLM said BENIGN" -
        # it is a limit of the static-analysis stage. For benign labels it is the CORRECT outcome (no
        # false alarm); for malicious labels it is a real miss, but SEPARATE from an LLM reasoning miss,
        # so it is kept in its own list.
        if verdict == "NO_CHAINS_FOUND":
            scored += 1
            if expected == "benign":
                correct += 1
                benign_no_chains.append(pkg_name)
                print(f"{pkg_name:30s} {verdict:22s} {str(n_chains):8s} {expected:14s} {'✓':8s}")
            elif expected == "malicious":
                static_analysis_misses.append(pkg_name)
                print(f"{pkg_name:30s} {verdict:22s} {str(n_chains):8s} {expected:14s} {'✗ static':10s}")
            continue

        flagged = verdict in ("MALICIOUS", "SUSPICIOUS")
        is_correct = ""
        if expected == "benign":
            is_correct = "✓" if not flagged else "✗ FP"
            scored += 1
            if flagged:
                false_positives.append(pkg_name)
            else:
                correct += 1
        elif expected == "malicious":
            is_correct = "✓" if flagged else "✗ FN"
            scored += 1
            if flagged:
                correct += 1
            else:
                false_negatives.append(pkg_name)

        print(f"{pkg_name:30s} {verdict:22s} {str(n_chains):8s} {expected:14s} {is_correct:8s}")

    if scored:
        print("-" * 90)
        print(f"\n[*] END-TO-END score (including static-analysis misses): {correct}/{scored} ({correct/scored*100:.0f}%)")
        # symmetric: NO_CHAINS_FOUND packages of BOTH classes are excluded
        llm_stage_scored = scored - len(static_analysis_misses) - len(benign_no_chains)
        llm_stage_correct = correct - len(benign_no_chains)
        if llm_stage_scored:
            print(f"[*] LLM-stage-only score (no NO_CHAINS_FOUND in either class): "
                  f"{llm_stage_correct}/{llm_stage_scored} ({llm_stage_correct/llm_stage_scored*100:.0f}%)")
        if benign_no_chains:
            print(f"[*] Benign without chains (TN end-to-end only): {len(benign_no_chains)}")
        if false_positives:
            print(f"[!] False Positives ({len(false_positives)}): {false_positives}")
        if false_negatives:
            print(f"[!] False Negatives - evaluated by the LLM but BENIGN ({len(false_negatives)}): {false_negatives}")
        if static_analysis_misses:
            print(f"[!] Static-analysis misses - CodeQL found nothing to evaluate "
                  f"({len(static_analysis_misses)}): {static_analysis_misses[:10]}"
                  f"{'...' if len(static_analysis_misses) > 10 else ''}")
    if inconclusive:
        print(f"\n[?] Unclear (API failure or no report written - NOT scored) - {len(inconclusive)}: "
              f"{inconclusive[:10]}{'...' if len(inconclusive) > 10 else ''}")
        print(f"    Run the same script again - they will be retried automatically.")

    # one file per (run, test set): the malware and benign sets of the same RAG_MODE run in parallel
    summary_out = os.path.join(_THESIS_ROOT, "results", "test_set_summaries",
                               f"test_set_summary_{RESULTS_TAG}_{os.path.basename(test_set_dir)}.json")
    os.makedirs(os.path.dirname(summary_out), exist_ok=True)
    llm_stage_scored = scored - len(static_analysis_misses) - len(benign_no_chains)
    with open(summary_out, "w", encoding="utf-8") as f:
        json.dump({
            "results": {pkg: reports.get(pkg, {}).get("final_verdict", "NOT_RUN") for pkg in packages},
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "static_analysis_misses": static_analysis_misses,
            "benign_no_chains": benign_no_chains,
            "inconclusive": inconclusive,
            "correct": correct,
            "correct_llm_stage_only": correct - len(benign_no_chains),
            "scored_end_to_end": scored,
            "scored_llm_stage_only": llm_stage_scored,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Summary -> {summary_out}")
    print(f"[✓] Full LLM reports -> {LLM_RESULTS_DIR}/report_<package>.json")


if __name__ == "__main__":
    main()

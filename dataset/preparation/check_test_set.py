"""
Τρέχει το llm_evaluator.py πάνω σε ΚΑΘΕ *.json μέσα στο test_set/ (ήδη
παραγμένα sliced_behavior_chain.json, ένα ανά πακέτο - εσύ τα φτιάχνεις
χειροκίνητα με analysis.py + build_behavior_chain.py), και συγκεντρώνει
τα verdicts σε έναν τελικό πίνακα.

ΔΟΜΗ ΠΟΥ ΠΕΡΙΜΕΝΕΙ:
    /Users/giorgos/Documents/Thesis/test_set/
        paramiko.json        <- sliced_behavior_chain.json, μετονομασμένο
        fabric.json
        boto3.json
        some-known-malware.json
        ...

(Το filename ΠΡΕΠΕΙ να είναι το όνομα του πακέτου - το llm_evaluator.py
παίρνει από εκεί το όνομα του report που θα γράψει.)

Για να παράξεις ένα τέτοιο αρχείο χειροκίνητα:
    export CODEQL_TARGET_DIR=/path/to/extracted/paramiko/source
    cd /Users/giorgos/Documents/Thesis/inference/codeql_pipeline
    rm -f results/final_codeql_results_*.csv results/call_graph_*.csv \
          results/backward_slice_*.csv results/control_deps_*.csv \
          results/sliced_behavior_chain.json
    python3 analysis.py
    python3 build_behavior_chain.py
    cp results/sliced_behavior_chain.json /Users/giorgos/Documents/Thesis/test_set/paramiko.json

(Το καθάρισμα πριν το analysis.py ΔΕΝ είναι προαιρετικό - βλ. το stale-CSV
bug που βρήκαμε στο πρώτο benign test. Χωρίς αυτό, ένα πακέτο όπου το
CodeQL δεν βρίσκει κώδικα "κληρονομεί" το behavior του προηγούμενου.)

ΠΡΟΑΙΡΕΤΙΚΟ - expected_labels.json, για αυτόματο σκορ false positive/negative:
    {"paramiko": "benign", "fabric": "benign", "some-known-malware": "malicious"}
"""

import json
import os
import subprocess
import sys

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION  # noqa: E402

DEFAULT_TEST_SET_DIR = os.path.join(_THESIS_ROOT, "test_set")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")

INFERENCE_DIR = os.path.join(_THESIS_ROOT, "inference")
LLM_EVALUATOR = os.path.join(INFERENCE_DIR, "llm_evaluator_lmstudio.py")
LLM_RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)


def main():
    # ΝΕΟ: δέχεται τον φάκελο ως όρισμα, ώστε το ΙΔΙΟ script να δουλεύει και
    # για το rag_test/ (391 ήδη επεξεργασμένα, γνωστά malicious) και για το
    # test_set/ (benign, όταν το ετοιμάσεις) - χωρίς διπλό κώδικα.
    test_set_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TEST_SET_DIR
    labels_file = sys.argv[2] if len(sys.argv) > 2 else EXPECTED_LABELS_FILE

    if not os.path.exists(test_set_dir):
        print(f"[!] Δεν βρέθηκε: {test_set_dir}")
        sys.exit(1)

    expected_labels = {}
    if os.path.exists(labels_file):
        with open(labels_file, "r", encoding="utf-8") as f:
            expected_labels = json.load(f)
        print(f"[*] {len(expected_labels)} αναμενόμενες ετικέτες φορτώθηκαν από {labels_file}")
    else:
        print(f"[*] Δεν βρέθηκε {labels_file} - θα τυπωθούν μόνο τα verdicts, χωρίς σκορ.")

    json_files = sorted(f for f in os.listdir(test_set_dir) if f.endswith(".json"))
    packages = [f[:-5] for f in json_files]
    print(f"[*] {len(packages)} πακέτα στο {test_set_dir}")

    reports = {}
    skipped = 0
    for fname, pkg_name in zip(json_files, packages):
        report_path = os.path.join(LLM_RESULTS_DIR, f"report_{pkg_name}.json")

        # ΝΕΟ: resume - αν υπάρχει ήδη ΕΓΚΥΡΟ report ΚΑΙ δεν ήταν αποτυχία API,
        # μην το ξανατρέξεις. Ένα "EVALUATION_FAILED" (π.χ. εξαντλημένο quota)
        # ΔΕΝ μετράει ως "ήδη έτοιμο" - χρειάζεται πραγματική επανάληψη.
        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                if existing.get("final_verdict") == "EVALUATION_FAILED":
                    print(f"[*] Ξαναπροσπάθεια (προηγούμενο ήταν EVALUATION_FAILED): {pkg_name}")
                else:
                    reports[pkg_name] = existing
                    print(f"[{len(reports)}/{len(packages)}] Παράλειψη (ήδη αξιολογημένο): {pkg_name}")
                    skipped += 1
                    continue
            except Exception:
                pass  # κατεστραμμένο report - ξαναπροσπάθησε κανονικά

        json_path = os.path.join(test_set_dir, fname)
        print(f"\n{'=' * 70}\n=== {pkg_name} ===\n{'=' * 70}")

        res = subprocess.run(["python3", LLM_EVALUATOR, json_path], cwd=INFERENCE_DIR)
        if res.returncode != 0:
            print(f"  [!] Σφάλμα LLM evaluator για {pkg_name} - παράλειψη.")
            continue

        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                reports[pkg_name] = json.load(f)
        else:
            print(f"  [!] Δεν βρέθηκε το αναμενόμενο report: {report_path}")

    if skipped:
        print(f"\n[*] Σύνολο παραλειφθέντων (ήδη αξιολογημένα από προηγούμενο run): {skipped}")

    # --- Τελικός πίνακας ---
    print(f"\n\n{'=' * 90}")
    print("ΣΥΓΚΕΝΤΡΩΤΙΚΑ ΑΠΟΤΕΛΕΣΜΑΤΑ")
    print(f"{'=' * 90}")
    print(f"{'Πακέτο':30s} {'Verdict':22s} {'Chains':8s} {'Αναμενόμενο':14s} {'Σωστό;':8s}")
    print("-" * 90)

    correct = 0
    scored = 0
    false_positives = []
    false_negatives = []          # Πραγματικά αξιολογήθηκε, το LLM είπε BENIGN
    static_analysis_misses = []   # NO_CHAINS_FOUND σε γνωστό malicious - το CodeQL δεν βρήκε τίποτα να αξιολογήσει
    inconclusive = []

    for pkg_name in packages:
        r = reports.get(pkg_name)
        verdict = r.get("final_verdict", "ΔΕΝ ΤΡΕΞΕ") if r else "ΔΕΝ ΤΡΕΞΕ"
        n_chains = r.get("total_chains_analyzed", "-") if r else "-"
        expected = expected_labels.get(pkg_name, "")

        if verdict in ("EVALUATION_FAILED", "ΔΕΝ ΤΡΕΞΕ"):
            inconclusive.append(pkg_name)
            print(f"{pkg_name:30s} {verdict:22s} {str(n_chains):8s} {expected:14s} {'? ασαφές':10s}")
            continue

        # ΝΕΟ: NO_CHAINS_FOUND (το CodeQL δεν βρήκε ΚΑΜΙΑ ευαίσθητη
        # συμπεριφορά) ΔΕΝ είναι το ίδιο με "το LLM είπε BENIGN" - είναι
        # limitation του static-analysis σταδίου. Για benign labels είναι
        # στην πραγματικότητα το ΣΩΣΤΟ αποτέλεσμα (καμία ψευδής συναγερμός).
        # Για malicious labels είναι πραγματικό κενό, αλλά ΞΕΧΩΡΙΣΤΟ από
        # ένα LLM reasoning miss - καταγράφεται σε δική του λίστα.
        if verdict == "NO_CHAINS_FOUND":
            scored += 1
            if expected == "benign":
                correct += 1
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
        print(f"\n[*] Σκορ END-TO-END (μαζί με static-analysis misses): {correct}/{scored} ({correct/scored*100:.0f}%)")
        llm_stage_scored = scored - len(static_analysis_misses)
        if llm_stage_scored:
            print(f"[*] Σκορ ΜΟΝΟ LLM-stage (εξαιρεί static-analysis misses): "
                  f"{correct}/{llm_stage_scored} ({correct/llm_stage_scored*100:.0f}%)")
        if false_positives:
            print(f"[!] False Positives ({len(false_positives)}): {false_positives}")
        if false_negatives:
            print(f"[!] False Negatives - LLM αξιολόγησε αλλά είπε BENIGN ({len(false_negatives)}): {false_negatives}")
        if static_analysis_misses:
            print(f"[!] Static-analysis misses - CodeQL δεν βρήκε τίποτα να αξιολογήσει "
                  f"({len(static_analysis_misses)}): {static_analysis_misses[:10]}"
                  f"{'...' if len(static_analysis_misses) > 10 else ''}")
    if inconclusive:
        print(f"\n[?] Ασαφή (API failure ή ποτέ δεν έγραψε report - ΔΕΝ μετρήθηκαν) - {len(inconclusive)}: "
              f"{inconclusive[:10]}{'...' if len(inconclusive) > 10 else ''}")
        print(f"    Ξανατρέξε το ίδιο script - αυτά θα ξαναπροσπαθήσουν αυτόματα.")

    summary_out = os.path.join(_THESIS_ROOT, f"test_set_summary_{PROMPT_VERSION}.json")
    llm_stage_scored = scored - len(static_analysis_misses)
    with open(summary_out, "w", encoding="utf-8") as f:
        json.dump({
            "results": {pkg: reports.get(pkg, {}).get("final_verdict", "ΔΕΝ ΤΡΕΞΕ") for pkg in packages},
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "static_analysis_misses": static_analysis_misses,
            "inconclusive": inconclusive,
            "correct": correct,
            "scored_end_to_end": scored,
            "scored_llm_stage_only": llm_stage_scored,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Περίληψη -> {summary_out}")
    print(f"[✓] Πλήρη LLM reports -> {LLM_RESULTS_DIR}/report_<πακέτο>.json")


if __name__ == "__main__":
    main()

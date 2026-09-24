"""
Συγκεντρωτική στατιστική αξιολόγηση όλων των report_*.json.

Παράγει:
  1. Κατανομή τελικών verdicts (ανά πακέτο) + πόσα analyzed συνολικά
  2. Ποιο μοντέλο απάντησε ανά chain (Gemini vs OpenRouter fallback) -
     χρήσιμο για methodological transparency στο thesis
  3. Confusion matrix + accuracy/precision/recall/F1, σε ΔΥΟ ορισμούς
     "θετικού" αποτελέσματος:
       - STRICT:  θετικό = μόνο MALICIOUS
       - LENIENT: θετικό = MALICIOUS ή SUSPICIOUS
     (χρήσιμο γιατί το SSVC έχει 4 επίπεδα, όχι binary - η επιλογή ορίου
     επηρεάζει τα νούμερα, αξίζει να τα δείξεις και τα δύο)
  4. Similarity score (RAG retrieval) ανά τελικό verdict - ελέγχει αν το
     similarity πραγματικά διακρίνει benign/malicious ή είναι απλά ένα
     "βρέθηκε κάτι κοντινό" binary σήμα (ό,τι είχαμε ήδη δει σε μικρότερο
     δείγμα - εδώ ενσωματωμένο, ώστε να μη χρειάζεται ξεχωριστό script).

Χρήση:  python3 results/evaluation_summary.py [tag ...]      π.χ. v12_samples
        - με ορίσματα: μόνο αυτά τα runs
        - χωρίς ορίσματα, με RAG_MODE στο περιβάλλον: το run αυτού του RAG_MODE
        - χωρίς τίποτα: όλα τα results/<PROMPT_VERSION>_* (εκτός smoke), και όσα τρέχουν ακόμα

Διαβάζει: results/<tag>/report_*.json
          expected_labels.json (προαιρετικό, για metrics)
"""

import glob
import json
import os

import sys
_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION, RESULTS_TAG  # noqa: E402

RESULTS_ROOT = os.path.join(_THESIS_ROOT, "results")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")
# Δομή του results/: <tag>/report_*.json, evaluation_summaries/, test_set_summaries/
SUMMARY_DIR = os.path.join(RESULTS_ROOT, "evaluation_summaries")


def select_tags():
    if len(sys.argv) > 1:
        return [os.path.basename(os.path.normpath(t)) for t in sys.argv[1:]]
    if os.environ.get("RAG_MODE"):
        return [RESULTS_TAG]
    return sorted(os.path.basename(d) for d in glob.glob(os.path.join(RESULTS_ROOT, f"{PROMPT_VERSION}_*"))
                  if os.path.isdir(d) and "smoke" not in os.path.basename(d))


def load_reports(results_dir):
    reports = {}
    for path in glob.glob(os.path.join(results_dir, "report_*.json")):
        pkg_name = os.path.basename(path)[len("report_"):-len(".json")]
        try:
            with open(path, "r", encoding="utf-8") as f:
                reports[pkg_name] = json.load(f)
        except Exception as e:
            print(f"  [!] Αγνοήθηκε {path}: {e}")
    return reports


def safe_div(a, b):
    return a / b if b else 0.0


def compute_confusion(reports, expected_labels, positive_verdicts):
    """
    ΔΙΟΡΘΩΣΗ: το NO_CHAINS_FOUND (το CodeQL δεν βρήκε ΚΑΜΙΑ ευαίσθητη
    συμπεριφορά) ΔΕΝ είναι το ίδιο με "το LLM αξιολόγησε και είπε BENIGN" -
    είναι limitation του static-analysis σταδίου, όχι του LLM reasoning.
    Πριν, μετρούνταν σαν απλό False Negative, νοθεύοντας το recall όποτε
    υπάρχουν πολλά τέτοια πακέτα (π.χ. 50/399 σε ένα run). Τώρα: για
    benign labels μετράει σωστά ως TN (καμία ψευδής συναγερμός), για
    malicious labels πάει σε ΞΕΧΩΡΙΣΤΟ bucket (static_misses) - ίδια
    λογική με το check_test_set.py, που ήδη το έκανε σωστά.
    """
    tp = tn = fp = fn = 0
    static_misses = 0
    unscored = 0
    benign_no_chains = 0  # benign που το LLM δεν είδε ποτέ: TN μόνο στο end-to-end
    for pkg, r in reports.items():
        expected = expected_labels.get(pkg)
        if expected not in ("benign", "malicious"):
            continue  # χωρίς ετικέτα - δεν μπαίνει καν στο confusion matrix
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "INCOMPLETE", "UNKNOWN", None):
            unscored += 1  # ΔΕΝ μετράει ως λάθος - απλά δεν ξέρουμε
            continue
        if verdict == "NO_CHAINS_FOUND":
            if expected == "benign":
                benign_no_chains += 1  # σωστό end-to-end, αλλά ΟΧΙ απόφαση του LLM
            else:
                static_misses += 1  # ΞΕΧΩΡΙΣΤΟ από LLM reasoning miss
            continue
        flagged = verdict in positive_verdicts
        if expected == "malicious":
            tp += flagged
            fn += (not flagged)
        else:
            fp += flagged
            tn += (not flagged)
    return tp, tn, fp, fn, static_misses, unscored, benign_no_chains


def print_metrics(label, tp, tn, fp, fn, static_misses, unscored, benign_no_chains=0):
    # END-TO-END: ό,τι έκανε το ΣΥΣΤΗΜΑ - malware χωρίς chains = χαμένο (FN),
    # benign χωρίς chains = κανένας συναγερμός (TN).
    fn_end_to_end = fn + static_misses
    tn_end_to_end = tn + benign_no_chains
    total_e2e = tp + tn_end_to_end + fp + fn_end_to_end
    accuracy_e2e = safe_div(tp + tn_end_to_end, total_e2e)
    recall_e2e = safe_div(tp, tp + fn_end_to_end)
    fpr_e2e = safe_div(fp, fp + tn_end_to_end)

    # LLM-STAGE ONLY: ΜΟΝΟ πακέτα που αξιολόγησε το LLM - εξαιρούνται ΣΥΜΜΕΤΡΙΚΑ τα
    # NO_CHAINS_FOUND και των δύο κλάσεων (πριν, τα benign NO_CHAINS μετρούσαν ως TN).
    total_llm = tp + tn + fp + fn
    accuracy_llm = safe_div(tp + tn, total_llm)
    fpr_llm = safe_div(fp, fp + tn)
    precision = safe_div(tp, tp + fp)
    recall_llm = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall_llm, precision + recall_llm)

    print(f"\n--- {label} ---")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}  static-analysis-misses={static_misses}  "
          f"benign-no-chains={benign_no_chains}  (ασαφή/αγνοήθηκαν: {unscored})")
    print(f"  Accuracy  END-TO-END (NO_CHAINS: malware=FN, benign=TN): {accuracy_e2e:.3f}")
    print(f"  Recall    END-TO-END: {recall_e2e:.3f}")
    print(f"  FPR       END-TO-END: {fpr_e2e:.3f}")
    print(f"  Accuracy  LLM-STAGE ONLY (χωρίς NO_CHAINS και στις 2 κλάσεις): {accuracy_llm:.3f}")
    print(f"  FPR       LLM-STAGE ONLY: {fpr_llm:.3f}")
    trivial_note = "  [!] FP=0 -> τετριμμένο, χρειάζεσαι 'benign' ετικέτες στο expected_labels.json" \
        if fp == 0 and tp > 0 else ""
    print(f"  Precision LLM-STAGE ONLY: {precision:.3f}{trivial_note}")
    print(f"  Recall    LLM-STAGE ONLY: {recall_llm:.3f}")
    print(f"  F1        LLM-STAGE ONLY: {f1:.3f}")

    # ΝΕΟ: επίστρεψε τα ίδια νούμερα που μόλις τυπώθηκαν, ώστε ο καλών να
    # μπορεί να τα αποθηκεύσει - πριν, αυτοί οι υπολογισμοί ζούσαν ΜΟΝΟ
    # στην οθόνη, ποτέ στο αποθηκευμένο summary JSON.
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "static_analysis_misses": static_misses, "unscored": unscored,
        "benign_no_chains": benign_no_chains,
        "accuracy_end_to_end": round(accuracy_e2e, 4),
        "recall_end_to_end": round(recall_e2e, 4),
        "fpr_end_to_end": round(fpr_e2e, 4),
        "accuracy_llm_stage_only": round(accuracy_llm, 4),
        "fpr_llm_stage_only": round(fpr_llm, 4),
        "precision_llm_stage_only": round(precision, 4),
        "recall_llm_stage_only": round(recall_llm, 4),
        "f1_llm_stage_only": round(f1, 4),
        "precision_trivial": (fp == 0 and tp > 0),
    }


def main():
    expected_labels = {}
    if os.path.exists(EXPECTED_LABELS_FILE):
        with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
            expected_labels = json.load(f)
    tags = select_tags()
    if not tags:
        sys.exit(f"[!] Δεν βρέθηκαν αποτελέσματα ({RESULTS_ROOT}/{PROMPT_VERSION}_*)")
    for tag in tags:
        summarize(tag, expected_labels)


def summarize(tag, expected_labels):
    results_dir = os.path.join(RESULTS_ROOT, tag)
    summary_out = os.path.join(SUMMARY_DIR, f"evaluation_summary_{tag}.json")
    reports = load_reports(results_dir)
    print(f"\n{'=' * 70}\n{tag}\n{'=' * 70}")
    print(f"[*] {len(reports)} reports βρέθηκαν στο {results_dir}")
    if not reports:
        return

    # --- 1. Κατανομή τελικών verdicts (ανά πακέτο) ---
    verdict_counts = {}
    model_counts = {}
    total_chains = 0
    for r in reports.values():
        v = r.get("final_verdict", "?")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
        for c in r.get("chain_details", []):
            total_chains += 1
            m = c.get("llm_evaluation", {}).get("model_used", "άγνωστο/σφάλμα")
            model_counts[m] = model_counts.get(m, 0) + 1

    print(f"\n=== Κατανομή τελικών verdicts (ανά πακέτο, {len(reports)} σύνολο) ===")
    for v, n in sorted(verdict_counts.items(), key=lambda x: -x[1]):
        print(f"  {v:20s} {n}")

    # breakdown ανά prompt_version - χρήσιμο μόλις αρχίσεις να συγκρίνεις
    # v1 (baseline) έναντι v2/v3. Reports από ΠΡΙΝ την προσθήκη αυτού του
    # tracking θα δείχνουν "unversioned".
    version_counts = {}
    for r in reports.values():
        pv = r.get("prompt_version", "unversioned")
        version_counts[pv] = version_counts.get(pv, 0) + 1
    if len(version_counts) > 1:
        print(f"\n=== Κατανομή prompt_version (ανά πακέτο) ===")
        for pv, n in sorted(version_counts.items(), key=lambda x: -x[1]):
            print(f"  {pv:20s} {n}")

    print(f"\n=== Ποιο μοντέλο απάντησε (ανά chain, {total_chains} σύνολο) ===")
    for m, n in sorted(model_counts.items(), key=lambda x: -x[1]):
        pct = n / total_chains * 100 if total_chains else 0
        print(f"  {m:25s} {n:5d}  ({pct:.1f}%)")

    # --- 2. Confusion matrix / metrics ---
    n_benign_labels = sum(1 for v in expected_labels.values() if v == "benign")
    n_malicious_labels = sum(1 for v in expected_labels.values() if v == "malicious")
    print(f"\n[*] expected_labels.json: {n_malicious_labels} malicious, {n_benign_labels} benign")
    
    print_metrics_lenient = print_metrics("LENIENT (θετικό = MALICIOUS ή SUSPICIOUS)",
                                          *compute_confusion(reports, expected_labels, {"MALICIOUS", "SUSPICIOUS"}))

    if n_benign_labels == 0:
        print("\n[!] ΚΑΝΕΝΑ 'benign' label στο expected_labels.json ακόμα - το Precision/F1 "
              "παραπάνω είναι ΤΕΤΡΙΜΜΕΝΟ (FP πάντα 0, οπότε Precision=1.0 αυτόματα).")
        print("    Χρειάζεσαι αποτελέσματα από το test_set/ (benign πακέτα) για ουσιαστικό Precision/F1.")
        print("    Μέχρι τότε, το Accuracy παραπάνω ισοδυναμεί με Recall (True Positive Rate).")

    # --- 3. Similarity score ανά τελικό verdict (ανά chain) ---
    by_verdict = {"BENIGN": [], "SUSPICIOUS": [], "MALICIOUS": []}
    for r in reports.values():
        for c in r.get("chain_details", []):
            ev = c.get("llm_evaluation", {})
            verdict = ev.get("verdict")
            sim = c.get("top_malware_similarity")
            if verdict in by_verdict and isinstance(sim, (int, float)):
                by_verdict[verdict].append(sim)

    print(f"\n=== Similarity score (RAG retrieval) ανά τελικό verdict (ανά chain) ===")
    print(f"{'Verdict':15s} {'N':6s} {'Μέσος όρος':12s} {'Min':8s} {'Max':8s}")
    print("-" * 55)
    for verdict, sims in by_verdict.items():
        if not sims:
            print(f"{verdict:15s} {0:<6d} {'-':12s} {'-':8s} {'-':8s}")
            continue
        avg = sum(sims) / len(sims)
        print(f"{verdict:15s} {len(sims):<6d} {avg:<12.4f} {min(sims):<8.4f} {max(sims):<8.4f}")

    benign_avg = (sum(by_verdict["BENIGN"]) / len(by_verdict["BENIGN"])) if by_verdict["BENIGN"] else None
    malicious_all = by_verdict["MALICIOUS"] + by_verdict["SUSPICIOUS"]
    malicious_avg = (sum(malicious_all) / len(malicious_all)) if malicious_all else None

    if benign_avg is not None and malicious_avg is not None:
        diff = malicious_avg - benign_avg
        print(f"\nΔιαφορά μέσου όρου (MALICIOUS/SUSPICIOUS − BENIGN): {diff:+.4f}")
        if abs(diff) < 0.05:
            print("[!] Πολύ μικρή διαφορά - το similarity score ΔΕΝ φαίνεται να διακρίνει")
            print("    ουσιαστικά benign από malicious. Η πραγματική διάκριση γίνεται")
            print("    κυρίως από το LLM reasoning, όχι από το retrieval score.")
        else:
            print("[✓] Υπάρχει αισθητή διαφορά - το similarity ΕΧΕΙ κάποια διακριτική αξία.")

    # --- 4. Αποθήκευση για αναφορά ---
    summary = {
        "results_tag": tag,
        "total_reports": len(reports),
        "verdict_counts": verdict_counts,
        "model_used_counts": model_counts,
        "expected_labels_malicious": n_malicious_labels,
        "expected_labels_benign": n_benign_labels,
        "metrics_lenient": print_metrics_lenient,
    }
    os.makedirs(SUMMARY_DIR, exist_ok=True)
    with open(summary_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Περίληψη -> {summary_out}")


if __name__ == "__main__":
    main()
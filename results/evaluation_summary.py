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

Διαβάζει: /home/sklavenitis/thesis/results/report_*.json
          /home/sklavenitis/thesis/expected_labels.json (προαιρετικό, για metrics)
"""

import glob
import json
import os

RESULTS_DIR = "/home/sklavenitis/thesis/results"
EXPECTED_LABELS_FILE = "/home/sklavenitis/thesis/expected_labels.json"
SUMMARY_OUT = "/home/sklavenitis/thesis/evaluation_summary.json"


def load_reports():
    reports = {}
    for path in glob.glob(os.path.join(RESULTS_DIR, "report_*.json")):
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
    tp = tn = fp = fn = 0
    unscored = 0
    for pkg, r in reports.items():
        expected = expected_labels.get(pkg)
        if expected not in ("benign", "malicious"):
            continue  # χωρίς ετικέτα - δεν μπαίνει καν στο confusion matrix
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "UNKNOWN", None):
            unscored += 1  # ΔΕΝ μετράει ως λάθος - απλά δεν ξέρουμε
            continue
        flagged = verdict in positive_verdicts
        if expected == "malicious":
            tp += flagged
            fn += (not flagged)
        else:
            fp += flagged
            tn += (not flagged)
    return tp, tn, fp, fn, unscored


def print_metrics(label, tp, tn, fp, fn, unscored):
    total = tp + tn + fp + fn
    accuracy = safe_div(tp + tn, total)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    print(f"\n--- {label} ---")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}   (ασαφή/αγνοήθηκαν: {unscored})")
    print(f"  Accuracy:  {accuracy:.3f}")
    trivial_note = "  [!] FP=0 -> τετριμμένο, χρειάζεσαι 'benign' ετικέτες στο expected_labels.json" \
        if fp == 0 and tp > 0 else ""
    print(f"  Precision: {precision:.3f}{trivial_note}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1:        {f1:.3f}")


def main():
    reports = load_reports()
    expected_labels = {}
    if os.path.exists(EXPECTED_LABELS_FILE):
        with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
            expected_labels = json.load(f)

    print(f"[*] {len(reports)} reports βρέθηκαν στο {RESULTS_DIR}")

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

    print(f"\n=== Ποιο μοντέλο απάντησε (ανά chain, {total_chains} σύνολο) ===")
    for m, n in sorted(model_counts.items(), key=lambda x: -x[1]):
        pct = n / total_chains * 100 if total_chains else 0
        print(f"  {m:25s} {n:5d}  ({pct:.1f}%)")

    # --- 2. Confusion matrix / metrics ---
    n_benign_labels = sum(1 for v in expected_labels.values() if v == "benign")
    n_malicious_labels = sum(1 for v in expected_labels.values() if v == "malicious")
    print(f"\n[*] expected_labels.json: {n_malicious_labels} malicious, {n_benign_labels} benign")

    tp, tn, fp, fn, unscored = compute_confusion(reports, expected_labels, {"MALICIOUS"})
    print_metrics("STRICT (θετικό = μόνο MALICIOUS)", tp, tn, fp, fn, unscored)

    tp, tn, fp, fn, unscored = compute_confusion(reports, expected_labels, {"MALICIOUS", "SUSPICIOUS"})
    print_metrics("LENIENT (θετικό = MALICIOUS ή SUSPICIOUS)", tp, tn, fp, fn, unscored)

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
        "total_reports": len(reports),
        "verdict_counts": verdict_counts,
        "model_used_counts": model_counts,
        "expected_labels_malicious": n_malicious_labels,
        "expected_labels_benign": n_benign_labels,
    }
    with open(SUMMARY_OUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Περίληψη -> {SUMMARY_OUT}")


if __name__ == "__main__":
    main()

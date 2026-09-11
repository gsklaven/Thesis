"""
Ελέγχει αν το top_malware_similarity (RAG retrieval score) πραγματικά
συσχετίζεται με το τελικό LLM verdict, ή αν λειτουργεί απλά σαν binary
"βρέθηκε κάτι κοντινό" σήμα χωρίς πραγματική διαβάθμιση.

Αν οι μέσοι όροι similarity είναι σχεδόν ΙΔΙΟΙ ανάμεσα σε BENIGN και
MALICIOUS/SUSPICIOUS chains, αυτό είναι σημαντικό εύρημα για το thesis:
η πραγματική διάκριση γίνεται σχεδόν αποκλειστικά από το LLM reasoning,
όχι από το retrieval score - χρήσιμο επιχείρημα για το γιατί χρειάζεται
το δεύτερο (LLM) στάδιο, όχι μόνο threshold πάνω στο similarity.
"""

import glob
import json
import os

RESULTS_DIR = "/home/sklavenitis/thesis/results"


def main():
    by_verdict = {"BENIGN": [], "SUSPICIOUS": [], "MALICIOUS": []}

    for path in glob.glob(os.path.join(RESULTS_DIR, "report_*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue

        for c in d.get("chain_details", []):
            ev = c.get("llm_evaluation", {})
            verdict = ev.get("verdict")
            sim = c.get("top_malware_similarity")
            if verdict in by_verdict and isinstance(sim, (int, float)):
                by_verdict[verdict].append(sim)

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
            print("    ουσιαστικά benign από malicious στο δείγμα σου μέχρι στιγμής.")
            print("    Η πραγματική διάκριση γίνεται κυρίως από το LLM reasoning.")
        else:
            print("[✓] Υπάρχει αισθητή διαφορά - το similarity ΕΧΕΙ κάποια διακριτική αξία.")


if __name__ == "__main__":
    main()

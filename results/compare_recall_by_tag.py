"""
Συγκρίνει το recall ΜΕΣΑ σε κάθε bucket (unclassified έναντι πακέτων με
συγκεκριμένο σημασιολογικό tag), για να δούμε αν το "unclassified" έχει
πραγματικά χειρότερο recall, ή απλά κυριαρχεί αριθμητικά στο dataset.

Χρησιμοποιείται μετά από κάθε αλλαγή prompt, για να ελέγξουμε αν το
διαγνωσμένο χάσμα (p=0.0025 στο v1) στένεψε.
"""

import json
import os
import sys

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION  # noqa: E402

RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")
TAGS_FILE = os.path.join(_THESIS_ROOT, "dataset", "attack_type_tags.json")


def main():
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)
    tags = {}
    if os.path.exists(TAGS_FILE):
        with open(TAGS_FILE, "r", encoding="utf-8") as f:
            tags = json.load(f)

    buckets = {"unclassified": {"tp": 0, "fn": 0}, "tagged": {"tp": 0, "fn": 0}}
    static_misses = {"unclassified": 0, "tagged": 0}

    for fname in os.listdir(RESULTS_DIR):
        if not (fname.startswith("report_") and fname.endswith(".json")):
            continue
        pkg = fname[len("report_"):-len(".json")]
        if expected_labels.get(pkg) != "malicious":
            continue

        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            r = json.load(f)
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "UNKNOWN", None):
            continue

        pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["unclassified"])
        bucket = "unclassified" if pkg_tags == ["unclassified"] else "tagged"

        # ΔΙΟΡΘΩΣΗ: NO_CHAINS_FOUND είναι static-analysis gap - το CodeQL δεν
        # έδωσε ΚΑΝΕΝΑ chain στο LLM, άρα δεν λέει τίποτα για το αν το tag
        # (unclassified/tagged) βοήθησε ή όχι το LLM reasoning. Εξαιρείται
        # εντελώς εδώ, αντί να μετράει σαν "το tag δεν βοήθησε".
        if verdict == "NO_CHAINS_FOUND":
            static_misses[bucket] += 1
            continue

        flagged = verdict in ("MALICIOUS", "SUSPICIOUS")
        if flagged:
            buckets[bucket]["tp"] += 1
        else:
            buckets[bucket]["fn"] += 1

    print(f"{'Bucket':15s} {'TP':6s} {'FN':6s} {'Recall':8s} {'static-misses':14s}")
    print("-" * 55)
    for name, b in buckets.items():
        total = b["tp"] + b["fn"]
        recall = b["tp"] / total if total else 0.0
        print(f"{name:15s} {b['tp']:<6d} {b['fn']:<6d} {recall:.3f}  (n={total})   "
              f"{static_misses[name]:<14d}")


if __name__ == "__main__":
    main()

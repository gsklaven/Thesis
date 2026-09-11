"""
Συγκρίνει το recall ΜΕΣΑ σε κάθε bucket (unclassified έναντι πακέτων με
συγκεκριμένο σημασιολογικό tag), για να δούμε αν το "unclassified" έχει
πραγματικά χειρότερο recall, ή απλά κυριαρχεί αριθμητικά στο dataset.
"""

import glob
import json
import os

import sys
sys.path.insert(0, "/home/sklavenitis/thesis/inference")
from query_rag import PROMPT_VERSION  # noqa: E402

RESULTS_DIR = f"/home/sklavenitis/thesis/results/{PROMPT_VERSION}"
EXPECTED_LABELS_FILE = "/home/sklavenitis/thesis/expected_labels.json"
TAGS_FILE = "/home/sklavenitis/thesis/dataset/attack_type_tags.json"


def main():
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)
    tags = {}
    if os.path.exists(TAGS_FILE):
        with open(TAGS_FILE, "r", encoding="utf-8") as f:
            tags = json.load(f)

    buckets = {"unclassified": {"tp": 0, "fn": 0}, "tagged": {"tp": 0, "fn": 0}}

    for path in glob.glob(os.path.join(RESULTS_DIR, "report_*.json")):
        pkg = os.path.basename(path)[len("report_"):-len(".json")]
        if expected_labels.get(pkg) != "malicious":
            continue
        with open(path, "r", encoding="utf-8") as f:
            r = json.load(f)
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "UNKNOWN", None):
            continue

        pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["unclassified"])
        bucket = "unclassified" if pkg_tags == ["unclassified"] else "tagged"

        flagged = verdict in ("MALICIOUS", "SUSPICIOUS")
        if flagged:
            buckets[bucket]["tp"] += 1
        else:
            buckets[bucket]["fn"] += 1

    print(f"{'Bucket':15s} {'TP':6s} {'FN':6s} {'Recall':8s}")
    print("-" * 40)
    for name, b in buckets.items():
        total = b["tp"] + b["fn"]
        recall = b["tp"] / total if total else 0.0
        print(f"{name:15s} {b['tp']:<6d} {b['fn']:<6d} {recall:.3f}  (n={total})")


if __name__ == "__main__":
    main()

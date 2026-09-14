"""
Πιο ακριβές τεστ από το compare_recall_by_tag.py - μετράει ΑΚΡΙΒΩΣ τη
μεταβλητή που άλλαξε με το OSV-description enrichment: έχει το ΙΔΙΟ το
πακέτο πραγματικό OSV description (ναι/όχι), όχι αν χτυπάει κάποιο keyword
tag. Αυτά τα δύο ΔΕΝ ταυτίζονται - ένα πακέτο μπορεί να έχει description
και να παραμένει "unclassified" αν το κείμενό του απλά δεν περιέχει καμία
από τις λέξεις-κλειδιά του attack_type_tagger.py.
"""

import json
import os
import sys

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION  # noqa: E402

RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")

_DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
_DEDUPED_JSON = os.path.join(_DATASET_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(_DATASET_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON


def main():
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)

    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    has_description = {
        item.get("package_name", ""): bool((item.get("description") or "").strip())
        for item in dataset
    }

    buckets = {"has_description": {"tp": 0, "fn": 0}, "no_description": {"tp": 0, "fn": 0}}
    static_misses = {"has_description": 0, "no_description": 0}

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

        bucket = "has_description" if has_description.get(pkg, False) else "no_description"

        if verdict == "NO_CHAINS_FOUND":
            static_misses[bucket] += 1
            continue

        flagged = verdict in ("MALICIOUS", "SUSPICIOUS")
        if flagged:
            buckets[bucket]["tp"] += 1
        else:
            buckets[bucket]["fn"] += 1

    print(f"{'Bucket':18s} {'TP':6s} {'FN':6s} {'Recall':8s} {'static-misses':14s}")
    print("-" * 58)
    for name, b in buckets.items():
        total = b["tp"] + b["fn"]
        recall = b["tp"] / total if total else 0.0
        print(f"{name:18s} {b['tp']:<6d} {b['fn']:<6d} {recall:.3f}  (n={total})   "
              f"{static_misses[name]:<14d}")


if __name__ == "__main__":
    main()

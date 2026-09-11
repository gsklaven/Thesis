"""
Δείχνει ΠΟΙΑ συγκεκριμένα πακέτα ήταν False Negatives (γνωστά malicious,
αλλά το σύστημα τα έκρινε BENIGN), μαζί με τα attack_type_tags τους -
για να δεις αν υπάρχει μοτίβο (π.χ. όλα σε 1-2 συγκεκριμένες κατηγορίες).
"""

import glob
import json
import os

RESULTS_DIR = "/home/sklavenitis/thesis/results"
EXPECTED_LABELS_FILE = "/home/sklavenitis/thesis/expected_labels.json"
TAGS_FILE = "/home/sklavenitis/thesis/dataset/attack_type_tags.json"


def main():
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)

    tags = {}
    if os.path.exists(TAGS_FILE):
        with open(TAGS_FILE, "r", encoding="utf-8") as f:
            tags = json.load(f)

    false_negatives = []
    for path in glob.glob(os.path.join(RESULTS_DIR, "report_*.json")):
        pkg = os.path.basename(path)[len("report_"):-len(".json")]
        if expected_labels.get(pkg) != "malicious":
            continue
        with open(path, "r", encoding="utf-8") as f:
            r = json.load(f)
        if r.get("final_verdict") == "BENIGN":
            pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["?"])
            false_negatives.append((pkg, pkg_tags, r.get("total_chains_analyzed")))

    print(f"[*] {len(false_negatives)} False Negatives:\n")
    print(f"{'Πακέτο':35s} {'Attack-type tags':35s} {'#chains'}")
    print("-" * 85)
    for pkg, pkg_tags, n_chains in false_negatives:
        print(f"{pkg:35s} {', '.join(pkg_tags):35s} {n_chains}")

    tag_counts = {}
    for _, pkg_tags, _ in false_negatives:
        for t in pkg_tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1

    print(f"\n[*] Κατανομή attack-type ΜΕΣΑ στα False Negatives:")
    for t, n in sorted(tag_counts.items(), key=lambda x: -x[1]):
        print(f"    {t:28s} {n}")


if __name__ == "__main__":
    main()

"""
Recall per attack-type category, for EVERY results folder (v1 ... v12_*) - shows whether recall is
related to how many training (index) samples each category has (hypothesis: under-represented
categories have lower recall). A package with several tags counts in EVERY category it belongs to.

NO_CHAINS_FOUND packages are excluded (a static-analysis gap, not an LLM reasoning miss) - the same
logic as evaluation_summary.py. Usage: python3 results/confusion_matrix_by_category.py
"""

import json
import os

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
RESULTS_ROOT = os.path.join(_THESIS_ROOT, "results")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")
TAGS_FILE = os.path.join(DATASET_DIR, "attack_type_tags.json")
RAG_TRAIN_DIR = os.path.join(DATASET_DIR, "rag_train")

FEW_SAMPLES_THRESHOLD = 20  # categories with fewer index samples are flagged


def get_training_counts(tags):
    """Number of rag_train packages per attack-type tag."""
    counts = {}
    if not os.path.exists(RAG_TRAIN_DIR):
        return counts
    train_pkgs = {f[:-5] for f in os.listdir(RAG_TRAIN_DIR) if f.endswith(".json")}
    for pkg in train_pkgs:
        pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["unclassified"])
        for t in pkg_tags:
            counts[t] = counts.get(t, 0) + 1
    return counts


def analyze_version(version, expected_labels, tags):
    """{tag: {tp, fn}} over the scored malicious packages of one results folder (None if it does not exist)."""
    results_dir = os.path.join(RESULTS_ROOT, version)
    if not os.path.isdir(results_dir):
        return None

    category_stats = {}

    for fname in os.listdir(results_dir):
        if not (fname.startswith("report_") and fname.endswith(".json")):
            continue
        pkg = fname[len("report_"):-len(".json")]
        if expected_labels.get(pkg) != "malicious":
            continue
        try:
            with open(os.path.join(results_dir, fname), "r", encoding="utf-8") as f:
                r = json.load(f)
        except Exception:
            continue
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "INCOMPLETE", "UNKNOWN", None, "NO_CHAINS_FOUND"):
            continue

        flagged = verdict in ("MALICIOUS", "SUSPICIOUS")
        pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["unclassified"])
        for t in pkg_tags:
            category_stats.setdefault(t, {"tp": 0, "fn": 0})
            if flagged:
                category_stats[t]["tp"] += 1
            else:
                category_stats[t]["fn"] += 1

    return category_stats


def main():
    """Print the per-category recall table of every results folder."""
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)
    with open(TAGS_FILE, "r", encoding="utf-8") as f:
        tags = json.load(f)

    training_counts = get_training_counts(tags)

    if not os.path.isdir(RESULTS_ROOT):
        print(f"[!] Not found: {RESULTS_ROOT}")
        return

    # only the version folders (v1, v11, v12_sum, ...), not evaluation_summaries/ test_set_summaries/ __pycache__/
    versions = sorted(d for d in os.listdir(RESULTS_ROOT)
                      if os.path.isdir(os.path.join(RESULTS_ROOT, d)) and d.startswith("v"))
    print(f"[*] Versions found: {versions}\n")

    for version in versions:
        stats = analyze_version(version, expected_labels, tags)
        if not stats:
            continue

        print(f"\n{'=' * 78}")
        print(f"=== {version} ===")
        print(f"{'=' * 78}")
        print(f"{'Category':28s} {'Train N':9s} {'TP':6s} {'FN':6s} {'Recall':8s}")
        print("-" * 70)

        for cat in sorted(stats.keys(), key=lambda c: -(stats[c]['tp'] + stats[c]['fn'])):
            tp, fn = stats[cat]["tp"], stats[cat]["fn"]
            total = tp + fn
            recall = tp / total if total else 0.0
            train_n = training_counts.get(cat, 0)
            flag = "  ⚠️ few training samples" if train_n < FEW_SAMPLES_THRESHOLD else ""
            print(f"{cat:28s} {train_n:<9d} {tp:<6d} {fn:<6d} {recall:.3f}{flag}")


if __name__ == "__main__":
    main()

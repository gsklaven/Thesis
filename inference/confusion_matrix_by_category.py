"""
Confusion matrix ανά attack-type κατηγορία, για ΚΑΘΕ prompt version που
έχεις reports - δείχνει αν το recall συσχετίζεται με το πόσα training
samples έχει η κάθε κατηγορία (υπόθεση: υποεκπροσωπημένες κατηγορίες
έχουν χειρότερο recall). Ένα πακέτο με πολλαπλά tags συνεισφέρει σε ΚΑΘΕ
κατηγορία που ανήκει.

Εξαιρεί NO_CHAINS_FOUND (static-analysis gap, όχι LLM reasoning miss) -
ίδια λογική με το evaluation_summary.py.
"""

import json
import os

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/Users/giorgos/Documents/Thesis")
DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
RESULTS_ROOT = os.path.join(_THESIS_ROOT, "results")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")
TAGS_FILE = os.path.join(DATASET_DIR, "attack_type_tags.json")
RAG_TRAIN_DIR = os.path.join(DATASET_DIR, "rag_train")

FEW_SAMPLES_THRESHOLD = 20


def get_training_counts(tags):
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
        if verdict in ("EVALUATION_FAILED", "UNKNOWN", None, "NO_CHAINS_FOUND"):
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
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)
    with open(TAGS_FILE, "r", encoding="utf-8") as f:
        tags = json.load(f)

    training_counts = get_training_counts(tags)

    if not os.path.isdir(RESULTS_ROOT):
        print(f"[!] Δεν βρέθηκε: {RESULTS_ROOT}")
        return

    versions = sorted(d for d in os.listdir(RESULTS_ROOT) if os.path.isdir(os.path.join(RESULTS_ROOT, d)))
    print(f"[*] Βρέθηκαν versions: {versions}\n")

    for version in versions:
        stats = analyze_version(version, expected_labels, tags)
        if not stats:
            continue

        print(f"\n{'=' * 78}")
        print(f"=== {version} ===")
        print(f"{'=' * 78}")
        print(f"{'Κατηγορία':28s} {'Train N':9s} {'TP':6s} {'FN':6s} {'Recall':8s}")
        print("-" * 70)

        for cat in sorted(stats.keys(), key=lambda c: -(stats[c]['tp'] + stats[c]['fn'])):
            tp, fn = stats[cat]["tp"], stats[cat]["fn"]
            total = tp + fn
            recall = tp / total if total else 0.0
            train_n = training_counts.get(cat, 0)
            flag = "  ⚠️ λίγα training δείγματα" if train_n < FEW_SAMPLES_THRESHOLD else ""
            print(f"{cat:28s} {train_n:<9d} {tp:<6d} {fn:<6d} {recall:.3f}{flag}")


if __name__ == "__main__":
    main()

"""
Διερευνά ΓΙΑΤΙ τα "tagged" (όχι unclassified) malicious πακέτα με
NO_CHAINS_FOUND κατέληξαν έτσι - υπόθεση: λάθος/ημιτελής αντιστοίχιση
πηγαίου κώδικα στο extract_samples.py ("first-match-wins" directory
matching), όχι πραγματική απουσία ευαίσθητης συμπεριφοράς.

Για κάθε τέτοιο πακέτο ελέγχει:
  - Υπάρχει πραγματικά ο φάκελος source_code_path;
  - Πόσα αρχεία περιέχει συνολικά, πόσα είναι πραγματικά .py/.js;
  - Μέγεθος σε KB.

Ταξινομεί σε 4 κατηγορίες αιτίας, ώστε να ξέρουμε ΠΟΥ να ψάξουμε παρακάτω.
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

_DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
_DEDUPED_JSON = os.path.join(_DATASET_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(_DATASET_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON


def count_code_files(path):
    total_files = 0
    code_files = 0
    total_size = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__', '.venv', 'venv')]
        for fname in files:
            total_files += 1
            fpath = os.path.join(root, fname)
            try:
                total_size += os.path.getsize(fpath)
            except OSError:
                pass
            if fname.endswith(('.py', '.js', '.ts', '.mjs', '.cjs')):
                code_files += 1
    return total_files, code_files, total_size


def main():
    with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
        expected_labels = json.load(f)
    with open(TAGS_FILE, "r", encoding="utf-8") as f:
        tags = json.load(f)

    print(f"[*] Φόρτωση {os.path.basename(DATASET_JSON)}...")
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    path_by_pkg = {item["package_name"]: item.get("source_code_path") for item in dataset}

    suspects = []
    for fname in os.listdir(RESULTS_DIR):
        if not (fname.startswith("report_") and fname.endswith(".json")):
            continue
        pkg = fname[len("report_"):-len(".json")]
        if expected_labels.get(pkg) != "malicious":
            continue

        pkg_tags = tags.get(pkg, {}).get("attack_type_tags", ["unclassified"])
        if pkg_tags == ["unclassified"]:
            continue  # μόνο "tagged" μας ενδιαφέρει εδώ

        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            r = json.load(f)
        if r.get("final_verdict") != "NO_CHAINS_FOUND":
            continue

        suspects.append(pkg)

    print(f"[*] {len(suspects)} 'tagged' πακέτα με NO_CHAINS_FOUND βρέθηκαν.\n")

    reasons = {"path_missing_or_unrecorded": 0, "empty_dir": 0, "no_code_files": 0, "has_code_but_0_chains": 0}

    print(f"{'Πακέτο':35s} {'Κατάσταση':30s} {'#αρχεία':10s} {'#code':8s} {'Μέγεθος'}")
    print("-" * 100)
    for pkg in suspects:
        path = path_by_pkg.get(pkg)
        if not path:
            print(f"{pkg:35s} {'ΔΕΝ βρέθηκε στο dataset json':30s}")
            reasons["path_missing_or_unrecorded"] += 1
            continue
        if not os.path.exists(path):
            print(f"{pkg:35s} {'Path καταγεγραμμένο αλλά ΔΕΝ υπάρχει':30s}")
            reasons["path_missing_or_unrecorded"] += 1
            continue

        total_files, code_files, total_size = count_code_files(path)
        size_str = f"{total_size/1024:.1f}KB"

        if total_files == 0:
            status = "ΚΕΝΟΣ φάκελος"
            reasons["empty_dir"] += 1
        elif code_files == 0:
            status = "Έχει αρχεία, ΚΑΜΙΑ .py/.js"
            reasons["no_code_files"] += 1
        else:
            status = "Έχει πραγματικό κώδικα"
            reasons["has_code_but_0_chains"] += 1

        print(f"{pkg:35s} {status:30s} {total_files:<10d} {code_files:<8d} {size_str}")

    print(f"\n[+] Σύνοψη αιτιών ({len(suspects)} σύνολο):")
    print(f"    Path λείπει/δεν καταγράφηκε:      {reasons['path_missing_or_unrecorded']}")
    print(f"    Φάκελος υπάρχει αλλά κενός:       {reasons['empty_dir']}")
    print(f"    Έχει αρχεία, καμία .py/.js:       {reasons['no_code_files']}")
    print(f"    Έχει πραγματικό κώδικα, 0 chains: {reasons['has_code_but_0_chains']}  <- χρειάζεται παραπάνω έλεγχο αν είναι μεγάλο ποσοστό")


if __name__ == "__main__":
    main()

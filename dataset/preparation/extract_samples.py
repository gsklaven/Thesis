import os
import json
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils import find_target_dir, CANDIDATE_SOURCES_DIRS

BASE_DIR = "/home/sklavenitis/thesis/dataset"
DATASET_JSON = os.path.join(BASE_DIR, "malware_dataset_all_sources.json")
MATCHED_OUTPUT = os.path.join(BASE_DIR, "malware_dataset_matched.json")
UNMATCHED_OUTPUT = os.path.join(BASE_DIR, "malware_dataset_unmatched.json")

# Ίδιο dual-name fallback με το collect_all_samples.py
DATADOG_FOLDER_CANDIDATES = ["malicious-software-packages-dataset", "datadog-malware"]


def resolve_output_dir():
    """Προτιμά έναν ΗΔΗ υπάρχοντα φάκελο malware_samples/ (όπου κι αν ζει),
    ώστε να ΜΗ φτιάχνουμε δεύτερο, ξεχωριστό αντίγραφο σε άλλο δίσκο απλά
    επειδή αυτός συνέβη να είναι πρώτος στη λίστα candidates."""
    existing = find_target_dir("malware_samples")
    if existing:
        return existing
    for base in CANDIDATE_SOURCES_DIRS:
        if os.path.exists(base):
            return os.path.join(base, "malware_samples")
    return os.path.join(BASE_DIR, "malware_samples")


OUTPUT_DIR = resolve_output_dir()


def extract_samples():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(DATASET_JSON, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    already_matched = [item for item in dataset if item.get("source_code_path")]
    to_match = [item for item in dataset if not item.get("source_code_path")]

    print(f"[*] {len(already_matched)} πακέτα έχουν ήδη source_code_path (από collect_all_samples.py).")
    print(f"[*] {len(to_match)} OSV entries χρειάζονται αντιστοίχηση με τον κώδικα στο disk.")

    print("[*] Ευρετηρίαση ΟΛΩΝ των φακέλων κώδικα για αντιστοίχηση...")

    SOURCE_DIRECTORIES = []
    for folder_name in ["pypi_malregistry", "maloss-samples", "pypi", "npm"] + DATADOG_FOLDER_CANDIDATES:
        target = find_target_dir(folder_name)
        if target:
            SOURCE_DIRECTORIES.append(target)

    datadog_extract = os.path.join(BASE_DIR, "malware_samples_datadog")
    if os.path.exists(datadog_extract):
        SOURCE_DIRECTORIES.append(datadog_extract)

    registry_dirs = {}
    for src_dir in SOURCE_DIRECTORIES:
        for root, dirs, files in os.walk(src_dir):
            path_parts = root.split(os.sep)
            if ".git" in path_parts or "node_modules" in path_parts:
                continue
            for d in dirs:
                if d.lower() not in registry_dirs:
                    registry_dirs[d.lower()] = os.path.join(root, d)

    found_count = 0
    missing_count = 0
    final_dataset = list(already_matched)
    unmatched_dataset = []

    print("[*] Αντιστοίχιση των OSV reports με τον πηγαίο κώδικα...")
    for item in to_match:
        pkg_name = item.get("package_name")
        matched_path = registry_dirs.get(pkg_name.lower())

        if matched_path:
            target_dest = os.path.join(OUTPUT_DIR, pkg_name)
            if not os.path.exists(target_dest):
                try:
                    shutil.copytree(matched_path, target_dest)
                except Exception as e:
                    unmatched_dataset.append({**item, "reason": f"copy_error: {e}"})
                    missing_count += 1
                    continue

            new_item = dict(item)
            new_item["source_code_path"] = target_dest
            final_dataset.append(new_item)
            found_count += 1
        else:
            unmatched_dataset.append({**item, "reason": "no_match_in_registry"})
            missing_count += 1

    with open(MATCHED_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(final_dataset, f, indent=4, ensure_ascii=False)

    with open(UNMATCHED_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(unmatched_dataset, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Η διαδικασία ολοκληρώθηκε!")
    print(f"[+] Pass-through (ήδη αντιστοιχισμένα): {len(already_matched)} πακέτα.")
    print(f"[+] Βρέθηκε κώδικας για {found_count} OSV πακέτα (Αντιγράφηκαν στο {OUTPUT_DIR}).")
    print(f"[-] Δεν βρέθηκε κώδικας για {missing_count} πακέτα.")
    print(f"[*] Σύνολο έτοιμων για CodeQL: {len(final_dataset)} πακέτα -> {MATCHED_OUTPUT}")

if __name__ == "__main__":
    extract_samples()

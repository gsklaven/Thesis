"""
Match every dataset entry with its source code on disk: dataset/malware_dataset_matched.json.

Entries that already have a source_code_path (from collect_all_samples.py) pass through unchanged.
Entries without one (OSV reports) are matched by package name against every folder of the source
repositories; the matched code is copied into a single malware_samples/ folder under the sources
location. Entries without any match go to dataset/malware_dataset_unmatched.json with a reason.
"""
import os
import json
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils import find_target_dir, CANDIDATE_SOURCES_DIRS

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
DATASET_JSON = os.path.join(BASE_DIR, "malware_dataset_all_sources.json")
MATCHED_OUTPUT = os.path.join(BASE_DIR, "malware_dataset_matched.json")
UNMATCHED_OUTPUT = os.path.join(BASE_DIR, "malware_dataset_unmatched.json")

# Folder name(s) of the Datadog dataset (same fallback idea as in collect_all_samples.py)
DATADOG_FOLDER_CANDIDATES = ["malicious-software-packages-dataset"]


def resolve_output_dir():
    """
    Prefer an EXISTING malware_samples/ folder (wherever it lives), so that a second, separate copy
    is not created on another disk just because that disk happens to come first in the candidates.
    Otherwise use the first existing sources location, and as a last resort the dataset folder.
    """
    existing = find_target_dir("malware_samples")
    if existing:
        return existing
    for base in CANDIDATE_SOURCES_DIRS:
        if os.path.exists(base):
            return os.path.join(base, "malware_samples")
    return os.path.join(BASE_DIR, "malware_samples")


OUTPUT_DIR = resolve_output_dir()


def extract_samples():
    """Match entries to code by name, copy matched code to OUTPUT_DIR, write matched / unmatched lists."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(DATASET_JSON, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    already_matched = [item for item in dataset if item.get("source_code_path")]
    to_match = [item for item in dataset if not item.get("source_code_path")]

    print(f"[*] {len(already_matched)} packages already have a source_code_path (from collect_all_samples.py).")
    print(f"[*] {len(to_match)} OSV entries need to be matched with code on disk.")

    print("[*] Indexing ALL code folders for matching...")

    SOURCE_DIRECTORIES = []
    for folder_name in ["pypi_malregistry", "maloss-samples", "pypi", "npm"] + DATADOG_FOLDER_CANDIDATES:
        target = find_target_dir(folder_name)
        if target:
            SOURCE_DIRECTORIES.append(target)

    datadog_extract = os.path.join(BASE_DIR, "malicious-software-packages-dataset")
    if os.path.exists(datadog_extract):
        SOURCE_DIRECTORIES.append(datadog_extract)

    # lower-cased folder name -> first path where a folder with that name occurs
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

    print("[*] Matching the OSV reports with source code...")
    for item in to_match:
        pkg_name = item.get("package_name")
        matched_path = registry_dirs.get(pkg_name.lower())

        if matched_path:
            # copy once; an existing copy is reused
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

    print(f"\n[✓] Done!")
    print(f"[+] Pass-through (already matched): {len(already_matched)} packages.")
    print(f"[+] Code found for {found_count} OSV packages (copied to {OUTPUT_DIR}).")
    print(f"[-] No code found for {missing_count} packages.")
    print(f"[*] Total ready for CodeQL: {len(final_dataset)} packages -> {MATCHED_OUTPUT}")

if __name__ == "__main__":
    extract_samples()

"""
Ενοποιεί όλες τις πηγές του sources/ σε ένα ενιαίο malware_dataset_all_sources.json,
στην ΙΔΙΑ μορφή που καταναλώνει το batch_analyzer.py.
"""

import json
import os
import random
import re
import zipfile
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils import find_target_dir

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
EXISTING_COMBINED = os.path.join(BASE_DIR, "malware_dataset.json")
OUTPUT_JSON = os.path.join(BASE_DIR, "malware_dataset_all_sources.json")

DATADOG_EXTRACT_DIR = os.path.join(BASE_DIR, "malware_samples_datadog")
DATADOG_ZIP_PASSWORD = b"infected"
DATADOG_FILENAME_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})-(?P<pkg>.+)-v(?P<version>[^-]+)\.zip$"
)

# ΤΟ Datadog repo μπορεί να έχει clone-αριστεί με το πραγματικό upstream
# όνομα ("malicious-software-packages-dataset") Η με ένα custom όνομα
# ("datadog-malware", όπως έδειχναν οι αρχικές οδηγίες clone). Δοκιμάζουμε
# ΚΑΙ ΤΑ ΔΥΟ, ώστε να δουλέψει όποιο έχεις πραγματικά στο δίσκο.
DATADOG_FOLDER_CANDIDATES = ["malicious-software-packages-dataset", "datadog-malware"]

MALOSS_RELEVANT_SUBDIRS = [
    "npmjs-samples", "pypi-samples", "python-samples",
    "high-impact-samples", "github-samples",
]

MAX_PER_BULK_SOURCE = 1000000
RANDOM_SEED = 42

def walk_top_level_packages(root, source_label, skip_names=None):
    entries = []
    if not os.path.exists(root):
        print(f"  [!] Δεν βρέθηκε: {root}")
        return entries

    skip_names = skip_names or set()
    all_names = [
        name for name in sorted(os.listdir(root))
        if name not in skip_names and not name.startswith(".")
        and os.path.isdir(os.path.join(root, name))
    ]

    if len(all_names) > MAX_PER_BULK_SOURCE:
        all_names = random.Random(RANDOM_SEED).sample(all_names, MAX_PER_BULK_SOURCE)
        print(f"  [*] {source_label}: {len(os.listdir(root))} διαθέσιμα -> τυχαίο δείγμα {MAX_PER_BULK_SOURCE}")

    for name in all_names:
        full = os.path.join(root, name)
        entries.append({
            "package_name": name,
            "summary": f"Malware sample from {source_label}",
            "description": "",
            "source_code_path": full,
            "source_origin": source_label,
        })
    return entries

def collect_pypi_malregistry():
    root = find_target_dir("pypi_malregistry")
    if not root:
        return []
    return walk_top_level_packages(root, "pypi_malregistry")

def collect_malwarebench_pypi():
    base = find_target_dir("pypi")
    if not base:
        return []
    root = os.path.join(base, "packages")
    return walk_top_level_packages(root, "pypi")

def collect_malwarebench_npm():
    base = find_target_dir("npm")
    if not base:
        return []

    root = os.path.join(base, "packages")
    entries = walk_top_level_packages(root, "npm")

    csv_path = os.path.join(base, "npm_package_info.csv")
    if os.path.exists(csv_path):
        try:
            import csv
            info_by_name = {}
            with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    pkg = row.get("package_name") or row.get("name") or row.get("package")
                    if pkg:
                        info_by_name[pkg.lower()] = row
            for e in entries:
                info = info_by_name.get(e["package_name"].lower())
                if info:
                    e["description"] = f"Source: npm. Metadata: {dict(info)}"
        except Exception as ex:
            print(f"  [!] Δεν μπόρεσα να διαβάσω το npm_package_info.csv: {ex}")

    return entries

def collect_maloss_samples():
    base = find_target_dir("maloss-samples")
    entries = []
    if not base:
        return entries

    for subdir in MALOSS_RELEVANT_SUBDIRS:
        root = os.path.join(base, subdir)
        entries.extend(walk_top_level_packages(root, f"maloss_{subdir}"))
    return entries

def _find_datadog_base():
    """Δοκιμάζει και τα δύο πιθανά ονόματα φακέλου - βλ. σχόλιο πάνω."""
    for name in DATADOG_FOLDER_CANDIDATES:
        base = find_target_dir(name)
        if base:
            return base
    return None

def collect_datadog_ecosystem(ecosystem):
    """Γενική συνάρτηση για Datadog, μπορεί να τραβήξει pypi ή npm."""
    base = _find_datadog_base()
    entries = []
    if not base:
        print(f"  [!] Δεν βρέθηκε κανένας από τους φακέλους: {DATADOG_FOLDER_CANDIDATES}")
        return entries

    root = os.path.join(base, "samples", ecosystem)
    if not os.path.exists(root):
        print(f"  [!] Δεν βρέθηκε: {root}")
        return entries

    zips = [f for f in os.listdir(root) if f.endswith(".zip")]
    for fname in sorted(zips):
        m = DATADOG_FILENAME_PATTERN.match(fname)
        if not m:
            continue
        pkg_name, version, date = m.group("pkg"), m.group("version"), m.group("date")
        zip_path = os.path.join(root, fname)
        dest_dir = os.path.join(DATADOG_EXTRACT_DIR, f"{pkg_name}-{version}")

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(zip_path, "r") as z:
                    dest_real = os.path.realpath(dest_dir)
                    for info in z.infolist():
                        target = os.path.join(dest_dir, info.filename)
                        if not os.path.realpath(target).startswith(dest_real):
                            print(f"  [!] BLOCKED path traversal: {info.filename}")
                            continue
                        if info.file_size > 100 * 1024 * 1024:
                            print(f"  [!] BLOCKED oversized: {info.filename}")
                            continue
                        z.extract(info, path=dest_dir, pwd=DATADOG_ZIP_PASSWORD)
            except Exception as e:
                print(f"  [!] Αδυναμία εξαγωγής {fname}: {e}")
                continue

        entries.append({
            "package_name": pkg_name,
            "summary": f"Malicious {ecosystem} package identified by Datadog GuardDog",
            "description": f"Source: datadog. Version: {version}. Discovery date: {date}.",
            "source_code_path": dest_dir,
            "source_origin": f"datadog_{ecosystem}",
        })
    return entries

def collect_datadog_pypi():
    return collect_datadog_ecosystem("pypi")

def collect_datadog_npm():
    return collect_datadog_ecosystem("npm")

def main():
    existing = []
    if os.path.exists(EXISTING_COMBINED):
        with open(EXISTING_COMBINED, "r", encoding="utf-8") as f:
            existing = json.load(f)
        print(f"[*] {len(existing)} πακέτα ήδη στο {EXISTING_COMBINED} (κρατούν προτεραιότητα).")

    known_names = {item.get("package_name", "").lower() for item in existing}
    combined = list(existing)

    collectors = [
        ("pypi_malregistry", collect_pypi_malregistry),
        ("pypi_malwarebench", collect_malwarebench_pypi),
        ("npm_malwarebench", collect_malwarebench_npm),
        ("maloss_samples", collect_maloss_samples),
        ("datadog_pypi", collect_datadog_pypi),
        ("datadog_npm", collect_datadog_npm),
    ]

    stats = {}
    for label, fn in collectors:
        print(f"\n[*] Συλλογή από: {label}")
        new_entries = fn()
        added = 0
        for e in new_entries:
            key = e["package_name"].lower()
            if key in known_names:
                continue
            combined.append(e)
            known_names.add(key)
            added += 1
        stats[label] = {"found": len(new_entries), "added": added}
        print(f"    Βρέθηκαν: {len(new_entries)} | Νέα (χωρίς duplicate): {added}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Σύνολο: {len(combined)} πακέτα -> {OUTPUT_JSON}")
    print("\n[+] Σύνοψη ανά πηγή:")
    for label, s in stats.items():
        print(f"    {label:20s} βρέθηκαν={s['found']:6d}  νέα={s['added']:6d}")

if __name__ == "__main__":
    main()

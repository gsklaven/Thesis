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
from utils import SOURCES_DIR, find_target_dir

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
EXISTING_COMBINED = os.path.join(BASE_DIR, "malware_dataset.json")
OUTPUT_JSON = os.path.join(BASE_DIR, "malware_dataset_all_sources.json")

# Αποσυμπίεση των κρυπτογραφημένων zip της Datadog ΣΤΟΝ ΦΑΚΕΛΟ ΠΗΓΩΝ, όχι μέσα στο έργο
DATADOG_EXTRACT_DIR = os.path.join(SOURCES_DIR, "malware_samples_datadog")
DATADOG_ZIP_PASSWORD = b"infected"
DATADOG_FILENAME_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})-(?P<pkg>.+)-v(?P<version>[^-]+)\.zip$"
)

DATADOG_FOLDER_CANDIDATES = ["malicious-software-packages-dataset", "datadog-malware"]

# ΝΕΟ: το upstream repo άλλαξε δομή - δεν είναι πια .zip αρχεία με όνομα
# "date-pkg-version.zip", είναι φάκελοι, χωρισμένοι σε δύο κατηγορίες.
# "compromised_lib" = πραγματικό, νόμιμο πακέτο που παραβιάστηκε (π.χ.
# "mistralai", "ultralytics" - γνωστά, υπαρκτά ονόματα). "malicious_intent"
# = πακέτα σχεδιασμένα εξ αρχής κακόβουλα (typosquats, fake packages, κ.λπ.)
DATADOG_PYPI_SUBCATEGORIES = ["compromised_lib", "malicious_intent"]

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
    for name in DATADOG_FOLDER_CANDIDATES:
        base = find_target_dir(name)
        if base:
            return base
    return None


def _load_datadog_manifest(pypi_root):
    """
    Φορτώνει το manifest.json (αν υπάρχει) - πιθανή πηγή σημασιολογικών
    περιγραφών ανά πακέτο, πολύτιμο δεδομένου ότι τα bulk sources συνήθως
    δεν έχουν καθόλου description (και ξέρουμε από το recall-by-tag
    ανάλυση ότι αυτό συσχετίζεται με χειρότερο recall - p=0.0025).
    Defensive: αν το schema δεν είναι αυτό που περιμένουμε, απλά αγνοείται.
    """
    manifest_path = os.path.join(pypi_root, "manifest.json")
    if not os.path.exists(manifest_path):
        return {}
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [!] Δεν μπόρεσα να διαβάσω το manifest.json: {e}")
        return {}

    # Το manifest μπορεί να είναι είτε dict {pkg_name: {...}} είτε list [{...}]
    by_name = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                by_name[k.lower()] = v
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                name = item.get("name") or item.get("package") or item.get("package_name")
                if name:
                    by_name[name.lower()] = item
    return by_name


def collect_datadog_pypi_v2():
    """
    ΝΕΟ collector για τη ΝΕΑ δομή του upstream repo: φάκελοι (όχι zips),
    χωρισμένοι σε samples/pypi/compromised_lib/ και samples/pypi/malicious_intent/.
    """
    base = _find_datadog_base()
    if not base:
        return []

    pypi_root = os.path.join(base, "samples", "pypi")
    if not os.path.isdir(pypi_root):
        return []

    manifest = _load_datadog_manifest(pypi_root)
    if manifest:
        print(f"  [✓] manifest.json: {len(manifest)} εγγραφές φορτώθηκαν.")

    entries = []
    for subcat in DATADOG_PYPI_SUBCATEGORIES:
        subcat_root = os.path.join(pypi_root, subcat)
        if not os.path.isdir(subcat_root):
            continue

        sub_entries = walk_top_level_packages(subcat_root, f"datadog_pypi_{subcat}")

        for e in sub_entries:
            pkg_lower = e["package_name"].lower()
            manifest_info = manifest.get(pkg_lower, {})
            manifest_desc = (
                manifest_info.get("description") or manifest_info.get("summary")
                or manifest_info.get("details") or ""
            )
            # ΔΙΟΡΘΩΣΗ: το subcategory ΔΕΝ μπαίνει πια μέσα στο "description".
            # Πριν, ΚΑΘΕ πακέτο μιας κατηγορίας έπαιρνε το ΙΔΙΟ, πανομοιότυπο
            # κείμενο (αφού το manifest.json είναι όλο null) - το
            # campaign_signature() στο utils.py χασάρει το description, οπότε
            # 135 άσχετα πακέτα με το ΙΔΙΟ σταθερό string κατέληγαν να
            # μοιράζονται ΤΟ ΙΔΙΟ campaign signature, δημιουργώντας μια
            # ψεύτικη "μεγα-καμπάνια" 135 πακέτων.
            e["description"] = manifest_desc
            e["datadog_category"] = subcat

        entries.extend(sub_entries)

    return entries


def collect_datadog_ecosystem(ecosystem):
    """
    Γενική συνάρτηση για Datadog. Δοκιμάζει ΠΡΩΤΑ τη ΝΕΑ δομή (φάκελοι
    compromised_lib/malicious_intent) - αν δεν βρεθεί (π.χ. ίσως το npm
    διατηρεί ακόμα την παλιά μορφή), κάνει fallback στην ΠΑΛΙΑ λογική
    (.zip αρχεία με όνομα date-pkg-version.zip).
    """
    if ecosystem == "pypi":
        new_style = collect_datadog_pypi_v2()
        if new_style:
            return new_style
        print("  [*] Νέα δομή (compromised_lib/malicious_intent) δεν βρέθηκε για pypi - δοκιμή παλιάς μορφής (.zip)...")

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
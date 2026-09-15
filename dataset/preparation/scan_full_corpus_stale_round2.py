"""
Δεύτερο πέρασμα, ΧΑΛΑΡΩΜΕΝΟ κριτήριο: σημειώνει σαν "μπαγιάτικο" αν υπάρχει
ΤΟΥΛΑΧΙΣΤΟΝ ένα αρχείο συμπίεσης ΚΑΙ μηδέν αρχεία κώδικα - ανεξάρτητα από
άλλα metadata αρχεία που μπορεί να συνυπάρχουν (PKG-INFO, README, κ.λπ.).
Το πρώτο πέρασμα (scan_full_corpus_stale.py) απαιτούσε ΟΛΑ τα αρχεία να
είναι αποκλειστικά archives - πολύ αυστηρό, χωρίς εξαιρέσεις για metadata.
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")

_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar", ".zip", ".whl")
MAX_FILE_SIZE_MB = 2


def has_archive_but_no_code(path):
    if not path or not os.path.exists(path):
        return False
    has_archive = False
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__', '.venv', 'venv')]
        for fname in files:
            lower = fname.lower()
            if lower.endswith(('.py', '.js', '.ts', '.mjs', '.cjs')):
                return False  # πραγματικός κώδικας βρέθηκε - ΔΕΝ είναι αυτό το πρόβλημα
            if lower.endswith(ARCHIVE_EXTENSIONS):
                has_archive = True
    return has_archive


def main():
    print(f"[*] Φόρτωση {os.path.basename(DATASET_JSON)}...")
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    path_by_pkg = {item["package_name"]: item.get("source_code_path") for item in dataset}

    zero_chain_packages = []
    all_files = [f for f in os.listdir(ANALYZED_CHAINS_DIR) if f.endswith(".json") and not f.startswith("_error_")]
    print(f"[*] {len(all_files)} συνολικά analyzed_chains αρχεία προς έλεγχο...")

    for i, fname in enumerate(all_files):
        if (i + 1) % 2000 == 0:
            print(f"    [{i+1}/{len(all_files)}]...")
        pkg = fname[:-5]
        fpath = os.path.join(ANALYZED_CHAINS_DIR, fname)
        try:
            if os.path.getsize(fpath) > MAX_FILE_SIZE_MB * 1024 * 1024:
                continue
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if data.get("summary", {}).get("total_behavior_chains", -1) == 0:
            zero_chain_packages.append(pkg)

    print(f"\n[*] {len(zero_chain_packages)} πακέτα με 0 chains σε ΟΛΟ το corpus (τώρα).")

    confirmed_stale = []
    for pkg in zero_chain_packages:
        path = path_by_pkg.get(pkg)
        if has_archive_but_no_code(path):
            confirmed_stale.append(pkg)

    print(f"[✓] {len(confirmed_stale)} πακέτα με ΧΑΛΑΡΩΜΕΝΟ κριτήριο (έχουν archive + 0 κώδικα).")

    out_path = os.path.join(BASE_DIR, "confirmed_stale_packages_round2.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(confirmed_stale, f, indent=2, ensure_ascii=False)
    print(f"[✓] Λίστα -> {out_path}")


if __name__ == "__main__":
    main()

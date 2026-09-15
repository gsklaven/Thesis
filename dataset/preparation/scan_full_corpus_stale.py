"""
Σαρώνει ΟΛΟΚΛΗΡΟ το analyzed_chains/ (όχι μόνο rag_test/) για πακέτα με
total_behavior_chains==0 όπου το source_code_path περιέχει ΑΠΟΚΛΕΙΣΤΙΚΑ
ασυμπίεστα αρχεία (.tar.gz/.whl/.zip) - το ίδιο επιβεβαιωμένο μοτίβο
"μπαγιάτικο αποτέλεσμα από παλιά extraction issue" που βρήκαμε στο
eth-security-auditor (0 -> 2 chains μετά από σωστή αποσυμπίεση).

Συντηρητικός κανόνας: σημειώνεται ως "επιβεβαιωμένο μπαγιάτικο" ΜΟΝΟ αν
ΟΛΑ τα αρχεία μέσα (αναδρομικά) είναι γνωστές επεκτάσεις archive και ΚΑΝΕΝΑ
δεν είναι .py/.js. Οτιδήποτε αλλιώς πάει σε ξεχωριστό "other_zero" bucket,
για χειροκίνητο έλεγχο αντί για αυτόματο reset.
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")

_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar", ".zip", ".whl")
MAX_FILE_SIZE_MB = 2  # ίδιο size guard με το build_final_dataset.py


def looks_like_unextracted_archive(path):
    if not path or not os.path.exists(path):
        return False
    found_any_file = False
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__', '.venv', 'venv')]
        for fname in files:
            found_any_file = True
            lower = fname.lower()
            if lower.endswith(('.py', '.js', '.ts', '.mjs', '.cjs')):
                return False  # πραγματικός κώδικας βρέθηκε ήδη - ΔΕΝ είναι αυτό το πρόβλημα
            if not lower.endswith(ARCHIVE_EXTENSIONS):
                return False  # κάτι άλλο - πιθανό διαφορετικό αίτιο, μην αγγίξεις αυτόματα
    return found_any_file


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
                continue  # τερατάκια, ούτως ή άλλως εξαιρούνται από το τελικό dataset
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if data.get("summary", {}).get("total_behavior_chains", -1) == 0:
            zero_chain_packages.append(pkg)

    print(f"\n[*] {len(zero_chain_packages)} πακέτα με 0 behavior chains σε ΟΛΟ το corpus.")

    confirmed_stale = []
    other_zero = []
    no_path_info = []

    for pkg in zero_chain_packages:
        path = path_by_pkg.get(pkg)
        if not path:
            no_path_info.append(pkg)
            continue
        if looks_like_unextracted_archive(path):
            confirmed_stale.append(pkg)
        else:
            other_zero.append(pkg)

    print(f"\n[✓] Επιβεβαιωμένα μπαγιάτικα (μόνο ασυμπίεστα archives): {len(confirmed_stale)}")
    print(f"[?] 0 chains για ΑΛΛΟ λόγο (πραγματικός κώδικας/κ.λπ.):    {len(other_zero)}")
    print(f"[!] Δεν βρέθηκε source_code_path στο dataset json:         {len(no_path_info)}")

    out_path = os.path.join(BASE_DIR, "confirmed_stale_packages.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(confirmed_stale, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Λίστα προς επαναφορά -> {out_path}")


if __name__ == "__main__":
    main()

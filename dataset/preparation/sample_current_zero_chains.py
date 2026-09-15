"""
Δείχνει ένα δείγμα πακέτων που ΤΩΡΑ (μετά το batch_analyzer run) έχουν
0 chains, μαζί με το αν ο φάκελός τους δείχνει ΑΚΟΜΑ το "μόνο ασυμπίεστο
αρχείο" pattern (σημάδι ότι το fix ΔΕΝ έπιασε αυτή την περίπτωση) ή αν
έχει πραγματικό κώδικα (πιθανό γνήσιο "καμία ευαίσθητη συμπεριφορά").
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")

_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

SAMPLE_SIZE = 15
ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar", ".zip", ".whl")


def describe_folder(path):
    if not path or not os.path.exists(path):
        return "path λείπει/δεν υπάρχει", 0, 0
    total_files = code_files = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            total_files += 1
            if f.endswith((".py", ".js", ".ts")):
                code_files += 1
            elif f.endswith(ARCHIVE_EXTENSIONS):
                pass
    return None, total_files, code_files


def main():
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    path_by_pkg = {item["package_name"]: item.get("source_code_path") for item in dataset}

    zero_chain = []
    for fname in os.listdir(ANALYZED_CHAINS_DIR):
        if not fname.endswith(".json") or fname.startswith("_error_"):
            continue
        pkg = fname[:-5]
        fpath = os.path.join(ANALYZED_CHAINS_DIR, fname)
        try:
            if os.path.getsize(fpath) > 2 * 1024 * 1024:
                continue
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if data.get("summary", {}).get("total_behavior_chains", -1) == 0:
            zero_chain.append(pkg)

    print(f"[*] {len(zero_chain)} πακέτα ΤΩΡΑ με 0 chains σε όλο το corpus.\n")

    import random
    sample = random.Random(42).sample(zero_chain, min(SAMPLE_SIZE, len(zero_chain)))

    print(f"{'Πακέτο':35s} {'#αρχεία':10s} {'#code':8s} {'Κατάσταση'}")
    print("-" * 90)
    for pkg in sample:
        path = path_by_pkg.get(pkg)
        err, total_files, code_files = describe_folder(path)
        if err:
            status = err
        elif total_files == 0:
            status = "ΚΕΝΟΣ φάκελος"
        elif code_files == 0:
            status = "ΑΚΟΜΑ μόνο ασυμπίεστα/μη-κώδικα αρχεία - ΠΙΘΑΝΟ FIX ΔΕΝ ΕΠΙΑΣΕ"
        else:
            status = "Έχει πραγματικό κώδικα - πιθανό γνήσιο 'καμία ευαίσθητη συμπεριφορά'"
        print(f"{pkg:35s} {total_files:<10d} {code_files:<8d} {status}")


if __name__ == "__main__":
    main()

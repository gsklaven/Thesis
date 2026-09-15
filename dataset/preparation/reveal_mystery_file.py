"""
Δείχνει το ΑΚΡΙΒΕΣ όνομα αρχείου + τα πρώτα λίγα bytes περιεχομένου, για
μερικά από τα πακέτα που ταιριάστηκαν σε φάκελο με ακριβώς 1, μη-κώδικα
αρχείο - για να δούμε ΤΙ ΑΚΡΙΒΩΣ είναι αυτό το αρχείο.
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
DATASET_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")

SAMPLE_PACKAGES = ["s3ffs", "web3-tool-sdk", "solana-wallet-utils", "eth-security-auditor"]


def main():
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    path_by_pkg = {item["package_name"]: item.get("source_code_path") for item in dataset}

    for pkg in SAMPLE_PACKAGES:
        path = path_by_pkg.get(pkg)
        print(f"\n=== {pkg} ===")
        print(f"source_code_path: {path}")
        if not path or not os.path.exists(path):
            print("  [!] Δεν υπάρχει.")
            continue

        for root, dirs, files in os.walk(path):
            rel = os.path.relpath(root, path)
            print(f"  [φάκελος] {rel}/  (υποφάκελοι: {dirs}, αρχεία: {files})")
            for fname in files:
                fpath = os.path.join(root, fname)
                print(f"\n    --- Περιεχόμενο του '{os.path.join(rel, fname)}' (πρώτοι 500 χαρακτήρες) ---")
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        print("    " + f.read(500).replace("\n", "\n    "))
                except Exception as e:
                    print(f"    [!] Δεν μπόρεσα να το διαβάσω ως κείμενο: {e}")


if __name__ == "__main__":
    main()

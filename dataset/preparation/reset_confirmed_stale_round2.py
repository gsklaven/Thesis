"""
Ίδιο με το reset_confirmed_stale.py, αλλά διαβάζει από τη λίστα του
δεύτερου, χαλαρωμένου περάσματος (confirmed_stale_packages_round2.json).
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")
STALE_LIST_FILE = os.path.join(BASE_DIR, "confirmed_stale_packages_round2.json")

RESULTS_ROOT = "/home/sklavenitis/thesis/results"


def main():
    with open(STALE_LIST_FILE, "r", encoding="utf-8") as f:
        stale_packages = json.load(f)

    print(f"[*] {len(stale_packages)} πακέτα προς πλήρη επαναφορά (round 2).")

    deleted_chains = 0
    deleted_reports = 0

    for pkg in stale_packages:
        chain_path = os.path.join(ANALYZED_CHAINS_DIR, f"{pkg}.json")
        if os.path.exists(chain_path):
            os.remove(chain_path)
            deleted_chains += 1

        if os.path.exists(RESULTS_ROOT):
            for version_dir in os.listdir(RESULTS_ROOT):
                report_path = os.path.join(RESULTS_ROOT, version_dir, f"report_{pkg}.json")
                if os.path.exists(report_path):
                    os.remove(report_path)
                    deleted_reports += 1

    print(f"[✓] {deleted_chains} παλιά analyzed_chains διαγράφηκαν.")
    print(f"[✓] {deleted_reports} παλιά LLM reports διαγράφηκαν.")
    print(f"\nΤρέξε ξανά: python3 batch_analyzer.py")


if __name__ == "__main__":
    main()

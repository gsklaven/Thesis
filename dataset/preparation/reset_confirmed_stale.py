"""
Διαγράφει τα analyzed_chains/<pkg>.json + τυχόν παλιά LLM reports για ΟΛΑ
τα πακέτα του confirmed_stale_packages.json (βλ. scan_full_corpus_stale.py),
ώστε το batch_analyzer.py να τα ξαναδουλέψει από την αρχή, σωστά.
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")
STALE_LIST_FILE = os.path.join(BASE_DIR, "confirmed_stale_packages.json")

RESULTS_ROOT = "/home/sklavenitis/thesis/results"


def main():
    with open(STALE_LIST_FILE, "r", encoding="utf-8") as f:
        stale_packages = json.load(f)

    print(f"[*] {len(stale_packages)} πακέτα προς πλήρη επαναφορά.")

    deleted_chains = 0
    deleted_reports = 0

    for pkg in stale_packages:
        chain_path = os.path.join(ANALYZED_CHAINS_DIR, f"{pkg}.json")
        if os.path.exists(chain_path):
            os.remove(chain_path)
            deleted_chains += 1

        # Σβήσε τυχόν παλιό LLM report σε ΟΠΟΙΟΔΗΠΟΤΕ version folder υπάρχει
        # (π.χ. v1, v3, ...) - όχι μόνο στο τρέχον PROMPT_VERSION, ώστε να
        # μην απομείνει κανένα stale report πουθενά.
        if os.path.exists(RESULTS_ROOT):
            for version_dir in os.listdir(RESULTS_ROOT):
                report_path = os.path.join(RESULTS_ROOT, version_dir, f"report_{pkg}.json")
                if os.path.exists(report_path):
                    os.remove(report_path)
                    deleted_reports += 1

    print(f"[✓] {deleted_chains} παλιά analyzed_chains διαγράφηκαν.")
    print(f"[✓] {deleted_reports} παλιά LLM reports διαγράφηκαν (όλων των versions).")
    print(f"\nΕπόμενα βήματα:")
    print(f"  1. python3 batch_analyzer.py          (ξαναδουλεύει ΜΟΝΟ τα {len(stale_packages)}, skip-logic στα υπόλοιπα)")
    print(f"  2. python3 build_final_dataset.py")
    print(f"  3. python3 split_train_test.py         (ΞΑΝΑΧΤΙΖΕΙ ολόκληρο το rag_test/ - αναμενόμενο)")
    print(f"  4. python3 build_rag_index.py")
    print(f"  5. check_test_set.py σε ΟΛΟΚΛΗΡΟ το νέο rag_test/ + begning_test_set/ (πλήρες evaluation ξανά)")


if __name__ == "__main__":
    main()

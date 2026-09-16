"""
Μετακινεί τα analyzed_chains/*.json πάνω από THRESHOLD_MB στο στικάκι, και
αφήνει ΣΤΗ ΘΕΣΗ ΤΟΥΣ ένα symbolic link προς το νέο μέρος - ελευθερώνει
χώρο στον κύριο δίσκο, ΧΩΡΙΣ να χαθεί τίποτα και ΧΩΡΙΣ να χρειάζεται καμία
αλλαγή σε batch_analyzer.py/build_final_dataset.py: ό,τι κάνει
os.path.exists()/open() σε αυτά τα paths συνεχίζει να δουλεύει κανονικά,
διαφανώς μέσα από το symlink.

ΠΡΩΤΑ dry-run (χωρίς --apply) για επιβεβαίωση, ΜΕΤΑ πραγματική εφαρμογή.
"""

import os
import shutil
import sys

ANALYZED_CHAINS_DIR = "/home/sklavenitis/thesis/dataset/analyzed_chains"
EXTERNAL_DEST_DIR = "/media/sklavenitis/C09F-7FCB/analyzed_chains_large"
THRESHOLD_MB = 2
MAX_FILES = 200
TARGET_FREED_GB = 30


def main():
    apply = "--apply" in sys.argv

    if apply and not os.path.exists(os.path.dirname(EXTERNAL_DEST_DIR.rstrip("/"))):
        print(f"[!] Το στικάκι δεν φαίνεται συνδεδεμένο: {EXTERNAL_DEST_DIR}")
        sys.exit(1)

    if apply:
        os.makedirs(EXTERNAL_DEST_DIR, exist_ok=True)

    # ΝΕΟ: μάζεψε ΠΡΩΤΑ όλους τους υποψήφιους, ταξινόμησε κατά μέγεθος
    # (μεγαλύτερα πρώτα) - μεγιστοποιεί τον ελευθερωμένο χώρο με τα
    # λιγότερα δυνατά αρχεία, σταματώντας μόλις φτάσουμε τον στόχο.
    candidates = []
    already_symlink = 0
    for fname in os.listdir(ANALYZED_CHAINS_DIR):
        if not fname.endswith(".json") or fname.startswith("_"):
            continue
        fpath = os.path.join(ANALYZED_CHAINS_DIR, fname)
        if os.path.islink(fpath):
            already_symlink += 1
            continue
        try:
            size = os.path.getsize(fpath)
        except OSError:
            continue
        if size > THRESHOLD_MB * 1024 * 1024:
            candidates.append((fname, fpath, size))

    candidates.sort(key=lambda x: -x[2])

    total_moved = 0
    count = 0
    target_bytes = TARGET_FREED_GB * 1024 ** 3

    for fname, fpath, size in candidates:
        if count >= MAX_FILES or total_moved >= target_bytes:
            break

        count += 1
        total_moved += size

        if apply:
            dest_path = os.path.join(EXTERNAL_DEST_DIR, fname)
            shutil.move(fpath, dest_path)
            os.symlink(dest_path, fpath)

    action = "Μετακινήθηκαν" if apply else "ΘΑ μετακινούνταν (dry-run, καμία αλλαγή ακόμα)"
    print(f"[*] {len(candidates)} συνολικά υποψήφια πάνω από {THRESHOLD_MB}MB "
          f"({already_symlink} ήδη symlinks, παραλείφθηκαν).")
    print(f"[*] Όριο: {MAX_FILES} αρχεία ή {TARGET_FREED_GB}GB, ό,τι έρθει πρώτο.")
    print(f"[{'✓' if apply else '*'}] {action}: {count} αρχεία, ~{total_moved/1e9:.1f}GB")

    if not apply:
        print(f"\nΓια πραγματική εφαρμογή: python3 {os.path.basename(__file__)} --apply")


if __name__ == "__main__":
    main()

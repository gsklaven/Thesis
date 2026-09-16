"""
Βρίσκει τα μεγαλύτερα analyzed_chains/*.json αρχεία - dry-run report,
ΔΕΝ διαγράφει τίποτα ακόμα. Σκοπός: να δούμε ΤΙ ακριβώς καταναλώνει τα
103GB πριν αποφασίσουμε τι να κάνουμε.
"""

import os

ANALYZED_CHAINS_DIR = "/home/sklavenitis/thesis/dataset/analyzed_chains"
THRESHOLD_MB = 2  # ίδιο όριο με το ιστορικό "2MB size filter"

def main():
    entries = []
    total_size = 0
    total_over_threshold = 0
    count_over_threshold = 0

    for fname in os.listdir(ANALYZED_CHAINS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(ANALYZED_CHAINS_DIR, fname)
        try:
            size = os.path.getsize(fpath)
        except OSError:
            continue
        total_size += size
        if size > THRESHOLD_MB * 1024 * 1024:
            entries.append((fname, size))
            total_over_threshold += size
            count_over_threshold += 1

    entries.sort(key=lambda x: -x[1])

    print(f"[*] Συνολικό μέγεθος analyzed_chains/: {total_size/1e9:.1f}GB")
    print(f"[*] {count_over_threshold} αρχεία πάνω από {THRESHOLD_MB}MB, "
          f"σύνολο {total_over_threshold/1e9:.1f}GB\n")

    print(f"{'Πακέτο':45s} {'Μέγεθος'}")
    print("-" * 60)
    for fname, size in entries[:30]:
        print(f"{fname[:-5]:45s} {size/1e6:.1f}MB")

    if len(entries) > 30:
        remaining_size = sum(s for _, s in entries[30:])
        print(f"\n... και {len(entries)-30} ακόμα, σύνολο {remaining_size/1e9:.1f}GB")

    print(f"\n[*] Αν καθαρίσεις όλα τα >{THRESHOLD_MB}MB: ~{total_over_threshold/1e9:.1f}GB ελεύθερα.")


if __name__ == "__main__":
    main()

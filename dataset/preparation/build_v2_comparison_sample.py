"""
Ετοιμάζει ένα ΜΙΚΡΟ, αντιπροσωπευτικό υποσύνολο του rag_test/ για τη σύγκριση
prompt v1 έναντι v2 - ΧΩΡΙΣ να χρειάζεται να ξανατρέξεις ολόκληρο το test set
(391 πακέτα) κάτω από το νέο prompt, κάτι που θα σπαταλούσε χρόνο/API quota
ξανά χωρίς λόγο.

Περιλαμβάνει:
  1. ΟΛΑ τα false negatives του v1 (να δεις αν το νέο prompt τα διορθώνει)
  2. Ένα ΤΥΧΑΙΟ δείγμα από τα ήδη-σωστά του v1 (να δεις αν "χάλασαν" - αν το
     νέο prompt απλά έγινε πιο επιθετικό, θα φανεί ΕΔΩ, όχι μόνο στα FN)

Το αποτέλεσμα μπαίνει σε ένα ΝΕΟ, μικρό φάκελο - δεν πειράζει καθόλου το
αρχικό rag_test/. Μετά την αλλαγή σε PROMPT_VERSION="v2" στο query_rag.py,
τρέξε:
    python3 check_test_set.py /home/sklavenitis/thesis/dataset/rag_test_v2_sample
    python3 check_test_set.py /home/sklavenitis/thesis/test_set
(και τα δύο γράφουν αυτόματα στο ίδιο results/v2/, χωρίς σύγκρουση)
"""

import json
import os
import random
import shutil
import sys

sys.path.insert(0, "/home/sklavenitis/thesis/inference")
from query_rag import PROMPT_VERSION  # noqa: E402

RAG_TEST_DIR = "/home/sklavenitis/thesis/dataset/rag_test"
RESULTS_DIR = f"/home/sklavenitis/thesis/results/{PROMPT_VERSION}"
OUTPUT_DIR = "/home/sklavenitis/thesis/dataset/rag_test_v2_sample"

SAMPLE_SIZE_FROM_CORRECT = 30
SEED = 42


def main():
    false_negatives = []
    correct = []

    for fname in os.listdir(RESULTS_DIR):
        if not fname.startswith("report_") or not fname.endswith(".json"):
            continue
        pkg = fname[len("report_"):-len(".json")]
        with open(os.path.join(RESULTS_DIR, fname), "r", encoding="utf-8") as f:
            r = json.load(f)
        verdict = r.get("final_verdict")

        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            correct.append(pkg)
        elif verdict == "BENIGN":
            false_negatives.append(pkg)
        # EVALUATION_FAILED/NO_CHAINS_FOUND/ΔΕΝ ΤΡΕΞΕ - αγνοούνται, δεν
        # ανήκουν ούτε σε "διορθώθηκε" ούτε σε "χάλασε" σύγκριση.

    print(f"[*] Βρέθηκαν {len(false_negatives)} false negatives και {len(correct)} σωστά (v1).")

    random.Random(SEED).shuffle(correct)
    sample_from_correct = correct[:SAMPLE_SIZE_FROM_CORRECT]

    to_copy = false_negatives + sample_from_correct
    print(f"[*] Θα αντιγραφούν {len(to_copy)} πακέτα "
          f"({len(false_negatives)} FN + {len(sample_from_correct)} τυχαία σωστά).")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    copied = 0
    for pkg in to_copy:
        src = os.path.join(RAG_TEST_DIR, f"{pkg}.json")
        dst = os.path.join(OUTPUT_DIR, f"{pkg}.json")
        if os.path.exists(src):
            shutil.copy2(src, dst)
            copied += 1

    print(f"[✓] {copied} αρχεία αντιγράφηκαν -> {OUTPUT_DIR}")
    print(f"\nΕπόμενα βήματα:")
    print(f"  1. Άλλαξε PROMPT_VERSION = \"v2\" στο query_rag.py (μαζί με το ίδιο το prompt)")
    print(f"  2. python3 check_test_set.py {OUTPUT_DIR}")
    print(f"  3. python3 check_test_set.py /home/sklavenitis/thesis/test_set")
    print(f"  4. python3 evaluation_summary.py   (θα διαβάσει αυτόματα το results/v2/)")


if __name__ == "__main__":
    main()

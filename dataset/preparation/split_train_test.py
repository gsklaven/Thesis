"""
Χωρίζει το final_diverse_subset/ σε train/ (για το RAG index) και test/
(κρατιέται ΕΞΩ από το RAG, για evaluation).

ΚΡΙΣΙΜΟ: το split γίνεται ανά campaign_signature, ΟΧΙ ανά μεμονωμένο πακέτο.
Αν χωρίζαμε τυχαία ανά πακέτο, ένα test δείγμα θα μπορούσε να είναι σχεδόν
πανομοιότυπο με κάτι που το RAG ήδη "είδε" από την ίδια καμπάνια στο train -
αυτό θα έδειχνε τεχνητά τέλεια απόδοση χωρίς να σημαίνει τίποτα για
πραγματική γενίκευση σε πρωτότυπο malware.
"""

import json
import os
import random
import shutil

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
SOURCE_DIR = os.path.join(BASE_DIR, "final_diverse_subset")
ATTACK_TAGS_JSON = os.path.join(BASE_DIR, "attack_type_tags.json")

TRAIN_DIR = os.path.join(BASE_DIR, "rag_train")
TEST_DIR = os.path.join(BASE_DIR, "rag_test")

TEST_FRACTION = 0.2   # ~20% των campaigns πάει σε test
SEED = 42              # deterministic split - αναπαραγώγιμο για το thesis


def main():
    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    pkgs = [f[:-5] for f in os.listdir(SOURCE_DIR) if f.endswith(".json")]
    print(f"[*] {len(pkgs)} πακέτα στο final_diverse_subset/")

    # Ομαδοποίηση ανά campaign_signature (ή, αν δεν υπάρχει, το ίδιο το
    # όνομα πακέτου λειτουργεί ως δική του "καμπάνια" ενός μέλους)
    campaign_to_pkgs = {}
    for pkg in pkgs:
        sig = attack_tags.get(pkg, {}).get("campaign_signature") or f"__unique__:{pkg}"
        campaign_to_pkgs.setdefault(sig, []).append(pkg)

    # M3 FIX: sorted() πριν shuffle — χωρίς αυτό, η σειρά των dict keys
    # εξαρτάται από τη σειρά εισαγωγής. Αν προστεθούν νέα πακέτα, ολόκληρο
    # το split αλλάζει απρόβλεπτα. Με sorted, μόνο νέες campaigns
    # μπαίνουν στο τέλος χωρίς να ανακατεύουν τις υπάρχουσες.
    campaigns = sorted(campaign_to_pkgs.keys())
    random.Random(SEED).shuffle(campaigns)

    n_test = max(1, int(len(campaigns) * TEST_FRACTION))
    test_campaigns = set(campaigns[:n_test])
    train_campaigns = set(campaigns[n_test:])

    train_pkgs, test_pkgs = [], []
    for sig, pkg_list in campaign_to_pkgs.items():
        target = test_pkgs if sig in test_campaigns else train_pkgs
        target.extend(pkg_list)

    for d in (TRAIN_DIR, TEST_DIR):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    for pkg in train_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TRAIN_DIR, f"{pkg}.json"))
    for pkg in test_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TEST_DIR, f"{pkg}.json"))

    print(f"[*] {len(train_campaigns)} campaigns / {len(train_pkgs)} πακέτα -> {TRAIN_DIR}")
    print(f"[*] {len(test_campaigns)} campaigns / {len(test_pkgs)} πακέτα -> {TEST_DIR}")
    print("[*] ΚΑΝΕΝΑ campaign δεν εμφανίζεται και στα δύο σύνολα (no leakage).")


if __name__ == "__main__":
    main()

"""
Χωρίζει το final_diverse_subset/ σε train/ (για το RAG index) και test/
(κρατιέται ΕΞΩ από το RAG, για evaluation).

ΚΡΙΣΙΜΟ: το split γίνεται ανά ΟΙΚΟΓΕΝΕΙΑ, ΟΧΙ ανά μεμονωμένο πακέτο. Οικογένεια = πακέτα που
συνδέονται (μεταβατικά) είτε με την ίδια πραγματική καμπάνια είτε με τον ίδιο κώδικα
(payload_signature). Αν χωρίζαμε ανά πακέτο, ή μόνο ανά καμπάνια (hash του κειμένου της
αναφοράς - ο ίδιος κώδικας είχε συχνά διαφορετικό κείμενο), ένα test δείγμα θα μπορούσε να
είναι πανομοιότυπο με κάτι που το RAG ήδη "είδε" στο train - αυτό θα έδειχνε τεχνητά καλή
απόδοση χωρίς να σημαίνει τίποτα για γενίκευση σε νέο malware.

Διαβάζει το final_diverse_subset_meta.json που γράφει το build_final_dataset.py.
"""

import collections
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
META_JSON = os.path.join(BASE_DIR, "final_diverse_subset_meta.json")
# Αποτελέσματα και ετικέτες αντιστοιχίζονται ανά ΟΝΟΜΑ: ένα malware του test με το ίδιο όνομα
# με benign του test θα "συγκρουόταν" (π.χ. requests). Τέτοιες οικογένειες πάνε στο train.
BENIGN_DIR = os.path.join(BASE_DIR, "benign_test_set")

TRAIN_DIR = os.path.join(BASE_DIR, "rag_train")
TEST_DIR = os.path.join(BASE_DIR, "rag_test")

TEST_FRACTION = 0.2   # ~20% των ΠΑΚΕΤΩΝ πάει σε test (ολόκληρες οικογένειες)
SEED = 42              # deterministic split - αναπαραγώγιμο για το thesis


def families(meta):
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    for pkg, m in meta.items():
        find(("pkg", pkg))
        if m.get("campaign"):
            union(("pkg", pkg), ("campaign", m["campaign"]))
        if m.get("n_chains", 0) > 0:   # ο κενός κώδικας (0 chains) δεν συνδέει πακέτα
            union(("pkg", pkg), ("payload", m["payload_signature"]))
    fam = collections.defaultdict(list)
    for pkg in meta:
        fam[find(("pkg", pkg))].append(pkg)
    return [sorted(f) for f in fam.values()]


def main():
    with open(META_JSON, "r", encoding="utf-8") as f:
        meta = json.load(f)
    pkgs = {f[:-5] for f in os.listdir(SOURCE_DIR) if f.endswith(".json")}
    missing = pkgs - set(meta)
    if missing:
        raise SystemExit(f"[!] {len(missing)} πακέτα του final_diverse_subset/ λείπουν από το "
                         f"{META_JSON} (π.χ. {sorted(missing)[:3]}) - ξανάτρεξε το build_final_dataset.py")
    meta = {p: m for p, m in meta.items() if p in pkgs}
    print(f"[*] {len(pkgs)} πακέτα στο final_diverse_subset/")

    # sorted() πριν το shuffle: η σειρά δεν εξαρτάται από τη σειρά εισαγωγής.
    fams = sorted(families(meta))
    random.Random(SEED).shuffle(fams)
    target = TEST_FRACTION * len(meta)
    benign_names = {f[:-5] for f in os.listdir(BENIGN_DIR) if f.endswith(".json")} if os.path.isdir(BENIGN_DIR) else set()
    train_pkgs, test_pkgs = [], []
    n_test_fams = 0
    for f in fams:
        if len(test_pkgs) + len(f) <= target and not (set(f) & benign_names):
            test_pkgs.extend(f)
            n_test_fams += 1
        else:
            train_pkgs.extend(f)

    # Επαλήθευση: καμία καμπάνια και κανένας (μη κενός) κώδικας και στα δύο σύνολα.
    key_sets = lambda P, k: {meta[p][k] for p in P if meta[p].get(k) and (k != "payload_signature" or meta[p]["n_chains"] > 0)}
    shared_c = key_sets(train_pkgs, "campaign") & key_sets(test_pkgs, "campaign")
    shared_p = key_sets(train_pkgs, "payload_signature") & key_sets(test_pkgs, "payload_signature")
    assert not shared_c and not shared_p, f"leakage: {len(shared_c)} campaigns, {len(shared_p)} payloads"
    assert not (set(test_pkgs) & benign_names), "όνομα malware του test ίδιο με benign του test"

    for d in (TRAIN_DIR, TEST_DIR):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    for pkg in train_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TRAIN_DIR, f"{pkg}.json"))
    for pkg in test_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TEST_DIR, f"{pkg}.json"))

    zero = lambda P: sum(1 for p in P if meta[p]["n_chains"] == 0)
    print(f"[*] {len(fams) - n_test_fams} οικογένειες / {len(train_pkgs)} πακέτα ({zero(train_pkgs)} χωρίς chains) -> {TRAIN_DIR}")
    print(f"[*] {n_test_fams} οικογένειες / {len(test_pkgs)} πακέτα ({zero(test_pkgs)} χωρίς chains) -> {TEST_DIR}")
    print(f"[*] Μεγαλύτερη οικογένεια: {max(len(f) for f in fams)} πακέτα.")
    print("[*] ΚΑΜΙΑ καμπάνια και ΚΑΝΕΝΑΣ κοινός κώδικας δεν εμφανίζεται και στα δύο σύνολα (no leakage).")


if __name__ == "__main__":
    main()

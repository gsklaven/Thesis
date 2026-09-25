"""
Split final_diverse_subset/ into rag_train/ (source of the RAG index) and rag_test/ (kept OUT of the
RAG, used only for evaluation).

CRITICAL: the split is by FAMILY, NOT by individual package. A family is the set of packages that are
connected (transitively) either by the same real campaign or by the same code (payload_signature).
Splitting per package, or only per campaign (a hash of the report text - identical code often had
different texts), would let a test sample be identical to something the RAG has already "seen" in
train; the results would look good without saying anything about generalisation to new malware.

Families whose package name also exists in the benign test set are kept in train, so that every name
of the evaluation sets has a single label. Reads final_diverse_subset_meta.json (written by
build_final_dataset.py) and ASSERTS that no campaign and no code is shared by train and test.
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
# Results and labels are matched by NAME: a test malware sample with the same name as a benign test
# package would collide with it (e.g. requests). Such families go to train.
BENIGN_DIR = os.path.join(BASE_DIR, "benign_test_set")

TRAIN_DIR = os.path.join(BASE_DIR, "rag_train")
TEST_DIR = os.path.join(BASE_DIR, "rag_test")

TEST_FRACTION = 0.2   # ~20% of the PACKAGES go to test (whole families)
SEED = 42              # deterministic split - reproducible


def families(meta):
    """
    Families of packages (sorted lists), computed with union-find: a package is joined with its
    campaign node and with its payload node, so packages sharing either end up in the same family.
    """
    parent = {}

    def find(x):
        """Root of x, with path halving."""
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        """Merge the sets of a and b."""
        parent[find(a)] = find(b)

    for pkg, m in meta.items():
        find(("pkg", pkg))
        if m.get("campaign"):
            union(("pkg", pkg), ("campaign", m["campaign"]))
        if m.get("n_chains", 0) > 0:   # empty code (0 chains) does not connect packages
            union(("pkg", pkg), ("payload", m["payload_signature"]))
    fam = collections.defaultdict(list)
    for pkg in meta:
        fam[find(("pkg", pkg))].append(pkg)
    return [sorted(f) for f in fam.values()]


def main():
    """Assign whole families to test until TEST_FRACTION of the packages, check for leakage and copy the files."""
    with open(META_JSON, "r", encoding="utf-8") as f:
        meta = json.load(f)
    pkgs = {f[:-5] for f in os.listdir(SOURCE_DIR) if f.endswith(".json")}
    missing = pkgs - set(meta)
    if missing:
        raise SystemExit(f"[!] {len(missing)} packages of final_diverse_subset/ are missing from "
                         f"{META_JSON} (e.g. {sorted(missing)[:3]}) - run build_final_dataset.py again")
    meta = {p: m for p, m in meta.items() if p in pkgs}
    print(f"[*] {len(pkgs)} packages in final_diverse_subset/")

    # sorted() before the shuffle: the order does not depend on insertion order (reproducible).
    fams = sorted(families(meta))
    random.Random(SEED).shuffle(fams)
    target = TEST_FRACTION * len(meta)
    benign_names = {f[:-5] for f in os.listdir(BENIGN_DIR) if f.endswith(".json")} if os.path.isdir(BENIGN_DIR) else set()
    train_pkgs, test_pkgs = [], []
    n_test_fams = 0
    for f in fams:
        # a whole family goes to test if it still fits and none of its names is a benign package
        if len(test_pkgs) + len(f) <= target and not (set(f) & benign_names):
            test_pkgs.extend(f)
            n_test_fams += 1
        else:
            train_pkgs.extend(f)

    # Verification: no campaign and no (non-empty) code in both sets.
    key_sets = lambda P, k: {meta[p][k] for p in P if meta[p].get(k) and (k != "payload_signature" or meta[p]["n_chains"] > 0)}
    shared_c = key_sets(train_pkgs, "campaign") & key_sets(test_pkgs, "campaign")
    shared_p = key_sets(train_pkgs, "payload_signature") & key_sets(test_pkgs, "payload_signature")
    assert not shared_c and not shared_p, f"leakage: {len(shared_c)} campaigns, {len(shared_p)} payloads"
    assert not (set(test_pkgs) & benign_names), "a test malware name equals a benign test package name"

    for d in (TRAIN_DIR, TEST_DIR):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    for pkg in train_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TRAIN_DIR, f"{pkg}.json"))
    for pkg in test_pkgs:
        shutil.copy2(os.path.join(SOURCE_DIR, f"{pkg}.json"), os.path.join(TEST_DIR, f"{pkg}.json"))

    zero = lambda P: sum(1 for p in P if meta[p]["n_chains"] == 0)
    print(f"[*] {len(fams) - n_test_fams} families / {len(train_pkgs)} packages ({zero(train_pkgs)} without chains) -> {TRAIN_DIR}")
    print(f"[*] {n_test_fams} families / {len(test_pkgs)} packages ({zero(test_pkgs)} without chains) -> {TEST_DIR}")
    print(f"[*] Largest family: {max(len(f) for f in fams)} packages.")
    print("[*] NO campaign and NO shared code appears in both sets (no leakage).")


if __name__ == "__main__":
    main()

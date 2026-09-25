"""
Reproducible evaluation subset for the local-model experiment (LLM running on the analyst's own machine).

A local model is much slower than an API model (~22 s per Behavior Chain with 4 parallel requests on an
Apple M5, vs ~16,500 chains per configuration for the full evaluation set), so it is evaluated on a
subset fixed IN ADVANCE: a seeded random sample of N_MALWARE packages of rag_test and N_BENIGN packages
of benign_test_set, among the packages with 1..MAX_CHAINS evaluable Behavior Chains (chains that are not
pure vendor code, the same filter as query_rag.py). The same packages already have DeepSeek results, so
the two models are compared package by package.

Writes:
  dataset/local_subset.json                 parameters + the selected package names (tracked in git)
  dataset/local_subset/malware/<pkg>.json   symlinks to dataset/rag_test/<pkg>.json
  dataset/local_subset/benign/<pkg>.json    symlinks to dataset/benign_test_set/<pkg>.json
The symlink folders are the input folders of results/check_test_set.py.

Usage: python3 dataset/preparation/select_local_subset.py [--malware 120] [--benign 60] [--max-chains 60]
"""
import argparse
import json
import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import is_pure_vendor_chain  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "dataset")
SEED = 42


def evaluable_chains(path):
    """Number of Behavior Chains of a chains file that the LLM would evaluate (pure vendor chains excluded)."""
    with open(path, encoding="utf-8") as f:
        chains = json.load(f).get("behavior_chains", [])
    return sum(1 for c in chains if not is_pure_vendor_chain(c))


def eligible(folder, max_chains):
    """Sorted package names of a folder with 1..max_chains evaluable chains, and the chain count of each."""
    counts = {}
    for fname in sorted(os.listdir(folder)):
        if fname.endswith(".json"):
            counts[fname[:-5]] = evaluable_chains(os.path.join(folder, fname))
    return sorted(p for p, n in counts.items() if 1 <= n <= max_chains), counts


def link_folder(dest, src_folder, packages):
    """(Re)create dest with one symlink per selected package, pointing to its chains file."""
    if os.path.lexists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    for p in packages:
        os.symlink(os.path.join(src_folder, f"{p}.json"), os.path.join(dest, f"{p}.json"))


def main():
    """Select the subset, write local_subset.json and the symlink folders, print its size."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware", type=int, default=120, help="number of malware packages")
    ap.add_argument("--benign", type=int, default=60, help="number of benign packages")
    ap.add_argument("--max-chains", type=int, default=60, help="maximum evaluable chains per package")
    args = ap.parse_args()

    mal_dir, ben_dir = os.path.join(DS, "rag_test"), os.path.join(DS, "benign_test_set")
    mal_ok, mal_n = eligible(mal_dir, args.max_chains)
    ben_ok, ben_n = eligible(ben_dir, args.max_chains)
    # one generator for both draws, in a fixed order -> the same subset on every machine
    rng = random.Random(SEED)
    malware = sorted(rng.sample(mal_ok, args.malware))
    benign = sorted(rng.sample(ben_ok, args.benign))

    subset = {
        "method": "seeded random sample of packages with 1..max_chains evaluable Behavior Chains",
        "seed": SEED, "max_chains": args.max_chains,
        "eligible": {"malware": len(mal_ok), "benign": len(ben_ok)},
        "chains": {"malware": sum(mal_n[p] for p in malware), "benign": sum(ben_n[p] for p in benign)},
        "malware": malware, "benign": benign,
    }
    with open(os.path.join(DS, "local_subset.json"), "w", encoding="utf-8") as f:
        json.dump(subset, f, indent=1)
    link_folder(os.path.join(DS, "local_subset", "malware"), mal_dir, malware)
    link_folder(os.path.join(DS, "local_subset", "benign"), ben_dir, benign)

    total = subset["chains"]["malware"] + subset["chains"]["benign"]
    print(f"[+] {len(malware)} malware ({subset['chains']['malware']} chains, of {len(mal_ok)} eligible) + "
          f"{len(benign)} benign ({subset['chains']['benign']} chains, of {len(ben_ok)} eligible)")
    print(f"[+] {total} chains per configuration -> dataset/local_subset.json, dataset/local_subset/{{malware,benign}}/")


if __name__ == "__main__":
    main()

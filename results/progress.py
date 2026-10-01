"""
progress.py - live progress of an evaluation run.

For every run folder given it shows, per set of packages: how many are done, the verdicts so far, the wrong
verdicts so far, the agreement with the DeepSeek run of the same RAG mode and representation (on the packages that run
evaluated) and the Behavior Chains left. The speed is measured in chains over the last two hours (so earlier
runs and pauses do not distort it) and gives the estimate of the remaining time.

The packages come either from a subset file (default: dataset/local_subset.json, the local-model runs v14_local_*)
or, with --sets, from dataset folders (e.g. the v14 run: rag_test, benign_test_set and the obfuscated sets).

Usage: python3 results/progress.py [tag ...] [--subset dataset/local_subset.json] [--watch SECONDS]
       python3 results/progress.py v14_sum v14_samples v14_policy v14_llm --sets dataset/rag_test \
           dataset/benign_test_set dataset/obfuscated/* --watch 60
"""
import argparse
import glob
import json
import os
import time
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
POSITIVE = ("MALICIOUS", "SUSPICIOUS")
NOT_JUDGED = ("NO_CHAINS_FOUND", "INCOMPLETE", "EVALUATION_FAILED", "UNKNOWN")
SPEED_WINDOW = 2 * 3600  # seconds of recent reports used to measure the speed
# the DeepSeek run every run is compared with: the one with the same Behavior Chain representation
# (v13_* local runs -> v12, everything else -> the final v14 runs)
def ref_tag(tag):
    return f"{'v12' if tag.startswith('v13') else 'v14'}_{tag.rsplit('_', 1)[1]}"


def reports(tag):
    """{package: (final verdict, file modification time, evaluated chains)} of a results folder."""
    out = {}
    for f in glob.glob(os.path.join(ROOT, "results", tag, "report_*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                r = json.load(fh)
            out[os.path.basename(f)[7:-5]] = (r.get("final_verdict"), os.path.getmtime(f),
                                              r.get("total_chains_analyzed") or 0)
        except (OSError, ValueError):
            pass  # a report being written right now
    return out


def seconds_per_chain(runs):
    """Seconds per Behavior Chain over the reports written in the last SPEED_WINDOW, None if too few."""
    recent = sorted((mtime, chains) for rep in runs for _, mtime, chains in rep.values()
                    if mtime >= time.time() - SPEED_WINDOW)
    if len(recent) < 3:
        return None
    # the chains of the first report were evaluated before the window's first timestamp
    chains = sum(c for _, c in recent[1:])
    return (recent[-1][0] - recent[0][0]) / chains if chains else None


def from_subset(path):
    """Sets, labels and chain counts (None: taken from the v12 reports) of a subset file."""
    with open(path, encoding="utf-8") as f:
        subset = json.load(f)
    sets = {"malware": subset["malware"], "benign": subset["benign"]}
    labels = {p: ("malicious" if name == "malware" else "benign") for name, pkgs in sets.items() for p in pkgs}
    return sets, labels, None


def from_folders(folders):
    """Sets (one per folder), labels (expected_labels.json) and chain counts of dataset folders."""
    with open(os.path.join(ROOT, "expected_labels.json"), encoding="utf-8") as f:
        expected = json.load(f)
    sets, chains = {}, {}
    for folder in folders:
        name = os.path.relpath(os.path.abspath(folder), os.path.join(ROOT, "dataset"))
        sets[name] = []
        for f in sorted(os.listdir(folder)):
            if f.endswith(".json") and not f.startswith("_"):
                with open(os.path.join(folder, f), encoding="utf-8") as fh:
                    chains[f[:-5]] = len(json.load(fh).get("behavior_chains") or [])
                sets[name].append(f[:-5])
    labels = {p: expected.get(p) for pkgs in sets.values() for p in pkgs}
    return sets, labels, chains


def show(tags, sets, labels, chains):
    """Print one progress block per run folder, then the estimate of the time left for all of them."""
    total = sum(len(v) for v in sets.values())
    print(time.strftime("%H:%M:%S"), "- " + ", ".join(f"{name}: {len(p)}" for name, p in sets.items()))
    runs, chains_left = [], 0
    for tag in tags:
        rep = reports(tag)
        # the DeepSeek run with the same RAG mode (v13_sum -> v12_sum); without chain counts of the sets it
        # also gives the chain count of the packages not evaluated yet
        ref = reports(ref_tag(tag))
        runs.append(rep)
        done = [p for s in sets.values() for p in s if p in rep]
        count = (lambda p: chains.get(p, 0)) if chains is not None else (lambda p: ref[p][2] if p in ref else 0)
        left = sum(count(p) for s in sets.values() for p in s if p not in rep)
        chains_left += left
        print(f"\n{tag}: {len(done)}/{total} packages | {left} chains left")
        for name, pkgs in sets.items():
            d = [p for p in pkgs if p in rep]
            v = Counter(rep[p][0] for p in d)
            in_ref = [p for p in d if p in ref]
            agree = sum((rep[p][0] in POSITIVE) == (ref[p][0] in POSITIVE) for p in in_ref)
            wrong = sum((rep[p][0] in POSITIVE) != (labels.get(p) == "malicious") for p in d
                        if rep[p][0] not in NOT_JUDGED)
            same = f" | same as {ref_tag(tag)}: {agree}/{len(in_ref)}" if in_ref else ""
            print(f"  {name:20s} {len(d):4d}/{len(pkgs):<4d} verdicts {dict(v)} | wrong so far: {wrong}{same}")
    speed = seconds_per_chain(runs)
    if speed:
        print(f"\n~{speed:.2f} s per chain (all runs together, last {SPEED_WINDOW // 3600} h) | {chains_left} "
              f"chains left -> ~{chains_left * speed / 3600:.1f} h" + ("" if chains_left else " (done)"))


def main():
    """Parse the arguments and print the progress once or every --watch seconds."""
    ap = argparse.ArgumentParser()
    ap.add_argument("tags", nargs="*", default=["v14_local_sum", "v14_local_llm"])
    ap.add_argument("--subset", default=os.path.join(ROOT, "dataset", "local_subset.json"))
    ap.add_argument("--sets", nargs="+", help="dataset folders instead of a subset file")
    ap.add_argument("--watch", type=int, default=0, help="refresh every N seconds (Ctrl+C to stop)")
    args = ap.parse_args()
    sets, labels, chains = from_folders(args.sets) if args.sets else from_subset(args.subset)
    while True:
        if args.watch:
            os.system("clear")
        show(args.tags, sets, labels, chains)
        if not args.watch:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()

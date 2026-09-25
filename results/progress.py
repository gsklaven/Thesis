"""
progress.py - live progress of an evaluation run (e.g. the local-model run on dataset/local_subset).

For every run folder given (default: v12_sum_lmstudio and v12_llm_lmstudio) it shows, over the packages of
the subset: how many are done per class, the verdicts so far, the agreement with the DeepSeek run of the
same RAG mode on the same packages, and the Behavior Chains left. The speed is measured in chains over the
last two hours (so earlier runs and pauses do not distort it) and gives the estimate of the remaining time.

Usage: python3 results/progress.py [tag ...] [--subset dataset/local_subset.json] [--watch SECONDS]
"""
import argparse
import glob
import json
import os
import time
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
POSITIVE = ("MALICIOUS", "SUSPICIOUS")
SPEED_WINDOW = 2 * 3600  # seconds of recent reports used to measure the speed


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


def show(tags, subset):
    """Print one progress block per run folder, then the estimate of the time left for all of them."""
    sets = {"malware": subset["malware"], "benign": subset["benign"]}
    total = sum(len(v) for v in sets.values())
    print(time.strftime("%H:%M:%S"), f"- subset: {len(sets['malware'])} malware + {len(sets['benign'])} benign")
    runs, chains_left = [], 0
    for tag in tags:
        rep = reports(tag)
        # the DeepSeek run with the same RAG mode (v12_sum_lmstudio -> v12_sum); it also gives the chain
        # count of the packages not evaluated yet
        ref = reports("_".join(tag.split("_")[:2]))
        runs.append(rep)
        done = [p for s in sets.values() for p in s if p in rep]
        left = sum(ref[p][2] for s in sets.values() for p in s if p not in rep and p in ref)
        chains_left += left
        print(f"\n{tag}: {len(done)}/{total} packages | {left} chains left")
        for name, pkgs in sets.items():
            d = [p for p in pkgs if p in rep]
            v = Counter(rep[p][0] for p in d)
            agree = sum((rep[p][0] in POSITIVE) == (ref[p][0] in POSITIVE) for p in d if p in ref)
            wrong = sum((rep[p][0] in POSITIVE) != (name == "malware") for p in d
                        if rep[p][0] not in ("NO_CHAINS_FOUND", "INCOMPLETE", "EVALUATION_FAILED", "UNKNOWN"))
            print(f"  {name:8s} {len(d):4d}/{len(pkgs):<4d} verdicts {dict(v)} | wrong so far: {wrong} | "
                  f"same as DeepSeek: {agree}/{len(d)}")
    speed = seconds_per_chain(runs)
    if speed:
        print(f"\n~{speed:.0f} s per chain (last {SPEED_WINDOW // 3600} h) | {chains_left} chains left "
              f"-> ~{chains_left * speed / 3600:.1f} h" + ("" if chains_left else " (done)"))


def main():
    """Parse the arguments and print the progress once or every --watch seconds."""
    ap = argparse.ArgumentParser()
    ap.add_argument("tags", nargs="*", default=["v12_sum_lmstudio", "v12_llm_lmstudio"])
    ap.add_argument("--subset", default=os.path.join(ROOT, "dataset", "local_subset.json"))
    ap.add_argument("--watch", type=int, default=0, help="refresh every N seconds (Ctrl+C to stop)")
    args = ap.parse_args()
    with open(args.subset, encoding="utf-8") as f:
        subset = json.load(f)
    while True:
        if args.watch:
            os.system("clear")
        show(args.tags, subset)
        if not args.watch:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()

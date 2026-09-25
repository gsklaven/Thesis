"""
progress.py - live progress of an evaluation run (e.g. the local-model run on dataset/local_subset).

For every run folder given (default: v12_sum_lmstudio and v12_llm_lmstudio) it shows, over the packages of
the subset: how many are done per class, the verdicts so far, the agreement with the DeepSeek run of the
same RAG mode on the same packages, the average time per package and an estimate of the remaining time.

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


def reports(tag):
    """{package: (final verdict, file modification time)} of a results folder."""
    out = {}
    for f in glob.glob(os.path.join(ROOT, "results", tag, "report_*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                out[os.path.basename(f)[7:-5]] = (json.load(fh).get("final_verdict"), os.path.getmtime(f))
        except (OSError, ValueError):
            pass  # a report being written right now
    return out


def show(tags, subset):
    """Print one progress block per run folder."""
    sets = {"malware": subset["malware"], "benign": subset["benign"]}
    total = sum(len(v) for v in sets.values())
    print(time.strftime("%H:%M:%S"), f"- subset: {len(sets['malware'])} malware + {len(sets['benign'])} benign")
    for tag in tags:
        rep = reports(tag)
        # the DeepSeek run with the same RAG mode (v12_sum_lmstudio -> v12_sum)
        ref = reports("_".join(tag.split("_")[:2]))
        done = [p for s in sets.values() for p in s if p in rep]
        print(f"\n{tag}: {len(done)}/{total} packages")
        for name, pkgs in sets.items():
            d = [p for p in pkgs if p in rep]
            v = Counter(rep[p][0] for p in d)
            agree = sum((rep[p][0] in POSITIVE) == (ref[p][0] in POSITIVE) for p in d if p in ref)
            wrong = sum((rep[p][0] in POSITIVE) != (name == "malware") for p in d
                        if rep[p][0] not in ("NO_CHAINS_FOUND", "INCOMPLETE", "EVALUATION_FAILED", "UNKNOWN"))
            print(f"  {name:8s} {len(d):4d}/{len(pkgs):<4d} verdicts {dict(v)} | wrong so far: {wrong} | "
                  f"same as DeepSeek: {agree}/{len(d)}")
        if len(done) >= 2:
            times = sorted(rep[p][1] for p in done)
            per_pkg = (times[-1] - times[0]) / (len(times) - 1)
            left = total - len(done)
            print(f"  ~{per_pkg / 60:.1f} min per package | remaining ~{left * per_pkg / 3600:.1f} h"
                  + ("" if left else " (done)"))


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

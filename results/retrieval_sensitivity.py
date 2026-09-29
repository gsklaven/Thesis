"""
retrieval_sensitivity.py - sensitivity of retrieval to the slice-node limit of the compact representation.

The Compact Behavior Chain Representation (utils.flatten_chain_to_text) keeps the first 10 slice nodes,
10 callees and 200 words, because of the input length of the embedding model. This script rebuilds the
index vectors (rag_train) and the query vectors (evaluation sets) with 5, 20 and unlimited slice nodes,
everything else unchanged, and compares them with the 10-node baseline:
  - change of the top-1 similarity of every evaluation Behavior Chain with the index;
  - evaluation packages that move to another similarity stratum (results_analysis.STRATA).
Pure vendor chains are left out on both sides, as in build_rag_index.py and query_rag.py.

Usage: python3 results/retrieval_sensitivity.py [--out results/analysis/retrieval_sensitivity.json]
"""
import argparse
import json
import os
import sys

import numpy as np
from sentence_transformers import SentenceTransformer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DS = os.path.join(ROOT, "dataset")
sys.path.insert(0, os.path.join(DS, "preparation"))
sys.path.insert(0, HERE)
import utils  # noqa: E402
import results_analysis as ra  # noqa: E402  (same similarity strata as the thesis tables)

MODEL_NAME = "all-MiniLM-L6-v2"
BASELINE = 10
VARIANTS = (5, 20, None)  # None = no limit on slice nodes


def chains(d):
    """(package, chain) for every non-vendor chain of a folder of <package>.json files."""
    out = []
    for f in sorted(os.listdir(d)):
        if f.endswith(".json") and not f.startswith("_"):
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                for c in json.load(fh).get("behavior_chains", []):
                    if not utils.is_pure_vendor_chain(c):
                        out.append((f[:-5], c))
    return out


def compact(chain, max_slice):
    # flatten_chain_to_text with the slice-node limit as the only difference
    return utils._serialize_chain(chain, None, max_words=200, max_slice=max_slice, max_callees=10)


def stratum(s):
    return next(label for label, lo, hi in ra.STRATA if lo <= s < hi)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=os.path.join(HERE, "analysis", "retrieval_sensitivity.json"))
    args = ap.parse_args()

    train = chains(os.path.join(DS, "rag_train"))
    mal = chains(os.path.join(DS, "rag_test"))
    ben = chains(os.path.join(DS, "benign_test_set"))
    query, malware = mal + ben, {p for p, _ in mal}
    print(f"[*] index chains {len(train)}, evaluation chains {len(query)} "
          f"({len(malware)} malware and {len({p for p, _ in ben})} benign packages)", flush=True)

    model = SentenceTransformer(MODEL_NAME)
    best, pkg = {}, {}
    for ms in (BASELINE,) + VARIANTS:
        index = model.encode([compact(c, ms) for _, c in train], batch_size=128, normalize_embeddings=True)
        q = model.encode([compact(c, ms) for _, c in query], batch_size=128, normalize_embeddings=True)
        # normalised vectors: the dot product is the cosine similarity
        best[ms] = np.concatenate([(q[i:i + 2048] @ index.T).max(1) for i in range(0, len(q), 2048)])
        pkg[ms] = {}
        for (p, _), s in zip(query, best[ms]):
            pkg[ms][p] = max(pkg[ms].get(p, 0.0), float(s))
        print(f"    max_slice={ms}: done", flush=True)

    result = {"baseline_max_slice": BASELINE, "packages": len(pkg[BASELINE]),
              "malware_packages": len(malware), "chains": len(query), "variants": {}}
    for ms in VARIANTS:
        d = np.abs(best[ms] - best[BASELINE])
        moved = sorted(p for p in pkg[BASELINE] if stratum(pkg[BASELINE][p]) != stratum(pkg[ms][p]))
        result["variants"]["none" if ms is None else str(ms)] = {
            "mean_abs_change": round(float(d.mean()), 4), "p95_abs_change": round(float(np.percentile(d, 95)), 4),
            "packages_changing_stratum": len(moved), "malware_changing_stratum": sum(p in malware for p in moved),
            "changed": moved}
        print(f"[*] max_slice={ms}: mean |change| {d.mean():.4f}, p95 {np.percentile(d, 95):.4f}, "
              f"{len(moved)} of {len(pkg[BASELINE])} packages change stratum "
              f"({sum(p in malware for p in moved)} malware)")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[*] -> {args.out}")


if __name__ == "__main__":
    main()

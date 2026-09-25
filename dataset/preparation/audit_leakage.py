"""
audit_leakage.py

Leakage / representativeness audit of the RAG evaluation. Run AFTER rebuild_rag.py, with
venv/bin/python (needs sentence_transformers + sklearn). Read-only.

  A. structure    train/test disjoint; index built ONLY from rag_train; benign packages are in
                  neither train, test nor the index; campaigns shared by train and test
  B. prompt scan  builds real prompts (no LLM call) for sample test + benign packages and checks that
                  they contain NO pre-computed hint about the package itself: no "[CRITICAL CONTEXT]",
                  no snippet of its own OSV description / campaign, and it never retrieves itself
  C. strata       top-1 similarity of every test/benign package against the index, bucketed
                  (>=0.98 known variant | 0.90-0.98 close | <0.90 novel) + exact twins (>=0.999).
                  These twins are NOT leakage (a new sample resembling known malware is the intended
                  use case) - the point is to REPORT results per stratum.
  D. artifacts    can benign vs malware be told apart from features that carry no behaviour
                  (chain count, vendored share, size, dependency count...)? Per-feature AUC and a
                  cross-validated logistic regression. AUC >> 0.5 = shortcut the LLM/aggregator could use.

Usage: ../../venv/bin/python audit_leakage.py [--sample N] [--chains-per-pkg K] [--out FILE]
"""
import argparse
import glob
import json
import os
import random
import re
import sys

import numpy as np

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "dataset")
sys.path.insert(0, os.path.join(ROOT, "inference"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_PARSE_MB = 200  # after compaction every chains file is < 70 MB; larger files are skipped


def names(d):
    """Package names of a folder of <package>.json files."""
    return {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(d, "*.json"))}


def benign_names():
    """Packages labelled 'benign' in expected_labels.json."""
    exp = json.load(open(os.path.join(ROOT, "expected_labels.json")))
    return {p for p, v in exp.items() if v == "benign"}


def auc(pos, neg):
    """ROC AUC as the probability that a positive score exceeds a negative one (ties count 1/2)."""
    if not pos or not neg:
        return float("nan")
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


# ---------------------------------------------------------------- A
def structure(train, test, benign, index_pkgs, tags):
    """
    Structural checks of the split: disjoint train/test, index built only from train, no benign
    package anywhere in the malware sets, and no campaign or identical code shared by train and test.
    """
    # Same campaign definition as the split (final_diverse_subset_meta.json): generic report texts
    # (e.g. the empty OSV boilerplate, covering hundreds of unrelated payloads) are NOT campaigns.
    meta_path = os.path.join(DS, "final_diverse_subset_meta.json")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    eff = lambda p: meta[p]["campaign"] if p in meta else tags.get(p, {}).get("campaign_signature")
    camp = lambda S: {eff(p) for p in S} - {None, ""}
    shared = camp(train) & camp(test)
    # raw OSV text signatures, reported for information only
    raw = lambda S: {tags.get(p, {}).get("campaign_signature") for p in S} - {None, ""}
    # payload signatures of packages that have chains (identical code)
    pay = lambda S: {meta[p]["payload_signature"] for p in S if p in meta and meta[p]["n_chains"] > 0}
    shared_payloads = pay(train) & pay(test)
    return {
        "train": len(train), "test": len(test), "benign": len(benign),
        "train_test_overlap": sorted(train & test),
        "index_packages_outside_train": sorted(index_pkgs - train),
        "benign_in_train_test_or_index": sorted(benign & (train | test | index_pkgs)),
        "campaigns_shared_train_test": len(shared),
        "identical_code_shared_train_test": len(shared_payloads),
        "generic_report_texts_shared(info, not campaigns)": len((raw(train) & raw(test)) - shared),
        "PASS": not (train & test) and not (index_pkgs - train) and not (benign & (train | test | index_pkgs))
                and not shared and not shared_payloads,
    }


# ---------------------------------------------------------------- B
# lines of an OSV report that are shared by many reports (not specific to one package)
BOILERPLATE = re.compile(r"^(---|_-=|## Source:|Malicious code in|Category:|Campaign:|Reasons \(based)", re.I)


def distinctive_snippet(desc):
    """A chunk of the OSV description that is specific to the report (boilerplate lines removed)."""
    lines = [l.strip() for l in (desc or "").splitlines() if l.strip() and not BOILERPLATE.match(l.strip())]
    text = " ".join(lines)
    return text[:100] if len(text) >= 60 else None


def prompt_scan(engine, packages, tags, matched, own_dir):
    """
    Build the real prompts of the first chains of each package (no LLM call) and look for hints
    about the package itself. Text that also appears in a retrieved neighbour is reported separately
    (it means the neighbour belongs to the same campaign text, not that the package leaked).
    """
    problems, overlaps, checked = [], [], 0
    for pkg, path in packages:
        try:
            res = engine.analyze_package(path, extra_context="")
        except Exception as e:  # noqa: BLE001
            problems.append((pkg, f"analyze_failed:{e.__class__.__name__}"))
            continue
        snippet = distinctive_snippet(matched.get(pkg, {}).get("description"))
        camp = (tags.get(pkg, {}).get("campaign_signature") or "")[:60]
        for r in res[:3]:
            p = r["prompt_for_llm"]
            checked += 1
            if "CRITICAL CONTEXT" in p:
                problems.append((pkg, "critical_context_present"))
            if snippet and snippet in p:
                in_neighbor = any(snippet in (m.get("description") or "") for m in r["malware_matches"])
                (overlaps if in_neighbor else problems).append(
                    (pkg, "own_description_text_also_in_a_neighbor" if in_neighbor else "own_description_in_prompt"))
            if len(camp) >= 30 and camp in p:
                overlaps.append((pkg, "own_campaign_signature_in_prompt"))
            if any(m["package"] == pkg for m in r["malware_matches"]):
                problems.append((pkg, "retrieves_itself"))
    return {"prompts_checked": checked, "problems": problems[:50], "n_problems": len(problems),
            "neighbor_overlap_info(same text in a train neighbor = shared campaign)": len({o[0] for o in overlaps}),
            "PASS": not problems}


# ---------------------------------------------------------------- C
def chain_texts(path, k, rng):
    """Embedding texts of up to k (randomly sampled) chains of a package; None if the file is too big."""
    from utils import flatten_chain_to_text, is_pure_vendor_chain
    if os.path.getsize(path) > MAX_PARSE_MB * 1024 * 1024:
        return None
    # same filter as query_rag.py, so the strata measure what the system actually retrieves for
    chains = [c for c in json.load(open(path)).get("behavior_chains", []) if not is_pure_vendor_chain(c)]
    if len(chains) > k:
        chains = rng.sample(chains, k)
    return [flatten_chain_to_text(c) for c in chains]


def strata(model, index_vecs, groups, k, rng):
    """Per group: packages bucketed by their best (top-1) cosine similarity to any index chain."""
    out = {}
    for label, items in groups.items():
        tops, skipped, twins = [], 0, []
        for pkg, path in items:
            texts = chain_texts(path, k, rng)
            if texts is None:
                skipped += 1
                continue
            if not texts:
                continue
            # normalised embeddings -> dot product = cosine similarity
            q = model.encode(texts, normalize_embeddings=True, batch_size=64)
            best = float((q @ index_vecs.T).max())
            tops.append(best)
            if best >= 0.999:
                twins.append(pkg)
        a = np.array(tops)
        out[label] = {
            "packages": len(tops), "skipped_too_big": skipped,
            ">=0.98 known variant": int((a >= 0.98).sum()), "0.90-0.98 close": int(((a >= 0.90) & (a < 0.98)).sum()),
            "<0.90 novel": int((a < 0.90).sum()), "exact_twins(>=0.999)": len(twins),
            "median_top1": round(float(np.median(a)), 3) if len(a) else None,
            "twin_examples": twins[:8],
        }
    return out


# ---------------------------------------------------------------- D
# byte-level regexes, so large chains files are scanned without parsing the JSON
CAT = re.compile(rb'"category":\s*"([a-z_]+)"')
LOC = re.compile(rb'"location":\s*"([^"]*)"')
N_CH = re.compile(rb'"total_behavior_chains":\s*(\d+)')
N_DEP = re.compile(rb'"total_package_dependencies":\s*(\d+)')
FEATURES = ["log_chains", "anchored_frac", "vendor_frac", "n_categories", "log_kb", "n_dependencies", "unique_files_per_chain"]


def artifact_features(path):
    """Behaviour-free features of one chains file (see FEATURES), or None if it has no chains."""
    data = open(path, "rb").read()
    # the totals are written at the top of the file
    n = int(N_CH.search(data[:2000]).group(1)) if N_CH.search(data[:2000]) else 0
    if n == 0:
        return None
    cats = [c.decode() for c in CAT.findall(data)]
    locs = [m.decode() for m in LOC.findall(data)]
    files = {l.rsplit(":", 1)[0] for l in locs}
    dep = int(N_DEP.search(data[:2000]).group(1)) if N_DEP.search(data[:2000]) else 0
    return [np.log1p(n), sum(c != "unanchored" for c in cats) / max(1, len(cats)),
            sum("vendor/" in l for l in locs) / max(1, len(locs)), len(set(cats)),
            np.log1p(len(data) / 1024), dep, len(files) / max(1, len(locs))]


def artifacts(mal, ben):
    """Per-feature AUC and a cross-validated logistic regression on the behaviour-free features."""
    X, y = [], []
    for label, items in ((1, mal), (0, ben)):
        for _, path in items:
            f = artifact_features(path)
            if f is not None:
                X.append(f)
                y.append(label)
    X, y = np.array(X), np.array(y)
    per = {FEATURES[j]: round(auc(list(X[y == 1, j]), list(X[y == 0, j])), 3) for j in range(X.shape[1])}
    res = {"n_malware": int((y == 1).sum()), "n_benign": int((y == 0).sum()), "per_feature_auc(malware vs benign)": per,
           "features_with_shortcut_risk(|auc-0.5|>0.3)": [k for k, v in per.items() if abs(v - 0.5) > 0.3]}
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedKFold, cross_val_predict
        from sklearn.metrics import roc_auc_score
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        # at most 5 folds, and never more folds than samples of the smaller class
        k = min(5, int((y == 0).sum()), int((y == 1).sum()))
        if k >= 2:
            clf = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=1000))
            p = cross_val_predict(clf, X, y, cv=StratifiedKFold(k, shuffle=True, random_state=0), method="predict_proba")[:, 1]
            res["logistic_cv_auc"] = round(float(roc_auc_score(y, p)), 3)
            res["PASS"] = res["logistic_cv_auc"] < 0.75
    except ImportError:
        res["logistic_cv_auc"] = "sklearn missing"
    return res


def main():
    """Run the four audits (A, D, B, C - cheapest first) and write the JSON report."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, help="limit packages per group (for quick tests)")
    ap.add_argument("--chains-per-pkg", type=int, default=20)
    ap.add_argument("--out", default=os.path.join(DS, "leakage_audit_report.json"))
    ap.add_argument("--benign-dir", default=os.path.join(DS, "benign_test_set"))
    args = ap.parse_args()
    rng = random.Random(0)

    tags = json.load(open(os.path.join(DS, "attack_type_tags.json")))
    matched = {i["package_name"]: i for i in json.load(open(os.path.join(DS, "malware_dataset_matched.json")))}
    meta = json.load(open(os.path.join(DS, "indexes", "rag_index", "metadata.json")))
    index_pkgs = {m["package"] for m in meta}
    train, test = names(os.path.join(DS, "rag_train")), names(os.path.join(DS, "rag_test"))
    benign = benign_names() & names(args.benign_dir)

    mal_items = sorted((p, os.path.join(DS, "rag_test", p + ".json")) for p in test)
    ben_items = sorted((p, os.path.join(args.benign_dir, p + ".json")) for p in benign)
    if args.sample:
        rng.shuffle(mal_items); rng.shuffle(ben_items)
        mal_items, ben_items = mal_items[: args.sample], ben_items[: args.sample]

    report = {}
    print("[A] structure ...")
    report["A_structure"] = structure(train, test, benign, index_pkgs, tags)
    print(json.dumps({k: v for k, v in report["A_structure"].items() if k not in ("train_test_overlap", "index_packages_outside_train")}, indent=1))

    print("[D] artifact-only baseline ...")
    report["D_artifacts"] = artifacts(mal_items, ben_items)
    print(json.dumps(report["D_artifacts"], indent=1))

    # B and C need the embedding model and the RAG engine (loaded only now)
    from sentence_transformers import SentenceTransformer
    import query_rag
    print("[B] prompt scan ...")
    engine = query_rag.RAGEngine()
    scan = (mal_items[: args.sample or 40] + ben_items[: args.sample or 20]) if args.sample else (mal_items[:60] + ben_items[:30])
    report["B_prompt_scan"] = prompt_scan(engine, scan, tags, matched, DS)
    print(json.dumps({k: v for k, v in report["B_prompt_scan"].items()}, indent=1)[:800])

    print("[C] similarity strata ...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    vecs = np.load(os.path.join(DS, "indexes", "rag_index", "vectors.npy"))
    report["C_strata"] = strata(model, vecs, {"malware_test": mal_items, "benign": ben_items}, args.chains_per_pkg, rng)
    print(json.dumps(report["C_strata"], indent=1))

    json.dump(report, open(args.out, "w"), indent=1, ensure_ascii=False, default=str)
    print(f"\n[+] report -> {args.out}")


if __name__ == "__main__":
    main()

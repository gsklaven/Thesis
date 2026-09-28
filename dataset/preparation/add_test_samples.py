"""
add_test_samples.py - add NEW malware samples to the evaluation set without rebuilding the RAG.

The index (rag_train/, indexes/rag_index/) and the existing train/test split stay exactly as they were
built, so the results of the existing evaluation packages remain comparable across versions. A sample is
new if its name is not in v12_known_samples.json (the sample list when the index was built). New samples
are collected and analysed as usual (run_pipeline.sh collect + analyze); this script then applies the
selection and split rules of build_final_dataset.py and split_train_test.py to them:
  - excluded: legitimate MalwareBench packages, samples without payload code (payload_scan.py), chains
    files larger than MAX_FILE_SIZE_MB;
  - one package per code (MAX_PER_PAYLOAD = 1 over the whole set): a new sample whose payload_signature
    already occurs in the final subset (index or evaluation) or in an earlier new sample is excluded;
  - family-level split: a new sample whose campaign occurs in rag_train is excluded (no campaign shared by
    index and evaluation); at most MAX_PER_CAMPAIGN packages per campaign in the evaluation set;
  - a name that is also a benign evaluation package is excluded.
The campaign of a new sample comes from its OSV report (as backfill_osv_descriptions.py +
attack_type_tagger.py do for the rest). Selected samples are copied to rag_test/ and labelled malicious in
expected_labels.json; every decision is written to dataset/added_test_samples.json.

Usage: python3 dataset/preparation/add_test_samples.py [--dry-run]
"""
import argparse
import collections
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_final_dataset as bfd  # noqa: E402
from backfill_osv_descriptions import OSV_DIR, extract_description  # noqa: E402
from utils import campaign_signature  # noqa: E402

DS = bfd._DATASET_DIR
ROOT = os.path.dirname(DS)
KNOWN = os.path.join(DS, "v12_known_samples.json")
OUT = os.path.join(DS, "added_test_samples.json")
TRAIN_DIR, TEST_DIR = os.path.join(DS, "rag_train"), os.path.join(DS, "rag_test")
BENIGN_DIR = os.path.join(DS, "benign_test_set")
LABELS = os.path.join(ROOT, "expected_labels.json")
norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()


def stems(folder):
    return {f[:-5] for f in os.listdir(folder) if f.endswith(".json")} if os.path.isdir(folder) else set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print the decisions without copying anything")
    args = ap.parse_args()

    known = set(json.load(open(KNOWN, encoding="utf-8"))["names"])  # samples when the index was built
    matched = json.load(open(os.path.join(DS, "malware_dataset_matched.json"), encoding="utf-8"))
    matched = {i["package_name"]: i for i in (matched if isinstance(matched, list) else matched.values())
               if i.get("package_name")}
    new = sorted(n for n in matched if n not in known)
    meta = json.load(open(bfd.META_OUT, encoding="utf-8"))
    train, test = stems(TRAIN_DIR), stems(TEST_DIR)
    benign = {norm(b) for b in stems(BENIGN_DIR)}
    false_positive, no_payload = bfd.load_false_positive(), bfd.load_no_payload()
    osv = {norm(d): d for d in os.listdir(OSV_DIR)} if os.path.isdir(OSV_DIR) else {}

    payloads = {m["payload_signature"] for m in meta.values()}
    train_campaigns = {meta[p]["campaign"] for p in train if p in meta and meta[p].get("campaign")}
    test_campaigns = collections.Counter(meta[p]["campaign"] for p in test if p in meta and meta[p].get("campaign"))

    decisions = {}
    for name in new:
        path = os.path.join(bfd.ANALYZED_DIR, f"{name}.json")
        if name in false_positive:
            decisions[name] = "excluded: legitimate MalwareBench package"
        elif name in no_payload:
            decisions[name] = "excluded: no payload code (payload_scan)"
        elif not os.path.exists(path):
            decisions[name] = "excluded: not analysed"
        elif os.path.getsize(path) > bfd.MAX_FILE_SIZE_BYTES:
            decisions[name] = "excluded: oversized chains file"
        elif norm(name) in benign:
            decisions[name] = "excluded: name of a benign evaluation package"
        else:
            data = json.load(open(path, encoding="utf-8"))
            sig = bfd.payload_signature(data)
            desc = (matched[name].get("description") or "").strip()
            if not desc and norm(name) in osv:
                desc = extract_description(os.path.join(OSV_DIR, osv[norm(name)]))
            camp = campaign_signature(desc)
            if data.get("behavior_chains") and sig in payloads:
                decisions[name] = "excluded: same code as a package of the final subset"
            elif camp and camp in train_campaigns:
                decisions[name] = "excluded: campaign of the index (family-level split)"
            elif camp and test_campaigns[camp] >= bfd.MAX_PER_CAMPAIGN:
                decisions[name] = "excluded: campaign already has MAX_PER_CAMPAIGN evaluation packages"
            else:
                decisions[name] = "added"
                if data.get("behavior_chains"):
                    payloads.add(sig)
                if camp:
                    test_campaigns[camp] += 1
                if not args.dry_run:
                    shutil.copy2(path, os.path.join(TEST_DIR, f"{name}.json"))

    added = [n for n, d in decisions.items() if d == "added"]
    print(f"new samples: {len(new)} | added to rag_test: {len(added)}")
    for reason, n in collections.Counter(decisions.values()).most_common():
        print(f"  {n:4d}  {reason}")
    if args.dry_run:
        return
    labels = json.load(open(LABELS, encoding="utf-8"))
    labels.update({n: "malicious" for n in added})
    json.dump(labels, open(LABELS, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump({"rules": "see add_test_samples.py", "decisions": decisions}, open(OUT, "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)
    print(f"[+] {OUT} and expected_labels.json updated")


if __name__ == "__main__":
    main()

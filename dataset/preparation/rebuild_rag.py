"""
rebuild_rag.py

One driver for the whole malware-RAG rebuild, in the right order, with backups and a
sanity report. Run after the static analysis (dataset/analyzed_chains/ must hold the chains).

  0. backup: small json files are copied to _backup_rag_rebuild/<stamp>/ ; the old
     directories are RENAMED (instant) to *_old : final_diverse_subset, rag_train,
     rag_test, indexes/rag_index
  1. backfill_osv_descriptions.py   (PEP 503 name normalisation, fills empty descriptions)
  2. attack_type_tagger.py          (tags + campaign signatures come from the descriptions)
  3. build_final_dataset.py         (balanced subset from analyzed_chains)
  4. split_train_test.py            (campaign-level split, seed 42)
  5. build_rag_index.py             (venv python: needs sentence_transformers)
  6. sanity report: train/test disjoint, index built only from train, description coverage

Usage: python3 dataset/preparation/rebuild_rag.py [--dry-run] [--from-step N] [--skip-check]
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "dataset")
PREP = os.path.join(DS, "preparation")
VENV_PY = os.path.join(ROOT, "venv", "bin", "python")

STEPS = [
    ("backfill descriptions", sys.executable, "backfill_osv_descriptions.py"),
    ("attack-type tags + campaigns", sys.executable, "attack_type_tagger.py"),
    ("final diverse subset", sys.executable, "build_final_dataset.py"),
    ("train/test split", sys.executable, "split_train_test.py"),
    ("RAG index", VENV_PY, "build_rag_index.py"),
]
SMALL_FILES = ["malware_dataset_matched.json", "attack_type_tags.json", "final_dataset_report.json",
               "final_diverse_subset_packages.json", "skipped_oversized_packages.json"]
RENAME = ["final_diverse_subset", "rag_train", "rag_test", os.path.join("indexes", "rag_index")]


def busy():
    out = subprocess.run("ps -eo command | grep -E 'rerun_chains|fetch_benign|codeql_pipeline/analysis|batch_analyzer' | grep -v grep",
                         shell=True, capture_output=True, text=True).stdout.strip()
    return [l[:90] for l in out.splitlines() if "rebuild_rag" not in l]


def backup(dry):
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bdir = os.path.join(DS, "_backup_rag_rebuild", stamp)
    for d in RENAME:
        if os.path.exists(os.path.join(DS, d + "_old")):
            sys.exit(f"refusing: {d}_old already exists (a previous rebuild's backup) - move it away first")
    print(f"[0] backup -> {bdir} ; rename {', '.join(d + ' -> ' + d + '_old' for d in RENAME)}")
    if dry:
        return
    os.makedirs(bdir)
    for f in SMALL_FILES:
        if os.path.exists(os.path.join(DS, f)):
            shutil.copy2(os.path.join(DS, f), bdir)
    for d in RENAME:
        if os.path.exists(os.path.join(DS, d)):
            os.rename(os.path.join(DS, d), os.path.join(DS, d + "_old"))


def sync_expected_labels(dry):
    """
    Το split αλλάζει τη σύνθεση του rag_test, αλλά κανένα άλλο script δεν ενημερώνει τα
    malicious labels του expected_labels.json - πακέτα χωρίς label δεν βαθμολογούνται
    καθόλου (σιωπηλά) στο check_test_set.py. Εδώ: κάθε πακέτο του rag_test -> "malicious",
    malicious labels πακέτων που δεν είναι πια στο rag_test αφαιρούνται, τα benign μένουν.
    """
    path = os.path.join(ROOT, "expected_labels.json")
    labels = json.load(open(path)) if os.path.exists(path) else {}
    test = {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(DS, "rag_test", "*.json"))}
    conflicts = sorted(p for p in test if labels.get(p) == "benign")
    stale = [p for p, v in labels.items() if v == "malicious" and p not in test]
    added = [p for p in test if labels.get(p) != "malicious"]
    print(f"\n[labels] rag_test {len(test)} | +{len(added)} malicious | -{len(stale)} stale malicious | "
          f"benign kept {sum(v == 'benign' for v in labels.values())}")
    if conflicts:
        print(f"[labels] ΠΡΟΣΟΧΗ: {len(conflicts)} πακέτα του rag_test είχαν label benign: {conflicts[:10]}")
    # Τα benign ορίζονται από τον φάκελο dataset/benign_test_set/ και ΔΕΝ αντικαθίστανται ποτέ
    # (π.χ. το νόμιμο requests είχε γίνει "malicious" λόγω συνονόματου malware - 2026-09-24).
    benign = {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(DS, "benign_test_set", "*.json"))}
    if test & benign:
        raise SystemExit(f"[labels] ΣΥΓΚΡΟΥΣΗ ονομάτων rag_test/benign_test_set: {sorted(test & benign)[:10]}")
    if dry:
        return
    for p in stale:
        del labels[p]
    for p in test:
        labels[p] = "malicious"
    for p in benign:
        labels[p] = "benign"
    json.dump(labels, open(path, "w"), indent=2, ensure_ascii=False)


def sanity():
    names = lambda d: {os.path.basename(f)[:-5] for f in glob.glob(os.path.join(DS, d, "*.json"))}
    train, test = names("rag_train"), names("rag_test")
    meta = json.load(open(os.path.join(DS, "indexes", "rag_index", "metadata.json")))
    idx_pk = {m["package"] for m in meta}
    matched = {i["package_name"]: i for i in json.load(open(os.path.join(DS, "malware_dataset_matched.json")))}
    nodesc = lambda S: sum(1 for p in S if not (matched.get(p, {}).get("description") or "").strip())
    print("\n=== sanity report ===")
    print(f"rag_train {len(train)} | rag_test {len(test)} | index chunks {len(meta)} from {len(idx_pk)} packages")
    print(f"train/test overlap: {len(train & test)} (must be 0) | index packages outside train: {len(idx_pk - train)} (must be 0)")
    print(f"no description: train {nodesc(train)}/{len(train)} | test {nodesc(test)}/{len(test)}")
    bad = sum(1 for f in glob.glob(os.path.join(DS, "rag_train", "*.json")) if b"ControlFlowNode for " in open(f, "rb").read())
    print(f"rag_train files still containing 'ControlFlowNode for': {bad} (must be 0)")
    ok = not (train & test) and not (idx_pk - train) and bad == 0
    print("RESULT:", "OK" if ok else "PROBLEM - inspect above")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--from-step", type=int, default=0)
    ap.add_argument("--skip-check", action="store_true")
    args = ap.parse_args()

    chains_dir = os.path.join(DS, "analyzed_chains")
    if not args.skip_check and not (os.path.isdir(chains_dir) and any(f.endswith(".json") for f in os.listdir(chains_dir))):
        sys.exit("dataset/analyzed_chains/ is missing or empty - run the static analysis first (or --skip-check)")
    if busy() and not args.dry_run:
        sys.exit("pipeline still running:\n  " + "\n  ".join(busy()))
    if args.from_step == 0:
        backup(args.dry_run)
    for i, (name, py, script) in enumerate(STEPS, 1):
        if i < args.from_step:
            continue
        print(f"\n[{i}] {name}: {os.path.basename(py)} {script}")
        if args.dry_run:
            continue
        t0 = time.time()
        r = subprocess.run([py, script], cwd=PREP)
        print(f"    ({time.time() - t0:.0f}s, exit {r.returncode})")
        if r.returncode != 0:
            sys.exit(f"step {i} failed - fix and resume with --from-step {i}")
    sync_expected_labels(args.dry_run)
    if not args.dry_run:
        sanity()


if __name__ == "__main__":
    main()

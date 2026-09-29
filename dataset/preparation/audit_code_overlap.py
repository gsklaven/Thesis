"""
audit_code_overlap.py - code overlap between the evaluation malware WITHOUT Behavior Chains and the index.

The family split (split_train_test.py) keeps packages with the same payload signature or campaign on the
same side. The payload signature is built from the Behavior Chains, so it is not defined for a package
that produced none; for those packages this audit compares the code files directly: every code file of
at least MIN_CHARS non-whitespace characters is hashed independently of formatting (all whitespace
removed) and looked up among the code files of every index (rag_train) package.

Archives inside a sample are read in memory; nothing is extracted to disk or executed.

Usage: python3 dataset/preparation/audit_code_overlap.py [--out dataset/audit_code_overlap.json]
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zipfile
import zlib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "dataset")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import resolve_source_path  # noqa: E402
import rerun_chains as rc  # noqa: E402

CODE = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".pth")
ARCHIVES = (".tar.gz", ".tgz", ".tar", ".zip", ".whl", ".egg")
MIN_CHARS = 200          # tiny files (empty __init__.py, one-line stubs) are shared by everything
MAX_MEMBER = 5_000_000   # archive members larger than this are skipped
MAX_FILE = 50_000_000


def norm_hash(data):
    """SHA-256 of the file without any whitespace (None for files shorter than MIN_CHARS)."""
    text = re.sub(rb"\s+", b"", data)
    return hashlib.sha256(text).hexdigest() if len(text) >= MIN_CHARS else None


def handle(data, name, out, depth=0):
    if name.endswith(CODE):
        h = norm_hash(data)
        if h:
            out.add(h)
    elif name.endswith(ARCHIVES) and depth <= 2:
        walk_archive(data, name, out, depth)


def walk_archive(data, name, out, depth):
    try:
        if name.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.isfile() and m.size < MAX_MEMBER:
                        f = t.extractfile(m)
                        if f:
                            handle(f.read(), m.name, out, depth + 1)
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    if not n.endswith("/") and z.getinfo(n).file_size < MAX_MEMBER:
                        handle(z.read(n), n, out, depth + 1)
    # corrupt, truncated or password-protected archives (RuntimeError) are skipped
    except (tarfile.TarError, zipfile.BadZipFile, zlib.error, OSError, EOFError, ValueError, RuntimeError,
            NotImplementedError):
        pass


def package_hashes(src):
    """Normalised hashes of the code files of one sample (folder or archive)."""
    root = rc.pick_analysis_root(resolve_source_path(src))
    out = set()
    if os.path.isfile(root):
        with open(root, "rb") as f:
            handle(f.read(), root, out)
        return out
    for d, _, files in os.walk(root):
        for name in files:
            p = os.path.join(d, name)
            if os.path.getsize(p) < MAX_FILE:
                with open(p, "rb") as f:
                    handle(f.read(), name, out)
    return out


def names(d):
    return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json") and not f.startswith("_"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=os.path.join(DS, "audit_code_overlap.json"))
    args = ap.parse_args()

    # source path of every sample: the known samples, then the matched dataset for the rest
    with open(os.path.join(DS, "v12_known_samples.json"), encoding="utf-8") as f:
        paths = json.load(f)["source_code_path"]
    with open(os.path.join(DS, "malware_dataset_matched.json"), encoding="utf-8") as f:
        for e in json.load(f):
            if e.get("package_name") and e.get("source_code_path"):
                paths.setdefault(e["package_name"], e["source_code_path"])

    test_dir, train_dir = os.path.join(DS, "rag_test"), os.path.join(DS, "rag_train")
    no_chains = []
    for n in names(test_dir):
        with open(os.path.join(test_dir, n + ".json"), encoding="utf-8") as f:
            if not json.load(f).get("behavior_chains"):
                no_chains.append(n)
    print(f"[*] evaluation malware without Behavior Chains: {len(no_chains)}", flush=True)
    test = {n: package_hashes(paths[n]) for n in no_chains if n in paths}
    missing = [n for n in no_chains if n not in paths]
    for n, h in test.items():
        print(f"    {n}: {len(h)} code files >= {MIN_CHARS} characters", flush=True)

    train = names(train_dir)
    shared, skipped = {}, []
    for i, n in enumerate(train, 1):
        if n not in paths:
            skipped.append(n)
            continue
        try:
            h = package_hashes(paths[n])
        except OSError as e:
            print(f"    skip {n}: {e}", flush=True)
            skipped.append(n)
            continue
        for t, th in test.items():
            common = th & h
            if common:
                with open(os.path.join(train_dir, n + ".json"), encoding="utf-8") as f:
                    index_chains = len(json.load(f).get("behavior_chains", []))
                shared.setdefault(t, []).append({"index_package": n, "shared_files": len(common),
                                                 "code_files": len(th), "index_package_chains": index_chains})
        if i % 200 == 0:
            print(f"    {i}/{len(train)} index packages scanned", flush=True)

    result = {"min_chars": MIN_CHARS, "evaluation_packages_without_chains": no_chains,
              "without_source_path": missing, "index_packages": len(train),
              "index_packages_skipped": skipped, "shared": shared}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[*] {len(shared)} of {len(test)} packages share a code file with the index -> {args.out}")
    for t, rows in shared.items():
        for r in rows:
            print(f"    {t} <-> {r['index_package']}: {r['shared_files']}/{r['code_files']} files "
                  f"(index package with {r['index_package_chains']} Behavior Chains)")


if __name__ == "__main__":
    main()

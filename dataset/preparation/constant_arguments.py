"""
constant_arguments.py - add the constant arguments of the calls (constant_args_py.ql) to Behavior Chains
built before that query existed, WITHOUT re-running the other CodeQL queries.

For every package file of the given folders: the source is prepared exactly as for the original analysis
(same root folder, so that the file paths of the chains match), a CodeQL database is created and only
constant_args_py.ql is run; its rows are attached to the stored chains by file and line
(build_behavior_chain.attach_constant_arguments) and "constant_arguments_source" records the run.
Packages analysed with the current pipeline already have the arguments and are skipped, so the script is
resumable. Only the packages that are EVALUATED need it: the LLM never reads the chains of the index.

Source of each package:
  - malware: the sample (v12_known_samples.json, else malware_dataset_matched.json), staged like
    rerun_chains.py does (latest version of multi-version samples, archives extracted, site-packages root);
  - benign: the same distribution file of the same release (benign_source), downloaded from PyPI;
  - obfuscated copies: THESIS_SOURCES_DIR/obfuscated/<level>/<package> (copied into the work folder).

Usage: python3 dataset/preparation/constant_arguments.py [--shard I/N] FOLDER [FOLDER ...]
"""
import argparse
import json
import os
import shutil
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PIPE = os.path.join(ROOT, "inference", "codeql_pipeline")
sys.path.insert(0, HERE)
sys.path.insert(0, PIPE)
import batch_analyzer as ba  # noqa: E402
import rerun_chains as rc  # noqa: E402
from utils import SOURCES_DIR, resolve_source_path  # noqa: E402
import analysis  # noqa: E402  (run_codeql: the same database settings and timeouts as the full analysis)
from build_behavior_chain import attach_constant_arguments  # noqa: E402

QUERY = os.path.join(PIPE, "python_queries", "constant_args_py.ql")
WORK = os.path.join(ROOT, "work", "constargs")


def malware_paths():
    paths = json.load(open(os.path.join(ROOT, "dataset", "v12_known_samples.json"), encoding="utf-8"))["source_code_path"]
    for item in json.load(open(os.path.join(ROOT, "dataset", "malware_dataset_matched.json"), encoding="utf-8")):
        if item.get("package_name") and item.get("source_code_path"):
            paths.setdefault(item["package_name"], item["source_code_path"])
    return paths


def prepare(name, data, work, paths):
    """Folder to analyse, laid out exactly like the original analysis of this package."""
    origin = data.get("obfuscated_from")
    if origin:
        src = os.path.join(SOURCES_DIR, "obfuscated", origin["level"], origin["package"])
        dest = os.path.join(work, "obf", origin["package"])
        shutil.copytree(src, dest)
        return dest
    if "benign_source" in data:
        prov = data["benign_source"]
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{prov['version']}/json", timeout=60) as r:
            url = next(u["url"] for u in json.load(r)["urls"] if u["filename"] == prov["filename"])
        dest = os.path.join(work, "extracted")
        os.makedirs(dest)
        with urllib.request.urlopen(url, timeout=300) as r, open(os.path.join(dest, prov["filename"]), "wb") as out:
            shutil.copyfileobj(r, out)
        ba.extract_archives(dest)
        return dest
    src = rc.pick_analysis_root(resolve_source_path(paths[name]))
    dest = os.path.join(work, "stage")
    ba.copy_recursive(src, dest)
    ba.extract_archives(dest)
    return rc.site_packages_root(dest)


def process(path, paths, work):
    """Run constant_args_py.ql for one package file and attach the rows; returns a short status."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    data = json.loads(raw)
    chains = data.get("behavior_chains", [])
    if not chains or all("constant_arguments" in c for c in chains):
        return "skipped"
    name = os.path.basename(path)[:-5]
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    target = prepare(name, data, work, paths)
    csv_path = os.path.join(work, "constant_args_python.csv")
    analysis.run_codeql(target, [(QUERY, csv_path)], language="python")
    import csv
    with open(csv_path, encoding="utf-8") as f:
        rows = [tuple(x.strip() for x in r[:5]) for r in list(csv.reader(f))[1:] if len(r) >= 5]
    attach_constant_arguments(chains, rows)
    files = {r[0] for r in rows}
    anchors_in_db = sum(c.get("location", "").rpartition(":")[0] in files for c in chains)
    data["constant_arguments_source"] = {
        "query": "constant_args_py.ql (added to existing chains by constant_arguments.py)",
        "rows": len(rows), "chains_with_arguments": sum(bool(c["constant_arguments"]) for c in chains),
        "anchor_files_found": f"{anchors_in_db}/{len(chains)}"}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4 if raw.startswith("{\n") else None, ensure_ascii=False)
    shutil.rmtree(work, ignore_errors=True)
    return f"ok ({data['constant_arguments_source']['chains_with_arguments']}/{len(chains)} chains)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folders", nargs="+")
    ap.add_argument("--shard", default="0/1", help="I/N: every N-th package starting at I (parallel workers)")
    args = ap.parse_args()
    i, n = map(int, args.shard.split("/"))
    files = sorted(os.path.join(d, f) for d in args.folders for f in os.listdir(d)
                   if f.endswith(".json") and not f.startswith("_"))[i::n]
    paths = malware_paths()
    work = os.path.join(WORK, f"w{i}")
    failed = {}
    for k, path in enumerate(files, 1):
        try:
            status = process(path, paths, work)
        except Exception as e:  # one package must not stop the shard; it is retried on the next run
            status = f"failed: {e}"
            failed[path] = str(e)[:300]
        print(f"[{k}/{len(files)}] {os.path.basename(path)}: {status}", flush=True)
    os.makedirs(WORK, exist_ok=True)
    with open(os.path.join(WORK, f"failed_w{i}.json"), "w", encoding="utf-8") as f:
        json.dump(failed, f, indent=1)
    print(f"done: {len(files) - len(failed)} ok/skipped, {len(failed)} failed")


if __name__ == "__main__":
    main()

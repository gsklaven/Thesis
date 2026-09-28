"""
build_obfuscated_set.py - obfuscated copies of evaluation packages, to measure robustness to obfuscation.

A seeded random sample of N malicious packages (rag_test/) and N benign packages (benign_test_set/) is
obfuscated with Intensio-Obfuscator (the tool used for the obfuscated set of IntelGuard) at two levels:
  A  -rts -ps        identifiers renamed to random strings + padding with dead code (junk branches/loops):
                     the data flow is intact, only names and surrounding control flow change;
  B  -rts -ps -rth   A + every file turned into a hex-encoded string that is executed with exec(): the
                     static analysis no longer sees the logic of the code.
Each copy goes through the SAME CodeQL pipeline as every other package and is stored as
dataset/obfuscated/<LEVEL>_<malware|benign>/<package>--obf<LEVEL>.json, with "obfuscated_from" (original
package, label, level, version) and its label in expected_labels.json. The obfuscated sources stay under
THESIS_SOURCES_DIR/obfuscated/ (never executed, never published).

Only packages with at least one Behavior Chain and a chains file of at most MAX_CHAINS_MB are sampled, so
that the effect of the obfuscation is measurable and the analysis stays fast. Benign packages are
re-downloaded from PyPI at exactly the analysed release (benign_source). Resumable: finished copies are
skipped. Run after the benign set is complete (the sample is drawn from it).

Setup (once): git clone https://github.com/Hnfull/Intensio-Obfuscator work/tools/Intensio-Obfuscator
              python3 -m venv work/tools/intensio-venv
              work/tools/intensio-venv/bin/pip install -r work/tools/Intensio-Obfuscator/requirements.txt
Usage: python3 dataset/preparation/build_obfuscated_set.py [--n 100] [--levels A B] [--pipeline-dir DIR]
"""
import argparse
import ast
import json
import os
import random
import shutil
import subprocess
import sys
import urllib.request
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("CODEQL_NO_VENDOR", "1")  # as in run_pipeline.sh: package code only
import batch_analyzer as ba  # noqa: E402
import fetch_benign_test_set as fb  # noqa: E402
from utils import SOURCES_DIR, resolve_source_path  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "dataset")
TOOL = os.path.join(ROOT, "work", "tools", "Intensio-Obfuscator", "src", "intensio_obfuscator")
TOOL_PY = os.path.join(ROOT, "work", "tools", "intensio-venv", "bin", "python")
LEVELS = {"A": ["-rts", "-ps"], "B": ["-rts", "-ps", "-rth"]}
SEED, MAX_CHAINS_MB = 42, 5
WORK = os.path.join(ROOT, "work", "obfuscation")
OBF_SOURCES = os.path.join(SOURCES_DIR, "obfuscated")
MANIFEST = os.path.join(DS, "obfuscated_set.json")
LABELS = os.path.join(ROOT, "expected_labels.json")


def eligible(folder):
    """Packages of a set with at least one Behavior Chain and a chains file of at most MAX_CHAINS_MB."""
    out = []
    for f in sorted(os.listdir(folder)):
        path = os.path.join(folder, f)
        if f.endswith(".json") and not f.startswith("_") and os.path.getsize(path) <= MAX_CHAINS_MB * 1e6:
            data = json.load(open(path, encoding="utf-8"))
            if data.get("behavior_chains"):
                out.append((f[:-5], data.get("benign_source", {}).get("version")))
    return out


def fetch_original(name, label, version, dest):
    """Copy (malware) or download (benign, exact release) the original package into dest and extract it."""
    os.makedirs(dest)
    if label == "malicious":
        src = resolve_source_path(json.load(open(os.path.join(DS, "v12_known_samples.json"),
                                                 encoding="utf-8"))["source_code_path"][name])
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(dest, "src"))
        else:
            shutil.copy2(src, dest)
    else:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=60) as r:
            files = [u for u in json.load(r).get("urls", []) if not u.get("yanked")]
        sdists = [u for u in files if u["packagetype"] == "sdist"]
        wheels = sorted((u for u in files if u["packagetype"] == "bdist_wheel"),
                        key=lambda u: ("none-any" not in u["filename"], u["filename"]))
        pick = (sdists or wheels)[0]
        with urllib.request.urlopen(pick["url"], timeout=300) as r, open(os.path.join(dest, pick["filename"]), "wb") as out:
            shutil.copyfileobj(r, out)
    ba.extract_archives(dest)


def obfuscate(src, out, level):
    """Run Intensio-Obfuscator; returns (ok, number of .py files that no longer parse)."""
    res = subprocess.run([TOOL_PY, "intensio_obfuscator.py", "-i", src, "-o", out, "-mlen", "lower", "-ind", "4",
                          *LEVELS[level]], cwd=TOOL, capture_output=True, text=True, timeout=600)
    if res.returncode != 0 or not os.path.isdir(out):
        return False, None
    broken = 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for root, _, files in os.walk(out):
            for f in files:
                if f.endswith(".py"):
                    try:
                        ast.parse(open(os.path.join(root, f), encoding="utf-8", errors="replace").read())
                    except (SyntaxError, ValueError):
                        broken += 1
    return True, broken


def private_pipeline(path):
    """A private copy of inference/codeql_pipeline (own results/), like run_pipeline.sh setup_worker."""
    if not os.path.isdir(path):
        shutil.copytree(os.path.join(ROOT, "inference", "codeql_pipeline"), path,
                        ignore=shutil.ignore_patterns("results", "__pycache__", ".DS_Store"))
    os.makedirs(os.path.join(path, "results"), exist_ok=True)
    fb.PIPELINE_DIR = path
    fb.PIPELINE_RESULTS_DIR = os.path.join(path, "results")
    fb.ANALYSIS_SCRIPT = os.path.join(path, "analysis.py")
    fb.BUILD_SCRIPT = os.path.join(path, "build_behavior_chain.py")
    fb.RESULTS_JSON = os.path.join(fb.PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100, help="packages per class")
    ap.add_argument("--levels", nargs="+", default=list(LEVELS), choices=list(LEVELS))
    ap.add_argument("--pipeline-dir", default=os.path.join(WORK, "pipeline"))
    args = ap.parse_args()
    if not os.path.exists(TOOL_PY):
        sys.exit(f"Intensio-Obfuscator is not set up - see the docstring ({TOOL_PY} missing)")
    private_pipeline(args.pipeline_dir)

    rng = random.Random(SEED)
    sample = {"malicious": rng.sample(eligible(os.path.join(DS, "rag_test")), args.n),
              "benign": rng.sample(eligible(os.path.join(DS, "benign_test_set")), args.n)}
    manifest = json.load(open(MANIFEST, encoding="utf-8")) if os.path.exists(MANIFEST) else {"results": {}}
    commit = subprocess.run(["git", "-C", os.path.dirname(os.path.dirname(TOOL)), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    manifest.update({"tool": f"Intensio-Obfuscator {commit}", "levels": LEVELS, "seed": SEED,
                     "max_chains_mb": MAX_CHAINS_MB, "sample": {k: [n for n, _ in v] for k, v in sample.items()}})
    labels = json.load(open(LABELS, encoding="utf-8"))

    for label, pkgs in sample.items():
        for name, version in pkgs:
            orig = os.path.join(WORK, "src", name)
            for level in args.levels:
                obf_name = f"{name}--obf{level}"
                out_dir = os.path.join(DS, "obfuscated", f"{level}_" + ("malware" if label == "malicious" else "benign"))
                dest = os.path.join(out_dir, f"{obf_name}.json")
                if os.path.exists(dest):
                    continue
                print(f"\n=== {obf_name} ({label}) ===")
                try:
                    if not os.path.isdir(orig):
                        fetch_original(name, label, version, orig)
                    obf_src = os.path.join(OBF_SOURCES, level, name)
                    if os.path.exists(obf_src):
                        shutil.rmtree(obf_src)
                    os.makedirs(os.path.dirname(obf_src), exist_ok=True)
                    ok, broken = obfuscate(orig, obf_src, level)
                    if not ok:
                        manifest["results"][obf_name] = "obfuscation failed"
                        continue
                    fb.TEST_SET_DIR = out_dir
                    if not fb.run_codeql_pipeline(obf_name, obf_src):
                        manifest["results"][obf_name] = "static analysis failed"
                        continue
                    data = json.load(open(dest, encoding="utf-8"))
                    data["obfuscated_from"] = {"package": name, "label": label, "level": level, "version": version}
                    json.dump(data, open(dest, "w", encoding="utf-8"), indent=4, ensure_ascii=False)
                    labels[obf_name] = label
                    manifest["results"][obf_name] = {"chains": len(data.get("behavior_chains", [])),
                                                     "unparsable_py_files": broken}
                except Exception as e:  # one package must not stop the whole set
                    manifest["results"][obf_name] = f"error: {e}"
                finally:
                    json.dump(manifest, open(MANIFEST, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
                    json.dump(labels, open(LABELS, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    done = [k for k, v in manifest["results"].items() if isinstance(v, dict)]
    print(f"\n[+] {len(done)} obfuscated packages analysed; manifest -> {MANIFEST}")


if __name__ == "__main__":
    main()

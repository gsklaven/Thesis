"""
dependency_findings.py - interpackage analysis of the evaluation sets (inference/dependency_check.py).

For every package file of the given folders, the dependencies the package declares and the known malicious
packages in its dependency graph are written into the file ("declared_dependencies",
"dependency_findings", "dependency_registry"). llm_evaluator.py copies the findings into the report and
derives final_verdict_with_dependencies; the LLM verdict on the package's own code is not affected.

Where the declared dependencies come from:
  - malware samples: the sample's own files (source_code_path in malware_dataset_matched.json, under
    THESIS_SOURCES_DIR);
  - benign packages: the PyPI metadata (Requires-Dist) of exactly the analysed release (benign_source);
  - obfuscated copies (build_obfuscated_set.py): the original package - obfuscation does not change the
    dependencies.
A package whose dependencies cannot be read is marked as not checked (dependency_findings = null).
Re-running recomputes everything (the registries may have been updated in the meantime) - including after
new verdicts of this system, which also re-checks the packages that depend on a newly flagged package.

--own-verdicts DIR...: also use the packages this system has judged MALICIOUS (reports in DIR) as a
second registry (see inference/dependency_check.py).

Usage: python3 dataset/preparation/dependency_findings.py dataset/rag_test [...] [--own-verdicts results/v12_sum]
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "inference"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dependency_check as dc  # noqa: E402
from utils import resolve_source_path  # noqa: E402


def malware_sources():
    """{package: local path of the sample}: malware_dataset_matched.json, completed with the paths of the
    v12 snapshot (v12_known_samples.json) for samples that a later `collect` no longer lists."""
    paths = {}
    snapshot = os.path.join(ROOT, "dataset", "v12_known_samples.json")
    if os.path.exists(snapshot):
        paths.update(json.load(open(snapshot, encoding="utf-8")).get("source_code_path", {}))
    with open(os.path.join(ROOT, "dataset", "malware_dataset_matched.json"), encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else list(data.values())
    paths.update({x["package_name"]: x["source_code_path"] for x in items
                  if x.get("package_name") and x.get("source_code_path")})
    return {name: resolve_source_path(p) for name, p in paths.items()}


def declared(name, label, version, sources):
    """Declared dependencies of a package ({name: pin}), or None if they cannot be read."""
    if label == "benign":
        return dc.pypi_requires(name, version) if version else None
    path = sources.get(name)
    return dc.declared_dependencies(path) if path and os.path.exists(path) else None


def registry_commit():
    """Commit of the local OSV malicious-packages clone (which registry state was used)."""
    repo = os.path.abspath(os.path.join(dc.OSV_DIR, "..", "..", ".."))
    r = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True)
    return r.stdout.strip() or None


def main(folders, own_verdicts=()):
    sources = malware_sources()
    registry = {"source": "OpenSSF malicious-packages (OSV)", "commit": registry_commit()}
    if own_verdicts:
        n = len(dc.load_own_verdicts(own_verdicts))
        registry["own_verdicts"] = {"dirs": list(own_verdicts), "malicious_packages": n}
    for folder in folders:
        n = checked = 0
        flagged = []
        is_benign_set = "benign" in os.path.basename(os.path.normpath(folder))
        for fname in sorted(os.listdir(folder)):
            if not fname.endswith(".json") or fname.startswith("_"):
                continue
            path = os.path.join(folder, fname)
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(raw)
            origin = data.get("obfuscated_from")
            if origin:  # an obfuscated copy: the dependencies of the original package
                name, label, version = origin["package"], origin["label"], origin.get("version")
            else:
                name = fname[:-5]
                label = "benign" if (is_benign_set or "benign_source" in data) else "malicious"
                version = data.get("benign_source", {}).get("version")
            deps = declared(name, label, version, sources)
            findings = dc.check(name, deps) if deps is not None else None
            data["declared_dependencies"] = deps
            data["dependency_findings"] = findings
            data["dependency_registry"] = registry
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4 if raw.startswith("{\n") else None, ensure_ascii=False)
            n += 1
            checked += deps is not None
            if findings:
                flagged.append((fname[:-5], [x["dependency"] for x in findings]))
        print(f"{folder}: {n} packages, dependencies read for {checked}, "
              f"{len(flagged)} with a malicious package in the dependency graph")
        for p, deps in flagged:
            print(f"   {p}: {', '.join(deps)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folders", nargs="+", help="folders of package chains files")
    ap.add_argument("--own-verdicts", nargs="*", default=[], help="results folders with this system's reports")
    args = ap.parse_args()
    main(args.folders, args.own_verdicts)

"""
patch_zero_chains.py

One-off script to retroactively apply the heuristic scanner to all packages
in analyzed_chains/ that currently have total_behavior_chains == 0.

batch_analyzer.py skips already-processed packages, so those 59 zero-chain
results will never be re-run automatically. This script finds them, locates
their original source code via the dataset JSON, and runs the heuristic
scanner. If patterns are found, the analyzed_chains/ JSON is updated in place.

Usage:
    python3 dataset/preparation/patch_zero_chains.py [--dry-run]
"""
import json
import os
import sys
import glob

# ── Allow importing heuristic_scanner from the pipeline dir ─────────────────
_THESIS_ROOT   = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
_PIPELINE_DIR  = os.path.join(_THESIS_ROOT, "inference", "codeql_pipeline")
sys.path.insert(0, _PIPELINE_DIR)
import heuristic_scanner                             # noqa: E402

_DATASET_DIR    = os.path.join(_THESIS_ROOT, "dataset")
_CHAINS_DIR     = os.path.join(_DATASET_DIR, "analyzed_chains")
_DEDUPED_JSON   = os.path.join(_DATASET_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON   = os.path.join(_DATASET_DIR, "malware_dataset_matched.json")
_DATASET_JSON   = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

DRY_RUN = "--dry-run" in sys.argv


def load_source_paths() -> dict:
    """Return {package_name: source_code_path} from the dataset JSON."""
    if not os.path.exists(_DATASET_JSON):
        print(f"[!] Dataset JSON not found: {_DATASET_JSON}")
        return {}
    with open(_DATASET_JSON, "r", encoding="utf-8") as f:
        items = json.load(f)
    mapping = {}
    for item in items:
        name = item.get("package_name", "")
        src  = item.get("source_code_path", "")
        if name and src:
            mapping[name] = src
    return mapping


def find_zero_chain_files() -> list:
    """Return list of (json_path, package_name) for zero-chain results."""
    zero = []
    for path in sorted(glob.glob(os.path.join(_CHAINS_DIR, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        n = data.get("summary", {}).get("total_behavior_chains", -1)
        if n == 0:
            pkg = os.path.basename(path).replace(".json", "")
            zero.append((path, pkg))
    return zero


def main():
    print(f"[*] {'DRY RUN — ' if DRY_RUN else ''}patch_zero_chains.py")
    print(f"[*] Chains dir : {_CHAINS_DIR}")
    print(f"[*] Dataset    : {_DATASET_JSON}\n")

    source_paths = load_source_paths()
    if not source_paths:
        print("[!] Δεν βρέθηκαν source paths. Έλεγξε το dataset JSON.")
        sys.exit(1)

    zero_files = find_zero_chain_files()
    print(f"[*] Βρέθηκαν {len(zero_files)} πακέτα με 0 chains.\n")

    stats = {"patched": 0, "still_zero": 0, "no_src": 0}

    for chain_path, pkg_name in zero_files:
        src_path = source_paths.get(pkg_name)

        if not src_path or not os.path.isdir(src_path):
            print(f"  [?] {pkg_name:45s} — source path not found or missing: {src_path}")
            stats["no_src"] += 1
            continue

        result = heuristic_scanner.scan_package(src_path)
        n = result["summary"]["total_behavior_chains"]

        if n == 0:
            print(f"  [-] {pkg_name:45s} — heuristic: 0 patterns")
            stats["still_zero"] += 1
        else:
            cats = ", ".join(f"{k}:{v}" for k, v in result["summary"]["by_category"].items())
            print(f"  [+] {pkg_name:45s} — heuristic: {n} patterns ({cats})")
            if not DRY_RUN:
                with open(chain_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=4, ensure_ascii=False)
            stats["patched"] += 1

    print(f"\n[*] Αποτελέσματα:")
    print(f"    Patched  (heuristic chains added) : {stats['patched']}")
    print(f"    Still 0  (nothing found)           : {stats['still_zero']}")
    print(f"    No src   (source path missing)     : {stats['no_src']}")
    if DRY_RUN:
        print("\n    (Dry run — καμία αλλαγή έγινε στο disk)")


if __name__ == "__main__":
    main()

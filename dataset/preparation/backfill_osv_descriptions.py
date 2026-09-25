"""
Backfill of missing sample descriptions from the OSV reports.

Samples collected in bulk (e.g. from pypi_malregistry) have an EMPTY description. The OSV folder of
OpenSSF Malicious Packages covers many more package names than the initial matching did; when the SAME
(PEP 503-normalised) name exists in both, the real OSV summary/details are copied into the sample.
Only the metadata is enriched - the code of the sample is not touched (it is already analysed).

Input/output: dataset/malware_dataset_matched.json (updated in place).
OSV folder: THESIS_OSV_DIR, or <THESIS_SOURCES_DIR>/malicious-packages/osv/malicious/pypi.
"""

import json
import os
import sys
import re

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
DATASET_JSON = os.path.join(_THESIS_ROOT, "dataset", "malware_dataset_matched.json")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import SOURCES_DIR as _SOURCES  # noqa: E402  (also loads the .env)
# first existing OSV folder: explicit variable, the sources location, or a local download
OSV_DIR = os.environ.get("THESIS_OSV_DIR") or next(
    (d for d in (os.path.join(_SOURCES, "malicious-packages", "osv", "malicious", "pypi"),
                 os.path.expanduser("~/Downloads/malicious-packages/osv/malicious/pypi")) if os.path.isdir(d)),
    os.path.join(_SOURCES, "malicious-packages", "osv", "malicious", "pypi"))


def norm(name):
    """PEP 503 normalisation: Ailynitro == ailynitro, a_b == a-b."""
    return re.sub(r"[-_.]+", "-", name).lower()


def extract_description(pkg_folder):
    """Concatenated summary + details of every OSV report (JSON file) in a package's OSV folder."""
    texts = []
    for root, dirs, files in os.walk(pkg_folder):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            summary = data.get("summary", "") or ""
            details = data.get("details", "") or ""
            if summary:
                texts.append(summary)
            if details:
                texts.append(details)
    return " ".join(texts).strip()


def main():
    """Fill empty descriptions from OSV and rewrite the dataset file."""
    print("[*] Loading dataset...")
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    zero_desc_items = [item for item in dataset if not item.get("description", "").strip()]
    print(f"    {len(zero_desc_items)} packages with an empty description.")

    if not os.path.exists(OSV_DIR):
        print(f"[!] OSV folder not found: {OSV_DIR}")
        return

    # normalised name -> actual folder name in the OSV directory
    osv_map = {norm(n): n for n in os.listdir(OSV_DIR)}
    osv_names = set(osv_map)
    print(f"    {len(osv_names)} packages available in the OSV directory.\n")

    enriched, still_empty, lengths = 0, 0, []

    for item in zero_desc_items:
        pkg = item["package_name"]
        if norm(pkg) not in osv_names:
            still_empty += 1
            continue
        description = extract_description(os.path.join(OSV_DIR, osv_map[norm(pkg)]))
        if description:
            item["description"] = description
            item["description_backfilled_from"] = "osv_cross_reference"  # provenance of the text
            enriched += 1
            lengths.append(len(description))
        else:
            still_empty += 1

    print(f"[+] {enriched} packages enriched with a real OSV description.")
    print(f"[+] {still_empty} remain without a description (not in OSV either).")
    if lengths:
        import statistics
        print(f"[*] Mean length of the new descriptions: {statistics.mean(lengths):.0f} characters "
              f"(median: {statistics.median(lengths):.0f})")

    with open(DATASET_JSON, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Updated: {DATASET_JSON}")
    print("    Next step: python3 build_rag_index.py (rebuilds the index with the enriched data)")


if __name__ == "__main__":
    main()

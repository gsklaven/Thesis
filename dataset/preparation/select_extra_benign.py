"""
select_extra_benign.py

Reproducible selection of extra, TYPICAL (not hand-picked) small benign PyPI
packages for the benign test set.

Procedure (seeded, documented in the output JSON):
  1. Take the public top-PyPI-packages list (hugovk/top-pypi-packages, 30 days).
  2. Keep ranks RANK_MIN..RANK_MAX (popular enough to be certainly legitimate,
     not the giant well-known libraries already in the test set).
  3. Shuffle with SEED and walk the list; accept a package when:
       - its latest release ships a wheel/sdist of <= MAX_KB
       - it is NOT in malware_dataset_matched.json, NOT in the OSV malicious-PyPI
         list, NOT already in BENIGN_PACKAGES (fetch_benign_test_set.py)
  4. Stop at N packages.
Output: benign_extra_selection.json (read by fetch_benign_test_set.py).
"""
import json
import os
import sys
import random
import re
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign_extra_selection.json")
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import SOURCES_DIR  # noqa: E402  (also loads the .env)

OSV_DIR = os.environ.get("THESIS_OSV_DIR") or os.path.join(SOURCES_DIR, "malicious-packages", "osv", "malicious", "pypi")
# seed, number of packages, rank window of the top-PyPI list, maximum file size (KB)
SEED, N, RANK_MIN, RANK_MAX, MAX_KB = 42, 130, 300, 3000, 150

# PEP 503 name normalisation (a_b == a-b == A.B)
norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()


def get(url):
    """HTTP GET with a descriptive User-Agent; returns the body bytes."""
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "thesis-benign-selection"}), timeout=60).read()


def existing_benign():
    """Normalised names of the curated BENIGN_PACKAGES list, read from fetch_benign_test_set.py (without importing it)."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fetch_benign_test_set.py"), encoding="utf-8").read()
    block = src.split("BENIGN_PACKAGES = [")[1].split("]")[0]
    return {norm(p) for p in re.findall(r'"([A-Za-z0-9_.\-]+)"', block)}


def main():
    """Walk the shuffled rank window and keep the first N packages that pass the filters; write the selection with its parameters."""
    top = json.loads(get(TOP_URL))["rows"]
    cands = [(i + 1, r["project"]) for i, r in enumerate(top)][RANK_MIN - 1:RANK_MAX]
    malware = {norm(i["package_name"]) for i in json.load(open(os.path.join(ROOT, "dataset", "malware_dataset_matched.json"))) if i.get("package_name")}
    osv = {norm(n) for n in os.listdir(OSV_DIR)} if os.path.isdir(OSV_DIR) else set()
    have = existing_benign()
    random.Random(SEED).shuffle(cands)

    chosen, rejected = [], {"malware_or_osv_name": 0, "already_benign": 0, "too_big_or_no_files": 0, "api_error": 0}
    for rank, name in cands:
        if len(chosen) >= N:
            break
        n = norm(name)
        if n in malware or n in osv:
            rejected["malware_or_osv_name"] += 1
            continue
        if n in have:
            rejected["already_benign"] += 1
            continue
        try:
            info = json.loads(get(f"https://pypi.org/pypi/{name}/json"))
        except Exception:
            rejected["api_error"] += 1
            continue
        files = info.get("urls", [])
        # smallest pure-Python wheel, else smallest sdist (used only to judge the package size)
        wheels = [f for f in files if f["packagetype"] == "bdist_wheel" and f["filename"].endswith("none-any.whl")]
        pick = min(wheels or [f for f in files if f["packagetype"] == "sdist"] or [None], key=lambda f: f["size"] if f else 0)
        if not pick or pick["size"] > MAX_KB * 1024:
            rejected["too_big_or_no_files"] += 1
            continue
        chosen.append({"package": name, "rank": rank, "file": pick["filename"], "size_kb": round(pick["size"] / 1024, 1),
                       "version": info["info"]["version"], "summary": (info["info"].get("summary") or "")[:100]})
    out = {"method": "seeded random sample of top-PyPI ranks, filtered by size and by absence from malware/OSV lists",
           "seed": SEED, "rank_range": [RANK_MIN, RANK_MAX], "max_kb": MAX_KB, "rejected": rejected, "packages": chosen}
    json.dump(out, open(OUT, "w"), indent=2, ensure_ascii=False)
    print(f"[+] {len(chosen)} packages selected; rejected: {rejected}")
    for c in chosen:
        print(f"  #{c['rank']:<5d} {c['package']:32s} {c['size_kb']:6.1f} KB  {c['summary'][:60]}")


if __name__ == "__main__":
    main()

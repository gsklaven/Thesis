"""
Build the benign evaluation set: download LEGITIMATE PyPI packages, run the full CodeQL pipeline
(analysis.py + build_behavior_chain.py) on each, and store the result as
dataset/benign_test_set/<package>.json. Afterwards run:  python3 results/check_test_set.py dataset/benign_test_set

Two groups of packages:
  1. BENIGN_PACKAGES: a curated list chosen ON PURPOSE because they make heavy, legitimate use of
     "sensitive" APIs (subprocess, network, credentials) that could look suspicious to a shallow
     analysis - false-positive testing, not a random sample:
       paramiko (SSH / remote command execution), fabric (deployment tool, runs shell commands),
       psutil (system/process introspection), cryptography, boto3 (AWS credentials), requests
       (network), pyyaml (file parsing), numpy (large general-purpose library), and packages whose
       capabilities resemble malware patterns while being 100% legitimate: pyautogui (keyboard/mouse
       control, RAT-like), mss (screen capture), pyngrok (tunneling, like a C2 channel), keyring
       (credential store), python-dotenv (reads .env secrets), supervisor / pyinstaller / ansible /
       netmiko (heavy subprocess/SSH use), etc.
  2. The typical small packages of benign_extra_selection.json (seeded random sample of the top-PyPI
     list, see select_extra_benign.py).

Packages are downloaded directly from the PyPI JSON API (never installed, nothing is executed); the
source distribution (sdist) is preferred, see pick_distribution().
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import batch_analyzer as ba  # noqa: E402

# Printed by analysis.py when the CodeQL pass of a language fails (see run_codeql_pipeline()).
PY_SKIP_MARK = "Skipping language 'python'"

BENIGN_PACKAGES = [
    "paramiko", "fabric", "psutil", "cryptography",
    "boto3", "requests", "pyyaml", "numpy",
    "sh", "httpx", "jinja2", "sqlalchemy", "flask",
    "pyautogui", "mss", "pyngrok", "keyring", "python-dotenv",
    "supervisor", "pyinstaller", "ansible", "netmiko", "celery",
    "docker", "kubernetes", "selenium", "scrapy", "redis",
    "pymongo", "psycopg2", "pyjwt",
    "oauthlib", "google-auth", "pynacl", "virtualenv", "pytest",
    "watchdog", "websockets", "gunicorn", "paho-mqtt",
]

# Additional typical small benign packages - see select_extra_benign.py (seeded, reproducible).
_EXTRA_SELECTION = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign_extra_selection.json")
if os.path.exists(_EXTRA_SELECTION):
    with open(_EXTRA_SELECTION, "r", encoding="utf-8") as _f:
        BENIGN_PACKAGES += [p["package"] for p in json.load(_f)["packages"] if p["package"] not in BENIGN_PACKAGES]

BASE_DIR = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
# benign_downloads/: temporary work folder (download + extraction of each archive), recreated when needed.
DOWNLOAD_DIR = os.path.join(BASE_DIR, "benign_downloads")
TEST_SET_DIR = os.path.join(BASE_DIR, "dataset", "benign_test_set")
EXPECTED_LABELS_FILE = os.path.join(BASE_DIR, "expected_labels.json")

# CodeQL pipeline paths (can be redirected to a private copy with --pipeline-dir)
PIPELINE_DIR = os.path.join(BASE_DIR, "inference", "codeql_pipeline")
PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")
ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")

# intermediate CSV files of the pipeline, removed before each package
CSV_GLOB_PATTERNS = [
    "final_codeql_results_*.csv", "call_graph_*.csv",
    "backward_slice_*.csv", "control_deps_*.csv",
]


def clean_pipeline_results():
    """Remove the previous package's pipeline outputs, so they can never be attributed to the next one."""
    if os.path.exists(RESULTS_JSON):
        os.remove(RESULTS_JSON)
    for pattern in CSV_GLOB_PATTERNS:
        for f in glob.glob(os.path.join(PIPELINE_RESULTS_DIR, pattern)):
            os.remove(f)


def pick_distribution(pkg_name):
    """
    Choose WHICH file of the latest release is analysed, using the PyPI JSON API.
    The sdist (source code TOGETHER with setup.py) is preferred, like the malware samples (most of
    which have chains in setup.py): with wheels the benign set would contain no setup.py at all, i.e.
    no legitimate install-time code to judge. A wheel (pure-Python first) is used only if there is no
    sdist. Returns (url, filename, version, dist_type) or None.
    """
    with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg_name}/json", timeout=60) as r:
        meta = json.load(r)
    version = meta["info"]["version"]
    files = [u for u in meta.get("urls", []) if not u.get("yanked")]
    sdists = [u for u in files if u.get("packagetype") == "sdist"]
    wheels = [u for u in files if u.get("packagetype") == "bdist_wheel"]
    # platform-independent wheels ("none-any") first, then by name for determinism
    wheels.sort(key=lambda u: ("none-any" not in u["filename"], u["filename"]))
    choice = (sdists or wheels or [None])[0]
    if not choice:
        return None
    return choice["url"], choice["filename"], version, ("sdist" if sdists else "wheel")


def download_and_extract(pkg_name):
    """
    Download the archive DIRECTLY (no pip: `pip download` of an sdist runs its setup.py to obtain the
    metadata) and extract it with the same safe functions that the malware pipeline uses
    (batch_analyzer.extract_archives). Returns (extract_dir, provenance) or (None, None).
    """
    pkg_download_dir = os.path.join(DOWNLOAD_DIR, pkg_name)
    if os.path.exists(pkg_download_dir):
        shutil.rmtree(pkg_download_dir)
    extract_dir = os.path.join(pkg_download_dir, "extracted")
    os.makedirs(extract_dir)

    print(f"  [-] Downloading {pkg_name}...")
    try:
        picked = pick_distribution(pkg_name)
        if not picked:
            print(f"  [!] No distribution file on PyPI for {pkg_name}")
            return None, None
        url, filename, version, dist = picked
        with urllib.request.urlopen(url, timeout=300) as r, open(os.path.join(extract_dir, filename), "wb") as out:
            shutil.copyfileobj(r, out)
    except Exception as e:
        print(f"  [!] Download of {pkg_name} failed: {e}")
        return None, None

    print(f"  [-] Extracting {filename} ({dist})...")
    ba.extract_archives(extract_dir)
    # extraction replaces the archive with its contents; if it is still there, extraction failed
    if not any(os.scandir(extract_dir)) or os.path.exists(os.path.join(extract_dir, filename)):
        print(f"  [!] Extraction of {filename} failed")
        return None, None
    return extract_dir, {"version": version, "dist": dist, "filename": filename}


def run_codeql_pipeline(pkg_name, src_dir, provenance=None):
    """
    Run analysis.py + build_behavior_chain.py on src_dir and store the chains file in TEST_SET_DIR,
    with the provenance (version, sdist/wheel, file name) added as "benign_source". Returns True on success.
    """
    clean_pipeline_results()

    env = os.environ.copy()
    env["CODEQL_TARGET_DIR"] = src_dir

    print(f"  [-] CodeQL analysis...")
    try:
        # hard timeout: kills the WHOLE process group (including CodeQL's Java children)
        res1 = ba.run_with_hard_timeout(["python3", ANALYSIS_SCRIPT], cwd=PIPELINE_DIR, env=env,
                                        timeout=int(os.environ.get("BENIGN_ANALYSIS_TIMEOUT", "600")),
                                        capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout in analysis.py for {pkg_name}")
        return False
    print(res1.stdout or "", end="")
    if res1.returncode != 0:
        print(f"  [!] CodeQL error for {pkg_name}")
        return False
    # Same check as rerun_chains.py (malware): if the Python pass was skipped (timeout / query error)
    # although the package has .py files, the result is partial or empty - it is NOT stored,
    # otherwise it would count as a falsely "correct" benign package (0 chains).
    if PY_SKIP_MARK in (res1.stdout or "") and any(
            f.endswith(".py") for _, _, fs in os.walk(src_dir) for f in fs):
        print(f"  [!] The CodeQL Python pass was skipped for {pkg_name} - not stored")
        return False

    print(f"  [-] Building behavior chains...")
    try:
        res2 = ba.run_with_hard_timeout(["python3", BUILD_SCRIPT], cwd=PIPELINE_DIR,
                                        timeout=int(os.environ.get("BENIGN_BUILD_TIMEOUT", "180")))
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout (3 minutes) in build_behavior_chain.py for {pkg_name}")
        return False
    if res2.returncode != 0:
        print(f"  [!] Builder error for {pkg_name}")
        return False

    if not os.path.exists(RESULTS_JSON):
        print(f"  [!] No result was produced for {pkg_name}")
        return False

    os.makedirs(TEST_SET_DIR, exist_ok=True)
    dest = os.path.join(TEST_SET_DIR, f"{pkg_name}.json")
    shutil.copy2(RESULTS_JSON, dest)
    if provenance:  # which version / distribution type was analysed (reproducibility)
        with open(dest, encoding="utf-8") as f:
            data = json.load(f)
        data["benign_source"] = provenance
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"  [✓] {dest}")
    return True


def update_expected_labels():
    """Label every analysed benign package as 'benign' in expected_labels.json (other labels are kept)."""
    labels = {}
    if os.path.exists(EXPECTED_LABELS_FILE):
        with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
            labels = json.load(f)

    for pkg in BENIGN_PACKAGES:
        if os.path.exists(os.path.join(TEST_SET_DIR, f"{pkg}.json")):
            labels[pkg] = "benign"

    with open(EXPECTED_LABELS_FILE, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] expected_labels.json updated ({len(labels)} labels in total)")


def main():
    """Download + analyse every benign package (optionally one shard of the list), then update the labels."""
    global PIPELINE_DIR, PIPELINE_RESULTS_DIR, ANALYSIS_SCRIPT, BUILD_SCRIPT, RESULTS_JSON

    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", help="I/N: process only every N-th package, starting at I (0-based) "
                    "- for parallel workers over the same list.")
    ap.add_argument("--pipeline-dir", help="private copy of inference/codeql_pipeline/ (with its own results/), "
                    "so that parallel workers do not interfere.")
    args = ap.parse_args()

    if args.pipeline_dir:
        PIPELINE_DIR = args.pipeline_dir
        PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")
        ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
        BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
        RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")
        os.makedirs(PIPELINE_RESULTS_DIR, exist_ok=True)

    packages = BENIGN_PACKAGES
    if args.shard:
        i, n = map(int, args.shard.split("/"))
        packages = packages[i::n]

    print(f"[*] {len(packages)} benign packages to analyse: {packages}")

    succeeded, failed = [], []
    for pkg in packages:
        print(f"\n{'=' * 60}\n=== {pkg} ===\n{'=' * 60}")

        # resumable: packages with an existing result are skipped
        dest = os.path.join(TEST_SET_DIR, f"{pkg}.json")
        if os.path.exists(dest):
            print(f"  [*] Skipped (already exists): {pkg}")
            succeeded.append(pkg)
            continue

        try:
            src_dir, prov = download_and_extract(pkg)
            if not src_dir:
                failed.append(pkg)
                continue

            if run_codeql_pipeline(pkg, src_dir, prov):
                succeeded.append(pkg)
            else:
                failed.append(pkg)
        except Exception as e:
            # An unexpected error in ONE package (e.g. a race in parallel runs, an unusual archive
            # format) must not stop the whole shard - it is recorded as failed and the loop continues.
            print(f"  [!] Unexpected error in {pkg}: {e}")
            failed.append(pkg)

    if args.shard:
        # Parallel workers over the same list: updating expected_labels.json (read-modify-write) is
        # NOT safe under concurrent execution - it is done once, after all workers have finished.
        print(f"\n[*] --shard: expected_labels.json is not updated "
              f"(run the script once without --shard at the end).")
    else:
        update_expected_labels()

    print(f"\n{'=' * 60}")
    print(f"[✓] Succeeded: {len(succeeded)}/{len(packages)} -> {succeeded}")
    if failed:
        print(f"[!] Failed: {failed}")
    print(f"\nNow run: python3 check_test_set.py {TEST_SET_DIR}")


if __name__ == "__main__":
    main()

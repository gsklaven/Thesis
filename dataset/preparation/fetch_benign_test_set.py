"""
Κατεβάζει μια επιμελημένη λίστα ΝΟΜΙΜΩΝ (benign) πακέτων - επιλεγμένα
ΕΠΙΤΗΔΕΣ επειδή χρησιμοποιούν "ευαίσθητα" APIs (subprocess, δίκτυο,
credentials) που θα μπορούσαν να μοιάζουν ύποπτα σε επιφανειακή ανάλυση,
τρέχει σε καθένα το πλήρες CodeQL pipeline (analysis.py + build_behavior_
chain.py), και αποθηκεύει το αποτέλεσμα στο test_set/<πακέτο>.json.

ΜΕΤΑ, τρέξε: python3 check_test_set.py $THESIS_BASE_DIR/test_set

Γιατί αυτά τα συγκεκριμένα πακέτα (false-positive testing, όχι τυχαία):
  paramiko     - SSH/remote command execution
  fabric       - deployment tool, εκτελεί shell commands
  psutil       - system/process introspection
  cryptography - crypto operations
  boto3        - AWS credentials handling
  requests     - δίκτυο
  pyyaml       - file parsing
  numpy        - καθαρό baseline, καμία ευαίσθητη API
  sh/httpx/jinja2/sqlalchemy/flask - ήδη προστέθηκαν
  +30 νέα ΝΕΑ πακέτα - επιλεγμένα σκόπιμα για ικανότητες που "μοιάζουν"
  με malware patterns (screen/keyboard control, C2-like tunneling,
  credential access, βαρύ subprocess usage) αλλά είναι 100% νόμιμα:
  pyautogui (keyboard/mouse control - RAT-like), mss (screen capture -
  RAT-like), pyngrok (ngrok wrapper - ίδιο tunneling εργαλείο που το δικό
  μας HEUR-05 αναφέρει ως πιθανό C2), keyring (credential store access),
  python-dotenv (διαβάζει .env μυστικά), supervisor/pyinstaller/ansible/
  netmiko (βαρύ subprocess/SSH usage), κ.λπ.
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile

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

BASE_DIR = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
DOWNLOAD_DIR = os.path.join(BASE_DIR, "benign_downloads")
TEST_SET_DIR = os.path.join(BASE_DIR, "benign_test_set")
EXPECTED_LABELS_FILE = os.path.join(BASE_DIR, "expected_labels.json")

PIPELINE_DIR = os.path.join(BASE_DIR, "inference", "codeql_pipeline")
PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")
ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")

CSV_GLOB_PATTERNS = [
    "final_codeql_results_*.csv", "call_graph_*.csv",
    "backward_slice_*.csv", "control_deps_*.csv",
]


def clean_pipeline_results():
    if os.path.exists(RESULTS_JSON):
        os.remove(RESULTS_JSON)
    for pattern in CSV_GLOB_PATTERNS:
        for f in glob.glob(os.path.join(PIPELINE_RESULTS_DIR, pattern)):
            os.remove(f)


def download_and_extract(pkg_name):
    pkg_download_dir = os.path.join(DOWNLOAD_DIR, pkg_name)
    if os.path.exists(pkg_download_dir):
        shutil.rmtree(pkg_download_dir)
    os.makedirs(pkg_download_dir)

    print(f"  [-] Κατέβασμα {pkg_name}...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "download", pkg_name, "--no-deps",
             "-d", pkg_download_dir, "--no-cache-dir"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout στη λήψη {pkg_name}")
        return None

    if result.returncode != 0:
        print(f"  [!] Αποτυχία λήψης {pkg_name}: {result.stderr[-300:]}")
        return None

    downloaded_files = [f for f in os.listdir(pkg_download_dir) if not f.startswith(".")]
    if not downloaded_files:
        print(f"  [!] Δεν κατέβηκε τίποτα για {pkg_name}")
        return None

    archive_path = os.path.join(pkg_download_dir, downloaded_files[0])
    extract_dir = os.path.join(pkg_download_dir, "extracted")
    os.makedirs(extract_dir)

    print(f"  [-] Αποσυμπίεση {downloaded_files[0]}...")
    try:
        if archive_path.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)
        elif archive_path.endswith((".whl", ".zip")):
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(extract_dir)
        else:
            print(f"  [!] Άγνωστη μορφή αρχείου: {downloaded_files[0]}")
            return None
    except Exception as e:
        print(f"  [!] Αποτυχία αποσυμπίεσης: {e}")
        return None

    return extract_dir


def run_codeql_pipeline(pkg_name, src_dir):
    clean_pipeline_results()

    env = os.environ.copy()
    env["CODEQL_TARGET_DIR"] = src_dir

    print(f"  [-] CodeQL ανάλυση...")
    try:
        res1 = subprocess.run(["python3", ANALYSIS_SCRIPT], cwd=PIPELINE_DIR, env=env, timeout=600)
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout (10 λεπτά) στο analysis.py για {pkg_name}")
        return False
    if res1.returncode != 0:
        print(f"  [!] Σφάλμα CodeQL για {pkg_name}")
        return False

    print(f"  [-] Σύνθεση behavior chains...")
    try:
        res2 = subprocess.run(["python3", BUILD_SCRIPT], cwd=PIPELINE_DIR, timeout=180)
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout (3 λεπτά) στο build_behavior_chain.py για {pkg_name}")
        return False
    if res2.returncode != 0:
        print(f"  [!] Σφάλμα Builder για {pkg_name}")
        return False

    if not os.path.exists(RESULTS_JSON):
        print(f"  [!] Δεν παράχθηκε αποτέλεσμα για {pkg_name}")
        return False

    os.makedirs(TEST_SET_DIR, exist_ok=True)
    dest = os.path.join(TEST_SET_DIR, f"{pkg_name}.json")
    shutil.copy2(RESULTS_JSON, dest)
    print(f"  [✓] {dest}")
    return True


def update_expected_labels():
    labels = {}
    if os.path.exists(EXPECTED_LABELS_FILE):
        with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
            labels = json.load(f)

    for pkg in BENIGN_PACKAGES:
        if os.path.exists(os.path.join(TEST_SET_DIR, f"{pkg}.json")):
            labels[pkg] = "benign"

    with open(EXPECTED_LABELS_FILE, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] expected_labels.json ενημερώθηκε ({len(labels)} συνολικές ετικέτες)")


def main():
    print(f"[*] {len(BENIGN_PACKAGES)} νόμιμα πακέτα προς ανάλυση: {BENIGN_PACKAGES}")

    succeeded, failed = [], []
    for pkg in BENIGN_PACKAGES:
        print(f"\n{'=' * 60}\n=== {pkg} ===\n{'=' * 60}")

        dest = os.path.join(TEST_SET_DIR, f"{pkg}.json")
        if os.path.exists(dest):
            print(f"  [*] Παράλειψη (ήδη υπάρχει): {pkg}")
            succeeded.append(pkg)
            continue

        src_dir = download_and_extract(pkg)
        if not src_dir:
            failed.append(pkg)
            continue

        if run_codeql_pipeline(pkg, src_dir):
            succeeded.append(pkg)
        else:
            failed.append(pkg)

    update_expected_labels()

    print(f"\n{'=' * 60}")
    print(f"[✓] Επιτυχή: {len(succeeded)}/{len(BENIGN_PACKAGES)} -> {succeeded}")
    if failed:
        print(f"[!] Απέτυχαν: {failed}")
    print(f"\nΤώρα τρέξε: python3 check_test_set.py {TEST_SET_DIR}")


if __name__ == "__main__":
    main()
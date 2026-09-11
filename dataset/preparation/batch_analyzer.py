import os
import json
import shutil
import subprocess
import tarfile
import zipfile
import signal
import glob

_DEDUPED_JSON = "/home/sklavenitis/thesis/dataset/malware_dataset_deduped.json"
_MATCHED_JSON = "/home/sklavenitis/thesis/dataset/malware_dataset_matched.json"
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON
FINAL_JSON_DIR = "/home/sklavenitis/thesis/dataset/analyzed_chains"

STAGING_DIR = "/home/sklavenitis/thesis/temp_malware_analysis"
PIPELINE_DIR = "/home/sklavenitis/thesis/inference/codeql_pipeline"
PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")

ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")

MAX_EXTRACT_PASSES = 3
MAX_STAGING_SIZE_MB = 50
MAX_STAGING_SIZE_BYTES = MAX_STAGING_SIZE_MB * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024
MIN_FREE_DISK_GB = 2

# ΝΕΟ - κρίσιμο data-integrity fix: αν το CodeQL αποτύχει να βρει κώδικα για
# ΟΠΟΙΑΔΗΠΟΤΕ γλώσσα (π.χ. "Processed 0 modules"), το analysis.py ΔΕΝ
# επιστρέφει σφάλμα (απλά τυπώνει "Παράλειψη γλώσσας" και συνεχίζει κανονικά,
# exit code 0). Αν δεν καθαρίσουμε τα ΕΝΔΙΑΜΕΣΑ CSV (final_codeql_results_*,
# call_graph_*, backward_slice_*, control_deps_*) πριν από ΚΑΘΕ πακέτο, το
# build_behavior_chain.py θα ξαναδιαβάσει ΠΑΛΙΑ CSV από το ΠΡΟΗΓΟΥΜΕΝΟ πακέτο
# που πέτυχε - παράγοντας ένα "επιτυχές" αλλά ΛΑΘΟΣ αποτέλεσμα, με το όνομα
# του τρέχοντος πακέτου αλλά το behavior ενός ΤΕΛΕΙΩΣ διαφορετικού.
CSV_GLOB_PATTERNS = [
    "final_codeql_results_*.csv", "call_graph_*.csv",
    "backward_slice_*.csv", "control_deps_*.csv",
]


def get_dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def run_with_hard_timeout(cmd, timeout, **kwargs):
    """
    ΣΗΜΑΝΤΙΚΟ FIX: το subprocess.Popen() (σε αντίθεση με το subprocess.run())
    ΔΕΝ καταλαβαίνει το "capture_output" - είναι convenience param ΜΟΝΟ του
    run(), που εσωτερικά το μεταφράζει σε stdout=PIPE/stderr=PIPE. Αφού εδώ
    καλούμε Popen() απευθείας (χρειαζόμαστε το για το killpg), κάνουμε ΕΜΕΙΣ
    αυτή τη μετάφραση πρώτα, ώστε όλα τα call sites να συνεχίσουν να
    δουλεύουν με το γνωστό capture_output=True χωρίς αλλαγές.
    """
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        raise


def clean_staging():
    assert STAGING_DIR.endswith("temp_malware_analysis"), \
        f"Refusing to rmtree unexpected path: {STAGING_DIR}"
    if os.path.exists(STAGING_DIR):
        shutil.rmtree(STAGING_DIR)
    os.makedirs(STAGING_DIR)

    if os.path.exists(RESULTS_JSON):
        os.remove(RESULTS_JSON)

    # ΝΕΟ: καθάρισε ΚΑΙ τα ενδιάμεσα CSV - βλ. σχόλιο πάνω. Χωρίς αυτό, ένα
    # πακέτο όπου το CodeQL αποτυγχάνει σιωπηλά (0 modules) "κληρονομεί" τα
    # behavior chains του ΠΡΟΗΓΟΥΜΕΝΟΥ πακέτου που πέτυχε.
    for pattern in CSV_GLOB_PATTERNS:
        for stale_csv in glob.glob(os.path.join(PIPELINE_RESULTS_DIR, pattern)):
            os.remove(stale_csv)


def copy_recursive(src_dir, dest_dir):
    for item in os.listdir(src_dir):
        s = os.path.join(src_dir, item)
        d = os.path.join(dest_dir, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)


def _safe_tar_extract(tar, dest_path):
    dest_real = os.path.realpath(dest_path)
    for member in tar.getmembers():
        member_path = os.path.join(dest_path, member.name)
        if not os.path.realpath(member_path).startswith(dest_real):
            print(f"  [!] BLOCKED path traversal: {member.name}")
            continue
        if member.issym() or member.islnk():
            print(f"  [!] BLOCKED symlink: {member.name}")
            continue
        if member.size > MAX_SINGLE_FILE_SIZE:
            print(f"  [!] BLOCKED oversized ({member.size/1e6:.0f}MB): {member.name}")
            continue
        tar.extract(member, dest_path)


def _safe_zip_extract(zf, dest_path):
    dest_real = os.path.realpath(dest_path)
    for info in zf.infolist():
        target = os.path.join(dest_path, info.filename)
        if not os.path.realpath(target).startswith(dest_real):
            print(f"  [!] BLOCKED path traversal: {info.filename}")
            continue
        if info.file_size > MAX_SINGLE_FILE_SIZE:
            print(f"  [!] BLOCKED oversized ({info.file_size/1e6:.0f}MB): {info.filename}")
            continue
        zf.extract(info, dest_path)


def extract_archives(directory):
    for _ in range(MAX_EXTRACT_PASSES):
        found_archive = False
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                lower = fname.lower()
                try:
                    if lower.endswith((".tar.gz", ".tgz")):
                        with tarfile.open(fpath, "r:gz") as tar:
                            _safe_tar_extract(tar, root)
                        os.remove(fpath)
                        found_archive = True
                    elif lower.endswith(".tar"):
                        with tarfile.open(fpath, "r:") as tar:
                            _safe_tar_extract(tar, root)
                        os.remove(fpath)
                        found_archive = True
                    elif lower.endswith((".zip", ".whl")):
                        with zipfile.ZipFile(fpath, "r") as z:
                            _safe_zip_extract(z, root)
                        os.remove(fpath)
                        found_archive = True
                except Exception as e:
                    print(f"  [!] Αδυναμία αποσυμπίεσης {fname}: {e}")
        if not found_archive:
            break


def main():
    if not os.path.exists(FINAL_JSON_DIR):
        os.makedirs(FINAL_JSON_DIR)

    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    total = len(dataset)
    success = 0
    failed = 0
    skipped = 0
    empty_result = 0

    for idx, item in enumerate(dataset):
        pkg_name = item["package_name"]
        src_path = item["source_code_path"]
        final_dest = os.path.join(FINAL_JSON_DIR, f"{pkg_name}.json")

        if os.path.exists(final_dest):
            print(f"[{idx+1}/{total}] Παράλειψη (έχει ήδη αναλυθεί): {pkg_name}")
            skipped += 1
            continue

        free_gb = shutil.disk_usage(FINAL_JSON_DIR).free / (1024 ** 3)
        if free_gb < MIN_FREE_DISK_GB:
            print(f"\n[!] ΣΤΑΜΑΤΑΩ: Μόνο {free_gb:.1f}GB ελεύθερα (< {MIN_FREE_DISK_GB}GB).")
            break

        print(f"\n[{idx+1}/{total}] === Ανάλυση: {pkg_name} ===")
        clean_staging()
        copy_recursive(src_path, STAGING_DIR)

        print("  [-] Αποσυμπίεση αρχείων (αν υπάρχουν)...")
        extract_archives(STAGING_DIR)

        staged_size = get_dir_size(STAGING_DIR)
        if staged_size > MAX_STAGING_SIZE_BYTES:
            print(f"  [!] Παράλειψη: {staged_size/1e6:.0f}MB > {MAX_STAGING_SIZE_MB}MB όριο.")
            failed += 1
            continue

        env = os.environ.copy()
        env["CODEQL_TARGET_DIR"] = STAGING_DIR

        try:
            res1 = run_with_hard_timeout(
                ["python3", ANALYSIS_SCRIPT], timeout=600, env=env, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (10 λεπτά). Προχωράμε...")
            failed += 1
            continue

        if res1.returncode != 0:
            log_path = os.path.join(FINAL_JSON_DIR, f"_error_{pkg_name}.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(res1.stdout or "")
                f.write(res1.stderr or "")
            print(f"  [!] Σφάλμα CodeQL — πλήρες log στο: {log_path}")
            failed += 1
            continue

        try:
            res2 = run_with_hard_timeout(
                ["python3", BUILD_SCRIPT], timeout=180, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (3 λεπτά). Προχωράμε...")
            failed += 1
            continue

        if res2.returncode != 0:
            print(f"  [!] Σφάλμα Builder")
            failed += 1
            continue

        if os.path.exists(RESULTS_JSON):
            # ΝΕΟ: έλεγχος ότι το αποτέλεσμα δεν είναι κενό - αν το CodeQL
            # δεν βρήκε ΚΑΝΕΝΑ module (0 modules και στις δύο γλώσσες), το
            # sliced_behavior_chain.json θα έχει total_behavior_chains == 0.
            # Το καταγράφουμε ξεχωριστά (δεν είναι "λάθος" per se, αλλά
            # χρήσιμο να ξέρεις πόσα πακέτα δεν έδωσαν κανένα εύρημα).
            try:
                with open(RESULTS_JSON, "r", encoding="utf-8") as rf:
                    result_data = json.load(rf)
                n_chains = result_data.get("summary", {}).get("total_behavior_chains", -1)
            except Exception:
                n_chains = -1

            shutil.copy2(RESULTS_JSON, final_dest)
            if n_chains == 0:
                print(f"  [~] Επιτυχία, αλλά 0 behavior chains (πιθανό: 'no source code found').")
                empty_result += 1
            else:
                print(f"  [✓] Επιτυχία! ({n_chains} behavior chains)")
            success += 1
        else:
            print(f"  [!] Δεν δημιουργήθηκε αποτέλεσμα (καμία εύρημα;)")
            failed += 1

    print(f"\n[*] Ολοκληρώθηκε. Επιτυχείς: {success} (εκ των οποίων {empty_result} με 0 chains) | "
          f"Αποτυχίες: {failed} | Παραλείψεις: {skipped}")


if __name__ == "__main__":
    main()

import os
import json
import shutil
import subprocess
import tarfile
import zipfile
import signal
import glob
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import resolve_source_path  # noqa: E402

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
_DEDUPED_JSON = os.path.join(_THESIS_ROOT, "dataset", "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(_THESIS_ROOT, "dataset", "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON
FINAL_JSON_DIR = os.path.join(_THESIS_ROOT, "dataset", "analyzed_chains")

# ΝΕΟ: STAGING_DIR μπορεί τώρα να δείχνει οπουδήποτε (π.χ. σε στικάκι με
# άφθονο ελεύθερο χώρο), μέσω env var - χρήσιμο όταν ο κύριος δίσκος δεν
# έχει άλλο χώρο. Χωρίς να οριστεί, συνεχίζει να δουλεύει όπως πριν.
STAGING_DIR = os.environ.get(
    "BATCH_STAGING_DIR", os.path.join(_THESIS_ROOT, "temp_malware_analysis")
)
PIPELINE_DIR = os.path.join(_THESIS_ROOT, "inference", "codeql_pipeline")
SCANNER_SCRIPT = os.path.join(PIPELINE_DIR, "heuristic_scanner.py")
PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")

ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")

MAX_EXTRACT_PASSES = 3
# ΝΕΟ: configurable μέσω env var, ώστε να μπορείς να τα μειώσεις άμεσα
# (χωρίς αλλαγή κώδικα) όταν θες να "τρέξεις γρήγορα" το τελευταίο
# κομμάτι ενός μεγάλου corpus - τα περισσότερα φυσιολογικά πακέτα
# τελειώνουν σε δευτερόλεπτα, μόνο τα προβληματικά φτάνουν στο πλήρες όριο.
ANALYSIS_TIMEOUT = int(os.environ.get("BATCH_ANALYSIS_TIMEOUT", "300"))
BUILD_TIMEOUT = int(os.environ.get("BATCH_BUILD_TIMEOUT", "90"))
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


def get_dir_size_capped(path, cap_bytes):
    """
    ΝΕΟ: μετράει το μέγεθος ΠΡΙΝ οποιαδήποτε αντιγραφή, σταματώντας νωρίς
    μόλις ξεπεραστεί το όριο - αποφεύγει να διαβάσει ΟΛΟΚΛΗΡΟ έναν τεράστιο
    φάκελο μόνο και μόνο για να μετρήσει το μέγεθός του. Επιστρέφει το
    μέγεθος (μπορεί να είναι ελαφρώς υποεκτιμημένο αν σταμάτησε νωρίς) και
    True/False αν ξεπέρασε το cap.
    """
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
            if total > cap_bytes:
                return total, True
    return total, False


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

    # ΝΕΟ FIX: σπάνιο race condition (πιθανό υπολειπόμενη διεργασία γράφει
    # μέσα σε 'vendor/' ακριβώς τη στιγμή που γίνεται rmtree) μπορούσε να
    # ρίξει ολόκληρο το batch_analyzer.py με OSError "Directory not empty".
    # Retry με μικρή καθυστέρηση - αν επιμείνει, ignore_errors ώστε ΕΝΑ
    # πεισματάρικο πακέτο να μη σταματήσει χιλιάδες υπόλοιπα.
    if os.path.exists(STAGING_DIR):
        for attempt in range(3):
            try:
                shutil.rmtree(STAGING_DIR)
                break
            except OSError as e:
                if attempt < 2:
                    print(f"  [!] rmtree retry ({e}) - περιμένω 1s...")
                    time.sleep(1)
                else:
                    print(f"  [!] rmtree απέτυχε 3 φορές, συνεχίζω με ignore_errors: {e}")
                    shutil.rmtree(STAGING_DIR, ignore_errors=True)
    os.makedirs(STAGING_DIR, exist_ok=True)

    if os.path.exists(RESULTS_JSON):
        os.remove(RESULTS_JSON)

    # ΝΕΟ: καθάρισε ΚΑΙ τα ενδιάμεσα CSV - βλ. σχόλιο πάνω. Χωρίς αυτό, ένα
    # πακέτο όπου το CodeQL αποτυγχάνει σιωπηλά (0 modules) "κληρονομεί" τα
    # behavior chains του ΠΡΟΗΓΟΥΜΕΝΟΥ πακέτου που πέτυχε.
    for pattern in CSV_GLOB_PATTERNS:
        for stale_csv in glob.glob(os.path.join(PIPELINE_RESULTS_DIR, pattern)):
            os.remove(stale_csv)

    # ΝΕΟ: καθάρισε ΠΑΛΙΟΥΣ (30+ λεπτά) προσωρινούς φακέλους του ίδιου του
    # pip (pip-unpack-*, pip-target-*) μέσα στο /tmp. Όταν το run_with_hard_
    # timeout() στέλνει SIGKILL σε αργή εγκατάσταση εξάρτησης, το pip ΔΕΝ
    # προλαβαίνει να καθαρίσει τους δικούς του temp φακέλους (SIGKILL δεν
    # πιάνεται) - χωρίς αυτό εδώ, αυτό συσσωρεύεται σε δεκάδες GB μέσα σε
    # χιλιάδες πακέτα. Το +30 λεπτά αφήνει ανέγγιχτο ό,τι πιθανό
    # χρησιμοποιεί ΤΩΡΑ ένα ενεργό, τρέχον install.
    cutoff = time.time() - 30 * 60
    for prefix in ("pip-unpack-", "pip-target-"):
        for stale_dir in glob.glob(f"/tmp/{prefix}*"):
            try:
                if os.path.getmtime(stale_dir) < cutoff:
                    shutil.rmtree(stale_dir, ignore_errors=True)
            except OSError:
                pass


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


# ΝΕΟ FIX: τα malware samples αυτού του dataset (pypi_malregistry κλπ.) είναι
# σχεδόν πάντα zip-αρισμένα με τον καθιερωμένο κωδικό "infected" (σύμβαση
# malware-research corpora, ώστε να μην τα ανοίγει/σαρώνει κατά λάθος AV).
# Το zipfile.ZipFile.extract() ΑΓΝΟΕΙ σιωπηλά το pwd για μη-κρυπτογραφημένα
# entries, οπότε είναι ασφαλές να το περνάμε ΠΑΝΤΑ - χωρίς αυτό, ΚΑΘΕ
# κρυπτογραφημένο πακέτο έριχνε RuntimeError στο ΠΡΩΤΟ του entry, η
# εξαγωγή θεωρούνταν αποτυχημένη, το staging έμενε άδειο (μόνο το ίδιο το
# .zip), και το CodeQL έβλεπε "0 modules" -> ψευδές "0 behavior chains".
ZIP_MALWARE_PASSWORD = b"infected"


def _safe_zip_extract(zf, dest_path, pwd=None):
    dest_real = os.path.realpath(dest_path)
    for info in zf.infolist():
        target = os.path.join(dest_path, info.filename)
        if not os.path.realpath(target).startswith(dest_real):
            print(f"  [!] BLOCKED path traversal: {info.filename}")
            continue
        if info.file_size > MAX_SINGLE_FILE_SIZE:
            print(f"  [!] BLOCKED oversized ({info.file_size/1e6:.0f}MB): {info.filename}")
            continue
        zf.extract(info, dest_path, pwd=pwd)


def _try_extract_as_tar(fpath, root):
    # "r:*" αυτόματα ανιχνεύει gzip/bz2/xz/χωρίς συμπίεση - πιο ανθεκτικό
    # από το πριν "r:gz" (που απαιτούσε ΑΠΟΚΛΕΙΣΤΙΚΑ gzip).
    with tarfile.open(fpath, "r:*") as tar:
        _safe_tar_extract(tar, root)


def _try_extract_as_zip(fpath, root):
    with zipfile.ZipFile(fpath, "r") as z:
        try:
            _safe_zip_extract(z, root)
        except RuntimeError as e:
            if "password" not in str(e).lower() and "encrypted" not in str(e).lower():
                raise
            _safe_zip_extract(z, root, pwd=ZIP_MALWARE_PASSWORD)


def extract_archives(directory):
    for _ in range(MAX_EXTRACT_PASSES):
        found_archive = False
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                lower = fname.lower()

                if not lower.endswith((".tar.gz", ".tgz", ".tar", ".zip", ".whl")):
                    continue

                # ΝΕΟ FIX: μερικά αρχεία στο πηγαίο dataset έχουν ΛΑΘΟΣ
                # επέκταση (π.χ. πραγματικό .whl αποθηκευμένο ως ".tar.gz" -
                # δίνει "not a gzip file"). Δοκιμάζουμε ΠΡΩΤΑ τη μέθοδο που
                # υποδεικνύει η επέκταση, και αν αποτύχει με σφάλμα ΜΟΡΦΗΣ,
                # δοκιμάζουμε την ΑΛΛΗ πριν τα παρατήσουμε εντελώς.
                prefers_tar = lower.endswith((".tar.gz", ".tgz", ".tar"))
                strategies = (
                    [_try_extract_as_tar, _try_extract_as_zip] if prefers_tar
                    else [_try_extract_as_zip, _try_extract_as_tar]
                )

                extracted = False
                last_error = None
                for strategy in strategies:
                    try:
                        strategy(fpath, root)
                        extracted = True
                        break
                    except Exception as e:
                        last_error = e

                # ΝΕΟ FIX: αρχεία της μορφής <pkg>/<hash>/<pkg>-<hash>.tar.gz περιέχουν
                # φάκελο με ΙΔΙΟ όνομα με το ίδιο το αρχείο -> η εξαγωγή στον ίδιο
                # φάκελο συγκρούεται με το αρχείο, αποτυγχάνει, και το CodeQL βλέπει
                # 0 modules (ψευδές "0 chains"). Δεύτερη προσπάθεια σε ξεχωριστό φάκελο.
                if not extracted:
                    alt_root = fpath + ".x"
                    os.makedirs(alt_root, exist_ok=True)
                    for strategy in strategies:
                        try:
                            strategy(fpath, alt_root)
                            extracted = True
                            break
                        except Exception as e:
                            last_error = e
                    if not extracted:
                        shutil.rmtree(alt_root, ignore_errors=True)

                if extracted:
                    os.remove(fpath)
                    found_archive = True
                else:
                    print(f"  [!] Αδυναμία αποσυμπίεσης {fname} (δοκιμάστηκαν tar ΚΑΙ zip): {last_error}")
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
        src_path = resolve_source_path(item["source_code_path"])   # βλ. utils.resolve_source_path
        final_dest = os.path.join(FINAL_JSON_DIR, f"{pkg_name}.json")

        oversized_marker = os.path.join(FINAL_JSON_DIR, f"_oversized_{pkg_name}.marker")
        # ΝΕΟ: ξεχωριστό marker για ΟΠΟΙΑΔΗΠΟΤΕ άλλη αποτυχία (timeout,
        # σφάλμα CodeQL/Builder, κενό αποτέλεσμα) - πριν, ΚΑΝΕΝΑ από αυτά
        # δεν άφηνε μόνιμο ίχνος, οπότε ΚΑΘΕ restart ξαναπερίμενε ολόκληρο
        # το timeout (μέχρι 10 λεπτά) στα ΙΔΙΑ πακέτα, ξανά και ξανά.
        failed_marker = os.path.join(FINAL_JSON_DIR, f"_failed_{pkg_name}.marker")

        if os.path.exists(final_dest):
            print(f"[{idx+1}/{total}] Παράλειψη (έχει ήδη αναλυθεί): {pkg_name}")
            skipped += 1
            continue

        # ΝΕΟ: αν ήδη ξέρουμε από προηγούμενο run ότι είναι πολύ μεγάλο,
        # μην το ξαναδοκιμάσεις καθόλου - ΧΩΡΙΣ αυτό, κάθε μελλοντικό run
        # θα ξανααντέγραφε/ξαναμετρούσε το ίδιο τεράστιο πακέτο για πάντα.
        if os.path.exists(oversized_marker):
            print(f"[{idx+1}/{total}] Παράλειψη (γνωστό ως πολύ μεγάλο): {pkg_name}")
            skipped += 1
            continue

        if os.path.exists(failed_marker):
            print(f"[{idx+1}/{total}] Παράλειψη (γνωστή προηγούμενη αποτυχία): {pkg_name}")
            skipped += 1
            continue

        # ΝΕΟ: γρήγορος έλεγχος μεγέθους ΤΗΣ ΠΗΓΗΣ πριν από ΟΠΟΙΑΔΗΠΟΤΕ
        # αντιγραφή - αν είναι ήδη προφανώς τεράστιο, μην το αντιγράψεις
        # καν (γλιτώνει χρόνο ΚΑΙ χώρο δίσκου). Δεν είναι 100% ακριβές
        # (η αποσυμπίεση μπορεί να το μεγαλώσει/μικρύνει), αλλά πιάνει τις
        # προφανείς περιπτώσεις φθηνά - ο μετά-αποσυμπίεσης έλεγχος παρακάτω
        # παραμένει ως τελικό, ακριβές φίλτρο.
        if os.path.exists(src_path):
            src_size, src_over = get_dir_size_capped(src_path, MAX_STAGING_SIZE_BYTES)
            if src_over:
                print(f"[{idx+1}/{total}] Παράλειψη ΠΡΙΝ την αντιγραφή "
                      f"(πηγή ήδη >{MAX_STAGING_SIZE_MB}MB): {pkg_name}")
                with open(oversized_marker, "w", encoding="utf-8") as f:
                    f.write(f"source_size_at_least={src_size}\n")
                failed += 1
                continue

        # ΝΕΟ FIX: έλεγχος ΚΑΙ των δύο δίσκων (όχι μόνο του FINAL_JSON_DIR) -
        # αν το STAGING_DIR έχει ανακατευθυνθεί (π.χ. σε στικάκι μέσω
        # BATCH_STAGING_DIR), πρέπει να ελέγχουμε ΚΑΙ εκεί. Χωρίς αυτό, ένα
        # redirect δεν βοηθάει καθόλου - ο έλεγχος έβλεπε ΠΑΝΤΑ μόνο τον
        # κύριο δίσκο όπου ζει το FINAL_JSON_DIR, ανεξάρτητα από πού
        # δείχνει πραγματικά το staging.
        final_free_gb = shutil.disk_usage(FINAL_JSON_DIR).free / (1024 ** 3)
        staging_disk_path = STAGING_DIR if os.path.exists(STAGING_DIR) else os.path.dirname(STAGING_DIR)
        staging_free_gb = shutil.disk_usage(staging_disk_path).free / (1024 ** 3)
        free_gb = min(final_free_gb, staging_free_gb)
        if free_gb < MIN_FREE_DISK_GB:
            print(f"\n[!] ΣΤΑΜΑΤΑΩ: Μόνο {free_gb:.1f}GB ελεύθερα "
                  f"(output disk: {final_free_gb:.1f}GB, staging disk: {staging_free_gb:.1f}GB) "
                  f"< {MIN_FREE_DISK_GB}GB.")
            break

        print(f"\n[{idx+1}/{total}] === Ανάλυση: {pkg_name} ===")
        clean_staging()
        copy_recursive(src_path, STAGING_DIR)

        print("  [-] Αποσυμπίεση αρχείων (αν υπάρχουν)...")
        extract_archives(STAGING_DIR)

        staged_size = get_dir_size(STAGING_DIR)
        if staged_size > MAX_STAGING_SIZE_BYTES:
            print(f"  [!] Παράλειψη: {staged_size/1e6:.0f}MB > {MAX_STAGING_SIZE_MB}MB όριο.")
            with open(oversized_marker, "w", encoding="utf-8") as f:
                f.write(f"staged_size_after_extract={staged_size}\n")
            failed += 1
            continue

        env = os.environ.copy()
        env["CODEQL_TARGET_DIR"] = STAGING_DIR

        try:
            res1 = run_with_hard_timeout(
                ["python3", ANALYSIS_SCRIPT], timeout=ANALYSIS_TIMEOUT, env=env, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (10 λεπτά). Προχωράμε...")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=timeout_analysis_py\n")
            failed += 1
            continue

        if res1.returncode != 0:
            log_path = os.path.join(FINAL_JSON_DIR, f"_error_{pkg_name}.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(res1.stdout or "")
                f.write(res1.stderr or "")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write(f"reason=codeql_error, βλ. {log_path}\n")
            print(f"  [!] Σφάλμα CodeQL — πλήρες log στο: {log_path}")
            failed += 1
            continue

        try:
            res2 = run_with_hard_timeout(
                ["python3", BUILD_SCRIPT], timeout=BUILD_TIMEOUT, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (3 λεπτά). Προχωράμε...")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=timeout_build_behavior_chain\n")
            failed += 1
            continue

        if res2.returncode != 0:
            print(f"  [!] Σφάλμα Builder")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=builder_error\n")
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
            if n_chains == 0 and os.environ.get("BATCH_ENABLE_HEURISTIC_FALLBACK") == "1":
                # ── Heuristic fallback (OPT-IN, off by default) ─────────────
                # CodeQL found nothing. Run the lightweight regex scanner as a
                # second chance before marking the package as empty. The scanner
                # overwrites RESULTS_JSON in-place if it finds anything, so the
                # subsequent copy picks up the heuristic result automatically.
                # Off by default: these are pattern-matched, not CodeQL-verified,
                # results and should not silently masquerade as real findings.
                n_chains = _try_heuristic_scanner(STAGING_DIR, RESULTS_JSON)
                shutil.copy2(RESULTS_JSON, final_dest)   # re-copy (heuristic or original)
                if n_chains == 0:
                    print(f"  [~] Επιτυχία, αλλά 0 behavior chains (CodeQL + heuristic scanner).")
                    empty_result += 1
                else:
                    print(f"  [✓] Επιτυχία! ({n_chains} heuristic chains)")
            elif n_chains == 0:
                print(f"  [~] Επιτυχία, αλλά 0 behavior chains (CodeQL).")
                empty_result += 1
            else:
                print(f"  [✓] Επιτυχία! ({n_chains} behavior chains)")
            success += 1
        else:
            print(f"  [!] Δεν δημιουργήθηκε αποτέλεσμα (καμία εύρημα;)")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=no_result_produced\n")
            failed += 1

    print(f"\n[*] Ολοκληρώθηκε. Επιτυχείς: {success} (εκ των οποίων {empty_result} με 0 chains) | "
          f"Αποτυχίες: {failed} | Παραλείψεις: {skipped}")


# ── Heuristic scanner fallback ───────────────────────────────────────────────

def _try_heuristic_scanner(staging_dir: str, results_json: str) -> int:
    """
    Run heuristic_scanner.py on *staging_dir* when CodeQL found 0 chains.
    If the scanner finds patterns it overwrites *results_json* in place.
    Returns the number of heuristic chains found (0 on any error/empty).
    """
    if not os.path.exists(SCANNER_SCRIPT):
        return 0

    print("  [~] 0 CodeQL chains — εκτελώ heuristic scanner...")
    try:
        res = run_with_hard_timeout(
            ["python3", SCANNER_SCRIPT, staging_dir],
            timeout=30,
            cwd=PIPELINE_DIR,
            capture_output=True,
            text=True,
        )
    except (subprocess.TimeoutExpired, OSError):
        print("  [!] Heuristic scanner timeout/error.")
        return 0

    if res.returncode != 0:
        stderr_snippet = (res.stderr or "").strip()[:120]
        print(f"  [!] Heuristic scanner απέτυχε: {stderr_snippet}")
        return 0

    # Scanner writes to its own RESULTS_DIR which IS the same pipeline results
    # dir. Re-read results_json to see how many chains were found.
    try:
        with open(results_json, "r", encoding="utf-8") as rf:
            scan_data = json.load(rf)
        n = scan_data.get("summary", {}).get("total_behavior_chains", 0)
        if n:
            print(f"  [~] Heuristic scanner: {n} pattern(s) βρέθηκαν.")
        return n
    except Exception:
        return 0


if __name__ == "__main__":
    main()
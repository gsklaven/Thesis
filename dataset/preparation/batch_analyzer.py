"""
Batch static analysis of the malware samples with the CodeQL pipeline, and the shared helpers that the
other analysis scripts (rerun_chains.py, fetch_benign_test_set.py, payload_scan.py) import.

For every entry of the dataset JSON the sample is copied to a staging folder, its archives are
extracted safely (path-traversal / symlink / size checks, encrypted malware zips), and
inference/codeql_pipeline/analysis.py + build_behavior_chain.py are run with hard timeouts. The result
(sliced_behavior_chain.json) is stored as dataset/analyzed_chains/<package>.json.

Resumable: packages with a result, or with an _oversized_ / _failed_ marker from a previous run, are
skipped, so a restart never waits again on the same failing packages.
"""
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

# The staging folder can point anywhere (e.g. a disk with plenty of free space) through an
# environment variable; by default it lives in the project folder.
STAGING_DIR = os.environ.get(
    "BATCH_STAGING_DIR", os.path.join(_THESIS_ROOT, "temp_malware_analysis")
)
PIPELINE_DIR = os.path.join(_THESIS_ROOT, "inference", "codeql_pipeline")
SCANNER_SCRIPT = os.path.join(PIPELINE_DIR, "heuristic_scanner.py")
PIPELINE_RESULTS_DIR = os.path.join(PIPELINE_DIR, "results")

ANALYSIS_SCRIPT = os.path.join(PIPELINE_DIR, "analysis.py")
BUILD_SCRIPT = os.path.join(PIPELINE_DIR, "build_behavior_chain.py")
RESULTS_JSON = os.path.join(PIPELINE_RESULTS_DIR, "sliced_behavior_chain.json")

MAX_EXTRACT_PASSES = 3  # archives inside archives are extracted up to this depth
# Timeouts are configurable through environment variables, so they can be changed without code
# changes; most packages finish in seconds, only problematic ones reach the full limit.
ANALYSIS_TIMEOUT = int(os.environ.get("BATCH_ANALYSIS_TIMEOUT", "300"))
BUILD_TIMEOUT = int(os.environ.get("BATCH_BUILD_TIMEOUT", "90"))
MAX_STAGING_SIZE_MB = 50
MAX_STAGING_SIZE_BYTES = MAX_STAGING_SIZE_MB * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024
MIN_FREE_DISK_GB = 2

# Data-integrity safeguard: if CodeQL finds no code for a language (e.g. "Processed 0 modules"),
# analysis.py does NOT fail - it prints "Skipping language" and exits with code 0. Unless the
# INTERMEDIATE CSV files (final_codeql_results_*, call_graph_*, backward_slice_*, control_deps_*) are
# removed before EVERY package, build_behavior_chain.py would re-read the OLD CSVs of the previous
# successful package - a "successful" but WRONG result, with the current package's name and the
# behaviour of a completely different one.
CSV_GLOB_PATTERNS = [
    "final_codeql_results_*.csv", "call_graph_*.csv",
    "backward_slice_*.csv", "control_deps_*.csv", "constant_args_*.csv",
]


def get_dir_size(path):
    """Total size in bytes of all files under path (unreadable files are ignored)."""
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
    Size of a folder measured BEFORE any copying, stopping as soon as the cap is exceeded, so a huge
    folder is never read completely just to measure it. Returns (size, exceeded); the size may be an
    underestimate when the walk stopped early.
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
    subprocess.run() replacement whose timeout kills the WHOLE process group (CodeQL starts Java
    child processes that would otherwise survive). Returns a CompletedProcess; re-raises
    TimeoutExpired after the kill.

    subprocess.Popen() (unlike run()) does not understand "capture_output" - it is a convenience
    parameter of run() that becomes stdout=PIPE / stderr=PIPE. Popen is needed here (for killpg), so
    that translation is done first and every call site can keep using capture_output=True.
    """
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    # new session -> the child is the leader of its own process group
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
    """
    Start every package from a clean state: empty the staging folder, remove the previous result JSON
    and intermediate CSVs, and delete stale pip temp folders left in /tmp by killed processes.
    """
    # safety guard: never delete an unexpected folder
    assert STAGING_DIR.endswith("temp_malware_analysis"), \
        f"Refusing to rmtree unexpected path: {STAGING_DIR}"

    # A rare race (a leftover process writing into 'vendor/' exactly during rmtree) could crash the
    # whole batch with OSError "Directory not empty". Retry with a short delay; if it persists, use
    # ignore_errors so that ONE stubborn package does not stop thousands of others.
    if os.path.exists(STAGING_DIR):
        for attempt in range(3):
            try:
                shutil.rmtree(STAGING_DIR)
                break
            except OSError as e:
                if attempt < 2:
                    print(f"  [!] rmtree retry ({e}) - waiting 1s...")
                    time.sleep(1)
                else:
                    print(f"  [!] rmtree failed 3 times, continuing with ignore_errors: {e}")
                    shutil.rmtree(STAGING_DIR, ignore_errors=True)
    os.makedirs(STAGING_DIR, exist_ok=True)

    if os.path.exists(RESULTS_JSON):
        os.remove(RESULTS_JSON)

    # Remove the intermediate CSVs as well (see the comment at CSV_GLOB_PATTERNS). Without this, a
    # package on which CodeQL silently fails (0 modules) "inherits" the chains of the previous package.
    for pattern in CSV_GLOB_PATTERNS:
        for stale_csv in glob.glob(os.path.join(PIPELINE_RESULTS_DIR, pattern)):
            os.remove(stale_csv)

    # Remove OLD (30+ minutes) temporary folders of pip (pip-unpack-*, pip-target-*) in /tmp. When
    # run_with_hard_timeout() SIGKILLs a slow dependency installation, pip cannot clean its own temp
    # folders (SIGKILL cannot be caught); over thousands of packages they add up to tens of GB. The
    # 30-minute margin leaves alone anything an active installation may still be using.
    cutoff = time.time() - 30 * 60
    for prefix in ("pip-unpack-", "pip-target-"):
        for stale_dir in glob.glob(f"/tmp/{prefix}*"):
            try:
                if os.path.getmtime(stale_dir) < cutoff:
                    shutil.rmtree(stale_dir, ignore_errors=True)
            except OSError:
                pass


def copy_recursive(src_dir, dest_dir):
    """Copy the contents of src_dir into dest_dir (merging into existing folders)."""
    for item in os.listdir(src_dir):
        s = os.path.join(src_dir, item)
        d = os.path.join(dest_dir, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)


def _safe_tar_extract(tar, dest_path):
    """Extract a tar archive member by member, skipping path traversal, links and oversized files."""
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


# Malware samples of these datasets (pypi_malregistry etc.) are usually zipped with the conventional
# password "infected" (a malware-research convention, so that antivirus software does not open or scan
# them by accident). zipfile.ZipFile.extract() silently IGNORES pwd for unencrypted entries, so it is
# safe to retry with it; without it, every encrypted sample failed on its first entry, the staging
# folder stayed empty and CodeQL reported "0 modules" -> a false "0 behavior chains".
ZIP_MALWARE_PASSWORD = b"infected"


def _safe_zip_extract(zf, dest_path, pwd=None):
    """Extract a zip archive entry by entry, skipping path traversal and oversized files."""
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
    """Extract fpath as a tar archive of any compression into root."""
    # "r:*" detects gzip/bz2/xz/uncompressed automatically (more robust than "r:gz")
    with tarfile.open(fpath, "r:*") as tar:
        _safe_tar_extract(tar, root)


def _try_extract_as_zip(fpath, root):
    """Extract fpath as a zip archive into root, retrying with the malware password if it is encrypted."""
    with zipfile.ZipFile(fpath, "r") as z:
        try:
            _safe_zip_extract(z, root)
        except RuntimeError as e:
            if "password" not in str(e).lower() and "encrypted" not in str(e).lower():
                raise
            _safe_zip_extract(z, root, pwd=ZIP_MALWARE_PASSWORD)


def extract_archives(directory):
    """
    Extract every archive (.tar.gz, .tgz, .tar, .zip, .whl) under directory in place and delete the
    archive, repeating up to MAX_EXTRACT_PASSES times for nested archives.
    """
    for _ in range(MAX_EXTRACT_PASSES):
        found_archive = False
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                lower = fname.lower()

                if not lower.endswith((".tar.gz", ".tgz", ".tar", ".zip", ".whl")):
                    continue

                # Some files of the source datasets have the WRONG extension (e.g. a real .whl saved
                # as ".tar.gz" -> "not a gzip file"). The method suggested by the extension is tried
                # FIRST and, if it fails with a format error, the OTHER one before giving up.
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

                # Archives like <pkg>/<hash>/<pkg>-<hash>.tar.gz contain a folder with the SAME name
                # as the archive itself -> extracting into the same folder collides with the file and
                # fails (and CodeQL sees 0 modules). Second attempt into a separate folder.
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
                    print(f"  [!] Could not extract {fname} (tried tar AND zip): {last_error}")
        if not found_archive:
            break


def main():
    """Analyse every dataset entry that has no result or marker yet; print a final summary."""
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
        src_path = resolve_source_path(item["source_code_path"])   # see utils.resolve_source_path
        final_dest = os.path.join(FINAL_JSON_DIR, f"{pkg_name}.json")

        oversized_marker = os.path.join(FINAL_JSON_DIR, f"_oversized_{pkg_name}.marker")
        # a separate marker for ANY other failure (timeout, CodeQL/builder error, no result), so a
        # restart does not wait for the full timeout again on the same packages
        failed_marker = os.path.join(FINAL_JSON_DIR, f"_failed_{pkg_name}.marker")

        if os.path.exists(final_dest):
            print(f"[{idx+1}/{total}] Skipped (already analysed): {pkg_name}")
            skipped += 1
            continue

        # already known to be too large from a previous run: never copy/measure it again
        if os.path.exists(oversized_marker):
            print(f"[{idx+1}/{total}] Skipped (known to be too large): {pkg_name}")
            skipped += 1
            continue

        if os.path.exists(failed_marker):
            print(f"[{idx+1}/{total}] Skipped (known previous failure): {pkg_name}")
            skipped += 1
            continue

        # Quick size check of the SOURCE before any copying: an obviously huge sample is not copied at
        # all (saves time AND disk space). Extraction may change the size, so the exact check after
        # extraction below remains the final filter.
        if os.path.exists(src_path):
            src_size, src_over = get_dir_size_capped(src_path, MAX_STAGING_SIZE_BYTES)
            if src_over:
                print(f"[{idx+1}/{total}] Skipped BEFORE copying "
                      f"(source already >{MAX_STAGING_SIZE_MB}MB): {pkg_name}")
                with open(oversized_marker, "w", encoding="utf-8") as f:
                    f.write(f"source_size_at_least={src_size}\n")
                failed += 1
                continue

        # Check BOTH disks: the output disk and the (possibly redirected, BATCH_STAGING_DIR) staging
        # disk. Checking only the output disk would make a staging redirect useless.
        final_free_gb = shutil.disk_usage(FINAL_JSON_DIR).free / (1024 ** 3)
        staging_disk_path = STAGING_DIR if os.path.exists(STAGING_DIR) else os.path.dirname(STAGING_DIR)
        staging_free_gb = shutil.disk_usage(staging_disk_path).free / (1024 ** 3)
        free_gb = min(final_free_gb, staging_free_gb)
        if free_gb < MIN_FREE_DISK_GB:
            print(f"\n[!] STOPPING: only {free_gb:.1f}GB free "
                  f"(output disk: {final_free_gb:.1f}GB, staging disk: {staging_free_gb:.1f}GB) "
                  f"< {MIN_FREE_DISK_GB}GB.")
            break

        print(f"\n[{idx+1}/{total}] === Analysing: {pkg_name} ===")
        clean_staging()
        copy_recursive(src_path, STAGING_DIR)

        print("  [-] Extracting archives (if any)...")
        extract_archives(STAGING_DIR)

        staged_size = get_dir_size(STAGING_DIR)
        if staged_size > MAX_STAGING_SIZE_BYTES:
            print(f"  [!] Skipped: {staged_size/1e6:.0f}MB > {MAX_STAGING_SIZE_MB}MB limit.")
            with open(oversized_marker, "w", encoding="utf-8") as f:
                f.write(f"staged_size_after_extract={staged_size}\n")
            failed += 1
            continue

        # the CodeQL pipeline reads the folder to analyse from this variable
        env = os.environ.copy()
        env["CODEQL_TARGET_DIR"] = STAGING_DIR

        try:
            res1 = run_with_hard_timeout(
                ["python3", ANALYSIS_SCRIPT], timeout=ANALYSIS_TIMEOUT, env=env, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (analysis). Moving on...")
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
                f.write(f"reason=codeql_error, see {log_path}\n")
            print(f"  [!] CodeQL error - full log in: {log_path}")
            failed += 1
            continue

        try:
            res2 = run_with_hard_timeout(
                ["python3", BUILD_SCRIPT], timeout=BUILD_TIMEOUT, cwd=PIPELINE_DIR,
                capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT (chain builder). Moving on...")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=timeout_build_behavior_chain\n")
            failed += 1
            continue

        if res2.returncode != 0:
            print(f"  [!] Builder error")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=builder_error\n")
            failed += 1
            continue

        if os.path.exists(RESULTS_JSON):
            # An empty result is counted separately: if CodeQL found no module at all (0 modules in both
            # languages), sliced_behavior_chain.json has total_behavior_chains == 0. Not an error as
            # such, but useful to know how many packages gave no finding.
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
                    print(f"  [~] Success, but 0 behavior chains (CodeQL + heuristic scanner).")
                    empty_result += 1
                else:
                    print(f"  [✓] Success! ({n_chains} heuristic chains)")
            elif n_chains == 0:
                print(f"  [~] Success, but 0 behavior chains (CodeQL).")
                empty_result += 1
            else:
                print(f"  [✓] Success! ({n_chains} behavior chains)")
            success += 1
        else:
            print(f"  [!] No result was created (no finding?)")
            with open(failed_marker, "w", encoding="utf-8") as f:
                f.write("reason=no_result_produced\n")
            failed += 1

    print(f"\n[*] Done. Succeeded: {success} (of which {empty_result} with 0 chains) | "
          f"Failed: {failed} | Skipped: {skipped}")


# ── Heuristic scanner fallback ───────────────────────────────────────────────

def _try_heuristic_scanner(staging_dir: str, results_json: str) -> int:
    """
    Run heuristic_scanner.py on *staging_dir* when CodeQL found 0 chains.
    If the scanner finds patterns it overwrites *results_json* in place.
    Returns the number of heuristic chains found (0 on any error/empty).
    """
    if not os.path.exists(SCANNER_SCRIPT):
        return 0

    print("  [~] 0 CodeQL chains - running the heuristic scanner...")
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
        print(f"  [!] Heuristic scanner failed: {stderr_snippet}")
        return 0

    # Scanner writes to its own RESULTS_DIR which IS the same pipeline results
    # dir. Re-read results_json to see how many chains were found.
    try:
        with open(results_json, "r", encoding="utf-8") as rf:
            scan_data = json.load(rf)
        n = scan_data.get("summary", {}).get("total_behavior_chains", 0)
        if n:
            print(f"  [~] Heuristic scanner: {n} pattern(s) found.")
        return n
    except Exception:
        return 0


if __name__ == "__main__":
    main()

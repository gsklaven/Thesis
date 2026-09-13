import ast
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import time

# Βασικές ρυθμίσεις του προγράμματος
CODEQL_BIN = (
    shutil.which("codeql")
    or next(
        (p for p in [
            "/opt/homebrew/bin/codeql",
            "/usr/local/bin/codeql",
            os.path.expanduser("~/codeql/codeql"),
        ] if os.path.isfile(p)),
        "codeql",  # fallback: hope it's on PATH at runtime
    )
)
_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
TARGET_DIR = os.environ.get("CODEQL_TARGET_DIR", os.path.join(_THESIS_ROOT, "behavior_chain"))
LANGUAGE = "python"
VENDOR_FOLDER = "vendor"

# ΚΡΙΣΙΜΟ: χωρίς αυτό, το CodeQL (JVM-based) δεν έχει ΚΑΝΕΝΑ όριο μνήμης - αν
# ένα malware δείγμα (πιθανώς σκόπιμα, ως anti-analysis τέχνασμα) προκαλέσει
# απότομη έκρηξη μνήμης, μπορεί να καταναλώσει ΟΛΗ τη RAM+swap του συστήματος,
# προκαλώντας system-wide OOM που σκοτώνει ολόκληρη τη γραφική συνεδρίδα
# (όχι μόνο το ίδιο το CodeQL process). Θέτουμε ένα ασφαλές ανώτατο όριο,
# αρκετά χαμηλότερο από τη συνολική RAM του μηχανήματος ώστε να μένει πάντα
# αρκετό περιθώριο για OS/desktop/browser.
CODEQL_MAX_RAM_MB = 4096

# Φάκελος για την αποθήκευση των αποτελεσμάτων
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

# Λεξικό για να βρίσκουμε το σωστό όνομα εγκατάστασης στο pip
IMPORT_TO_PACKAGE = {
    "yaml": "pyyaml", "cv2": "opencv-python", "PIL": "pillow",
    "bs4": "beautifulsoup4", "sklearn": "scikit-learn",
    "Crypto": "pycryptodome", "Cryptodome": "pycryptodome",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv",
    "OpenSSL": "pyopenssl", "git": "GitPython", "serial": "pyserial",
    "win32api": "pywin32",
}

BUILD_TOOLING_EXCLUDE = {
    "pip", "setuptools", "wheel", "pkg_resources", "distutils",
    "build", "installer", "pep517", "pep621",
    "sphinx", "sphinx_rtd_theme", "docutils", "mkdocs",
}

NOISE_DIR_NAMES = {
    "docs", "doc", "_static", "static", "test", "tests",
    "examples", "example", "demo", "demos", ".egg-info",
}


def run_with_hard_timeout(cmd, timeout, check=False, **kwargs):
    """
    ΑΝΤΙ για subprocess.run(cmd, timeout=..., check=...). Το CODEQL_BIN είναι
    ένα shell script που κάνει fork σε Java process - αν λήξει το timeout,
    subprocess.run() σκοτώνει ΜΟΝΟ το άμεσο child (το codeql script), αφήνοντας
    το Java process ΟΡΦΑΝΟ να τρέχει επ' άπειρον στο παρασκήνιο, καταναλώνοντας
    CPU/μνήμη/δίσκο χωρίς κανείς να το ξέρει (ακριβώς αυτό προκάλεσε το
    πρόβλημα δίσκου/ταχύτητας μιας εβδομάδας).

    Εδώ τρέχουμε το process σε ΔΙΚΟ ΤΟΥ process group (start_new_session=True),
    και αν λήξει ο χρόνος, σκοτώνουμε ΟΛΟΚΛΗΡΟ το group (killpg) - αυτό
    σκοτώνει και τα Java παιδιά/εγγόνια, όχι μόνο το άμεσο process.

    FIX: το Popen() δεν καταλαβαίνει "capture_output" (μόνο το run() το
    καταλαβαίνει) - το μεταφράζουμε σε stdout=PIPE/stderr=PIPE εμείς πριν
    το Popen(), ώστε το pip install call (πιο κάτω) να συνεχίσει να δουλεύει.
    """
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)

    proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise

    result = subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, stdout, stderr)
    return result


def auto_fetch_dependencies(source_directory, vendor_folder=VENDOR_FOLDER):
    vendor_path = os.path.join(source_directory, vendor_folder)
    if not os.path.exists(vendor_path):
        os.makedirs(vendor_path)

    print("\nΑυτόματη Ανάλυση Εξαρτήσεων")

    found_imports = []
    for root, dirs, files in os.walk(source_directory):
        if vendor_folder in root or ".venv" in root:
            continue

        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        file_content = f.read()
                        tree = ast.parse(file_content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                package_name = alias.name.split(".")[0]
                                found_imports.append(package_name)
                        elif isinstance(node, ast.ImportFrom):
                            if node.module is not None and node.level == 0:
                                package_name = node.module.split(".")[0]
                                found_imports.append(package_name)
                except Exception as e:
                    print(f"Αδυναμία ανάλυσης του αρχείου {file}: {e}")

    external_packages = []
    for pkg in found_imports:
        if pkg in BUILD_TOOLING_EXCLUDE:
            continue
        if pkg not in sys.stdlib_module_names:
            if pkg not in external_packages:
                external_packages.append(pkg)

    if len(external_packages) == 0:
        return []

    installed_packages = []
    for pkg in external_packages:
        if pkg in IMPORT_TO_PACKAGE:
            dist_name = IMPORT_TO_PACKAGE[pkg]
        else:
            dist_name = pkg

        print(f"Κατέβασμα: {dist_name} -> vendor/")

        # --no-cache-dir: αυτά τα vendor installs είναι one-off - ο φάκελος
        # vendor/ σβήνεται στο ΕΠΟΜΕΝΟ πακέτο ούτως ή άλλως (clean_staging()).
        # Χωρίς αυτό, το pip cache μεγαλώνει επ' άπειρον σε χιλιάδες
        # εγκαταστάσεις (ήδη είχε φτάσει τα 10GB μία φορά) - πιθανή αιτία
        # των crashes γύρω στο ίδιο σημείο κάθε φορά.
        pip_command = [
            sys.executable, "-m", "pip", "install", dist_name,
            "--target", vendor_path, "--no-deps", "--no-cache-dir",
        ]
        try:
            result = run_with_hard_timeout(pip_command, timeout=90, capture_output=True)
        except subprocess.TimeoutExpired:
            print(f"  [!] Timeout (90s) κατά την εγκατάσταση {dist_name} - παράλειψη.")
            continue

        if result.returncode == 0:
            installed_packages.append(dist_name)

    strip_noise_dirs(vendor_path)

    return installed_packages


def strip_noise_dirs(vendor_path):
    if not os.path.exists(vendor_path):
        return
    removed = []
    for root, dirs, files in os.walk(vendor_path, topdown=True):
        keep_dirs = []
        for d in dirs:
            if d.lower() in NOISE_DIR_NAMES:
                full = os.path.join(root, d)
                try:
                    shutil.rmtree(full, ignore_errors=True)
                    removed.append(full)
                except Exception:
                    pass
            else:
                keep_dirs.append(d)
        dirs[:] = keep_dirs
    if removed:
        print(f"Αφαιρέθηκαν {len(removed)} 'θορυβώδεις' vendor φάκελοι (docs/tests/examples/static).")


def generate_dependency_tree(source_directory, vendor_folder=VENDOR_FOLDER):
    output_path = os.path.join(RESULTS_DIR, "dependency_tree.json")
    vendor_path = os.path.join(source_directory, vendor_folder)

    dependency_tree = {}
    metadata_files = glob.glob(os.path.join(vendor_path, "*.dist-info", "METADATA"))

    for meta_file in metadata_files:
        package_name = ""
        requires = []

        try:
            with open(meta_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("Name:"):
                        package_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Requires-Dist:"):
                        dependency = line.split(":", 1)[1].strip()
                        dependency_name = dependency.split(";")[0].split()[0]
                        requires.append(dependency_name)
        except Exception as e:
            print(f"Πρόβλημα ανάγνωσης αρχείου {meta_file}: {e}")

        if package_name != "":
            dependency_tree[package_name] = sorted(list(set(requires)))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dependency_tree, f, indent=4)

    return dependency_tree


def safe_remove_db(db_name, retries=5, delay=1.0):
    if not os.path.exists(db_name):
        return
    last_err = None
    for attempt in range(retries):
        try:
            shutil.rmtree(db_name)
            return
        except OSError as e:
            last_err = e
            time.sleep(delay)
    shutil.rmtree(db_name, ignore_errors=True)
    if os.path.exists(db_name):
        raise RuntimeError(
            f"Δεν κατάφερα να διαγράψω την παλιά database {db_name} μετά από {retries} προσπάθειες: {last_err}"
        )


def run_codeql(target_dir, queries_list, language=LANGUAGE):
    db_root = os.path.join(os.path.dirname(os.path.normpath(target_dir)), "codeql_dbs")
    if not os.path.exists(db_root):
        os.makedirs(db_root)

    db_name = os.path.join(db_root, f"codeql_db_{language}")

    safe_remove_db(db_name)

    print(f"Δημιουργία βάσης δεδομένων CodeQL για {language}...")
    create_cmd = [
        CODEQL_BIN, "database", "create", db_name,
        f"--language={language}",
        f"--source-root={target_dir}",
        f"--ram={CODEQL_MAX_RAM_MB}",
    ]
    run_with_hard_timeout(create_cmd, timeout=600, check=True)

    for query_file, csv_output in queries_list:
        print(f"Εκτέλεση ερωτήματος: {os.path.basename(query_file)}")
        raw_bqrs = os.path.splitext(csv_output)[0] + ".bqrs"

        run_cmd = [
            CODEQL_BIN, "query", "run", query_file, f"--database={db_name}",
            f"--output={raw_bqrs}", f"--ram={CODEQL_MAX_RAM_MB}",
        ]
        run_with_hard_timeout(run_cmd, timeout=300, check=True)

        decode_cmd = [CODEQL_BIN, "bqrs", "decode", raw_bqrs, "--format=csv", f"--output={csv_output}"]
        run_with_hard_timeout(decode_cmd, timeout=120, check=True)

        if os.path.exists(raw_bqrs):
            os.remove(raw_bqrs)


if __name__ == "__main__":

    auto_fetch_dependencies(TARGET_DIR)
    generate_dependency_tree(TARGET_DIR)

    QUERY_FOLDERS = {
        "python": "python_queries",
        "javascript": "js_queries"
    }

    QUERIES_BY_LANGUAGE = {
        "python": [
            ("find_flow.ql", "final_codeql_results_python.csv"),
            ("call_graph_py.ql", "call_graph_python.csv"),
            ("backward_slice_py.ql", "backward_slice_python.csv"),
            ("control_deps_py.ql", "control_deps_python.csv"),
        ],
        "javascript": [
            ("call_graph_js.ql", "call_graph_javascript.csv"),
            ("find_flow_js.ql", "final_codeql_results_javascript.csv"),
            ("backward_slice_js.ql", "backward_slice_javascript.csv"),
            ("control_deps_js.ql", "control_deps_javascript.csv"),
        ],
    }

    for lang in QUERIES_BY_LANGUAGE:
        print(f"\nCodeQL pass: {lang}")

        folder_name = QUERY_FOLDERS[lang]
        queries_to_run = []

        for query_filename, csv_filename in QUERIES_BY_LANGUAGE[lang]:
            full_query_path = os.path.join(PROJECT_DIR, folder_name, query_filename)
            full_csv_path = os.path.join(RESULTS_DIR, csv_filename)
            queries_to_run.append((full_query_path, full_csv_path))

        try:
            run_codeql(TARGET_DIR, queries_to_run, language=lang)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError) as e:
            print(f"[!] Παράλειψη γλώσσας '{lang}': {e}")
            continue

    print(f"\nΤα αποτελέσματα CodeQL αποθηκεύτηκαν στον φάκελο: {RESULTS_DIR}")

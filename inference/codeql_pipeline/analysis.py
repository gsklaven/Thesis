"""
Stage 1 of the static analysis: run the CodeQL queries on one package.

For the package in CODEQL_TARGET_DIR:
  1. find its third-party imports (AST scan of every .py file) - with CODEQL_NO_VENDOR=1 they are only
     recorded by name in results/dependency_tree.json; otherwise each is pip-installed into vendor/
     (no dependencies of dependencies) so that library code can be analysed too;
  2. for each language (Python, JavaScript): create a CodeQL database and run the four queries
     (find_flow = source->sink taint tracking to sensitive API calls, call_graph, backward_slice,
     control_deps), decoding every result to a CSV file in results/.

A language whose database or queries fail is skipped with the message "[!] Skipping language '<lang>'"
(the scripts that run this one look for that exact text). build_behavior_chain.py then combines the CSV
files into Behavior Chains.
"""
import ast
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import time

# Basic settings: the CodeQL binary (PATH first, then common install locations)
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
_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
# the package to analyse (set by the calling script)
TARGET_DIR = os.environ.get("CODEQL_TARGET_DIR", os.path.join(_THESIS_ROOT, "behavior_chain"))
LANGUAGE = "python"
VENDOR_FOLDER = "vendor"

# CRITICAL: without this CodeQL (JVM-based) has NO memory limit. A malware sample that (possibly on
# purpose, as an anti-analysis trick) makes memory use explode could consume ALL RAM + swap and cause
# a system-wide out-of-memory condition that kills the whole desktop session, not only CodeQL. The cap
# is well below the machine's total RAM, leaving room for the OS and other programs.
CODEQL_MAX_RAM_MB = 4096

# Time limits per step (seconds), configurable through the environment, so that large packages do not
# silently lose e.g. the backward slice because of a timeout.
DB_CREATE_TIMEOUT = int(os.environ.get("CODEQL_DB_TIMEOUT", "600"))
QUERY_TIMEOUT = int(os.environ.get("CODEQL_QUERY_TIMEOUT", "300"))

# CODEQL_NO_VENDOR=1: dependencies are detected but NOT installed into vendor/ - CodeQL analyses only
# the package's own code (sensitive calls into libraries are still recognised from the imports through
# API graphs, without the library code). The dependency names are written to dependency_tree.json
# (without sub-dependencies).
NO_VENDOR = os.environ.get("CODEQL_NO_VENDOR") == "1"

# Folder of the results (CSV files, dependency tree)
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

# import name -> pip distribution name, where the two differ
IMPORT_TO_PACKAGE = {
    "yaml": "pyyaml", "cv2": "opencv-python", "PIL": "pillow",
    "bs4": "beautifulsoup4", "sklearn": "scikit-learn",
    "Crypto": "pycryptodome", "Cryptodome": "pycryptodome",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv",
    "OpenSSL": "pyopenssl", "git": "GitPython", "serial": "pyserial",
    "win32api": "pywin32",
}

# build/documentation tooling is not treated as a dependency of the package
BUILD_TOOLING_EXCLUDE = {
    "pip", "setuptools", "wheel", "pkg_resources", "distutils",
    "build", "installer", "pep517", "pep621",
    "sphinx", "sphinx_rtd_theme", "docutils", "mkdocs",
}

# folders removed from installed vendor packages (documentation, tests, examples)
NOISE_DIR_NAMES = {
    "docs", "doc", "_static", "static", "test", "tests",
    "examples", "example", "demo", "demos", ".egg-info",
}


def run_with_hard_timeout(cmd, timeout, check=False, **kwargs):
    """
    Replacement for subprocess.run(cmd, timeout=..., check=...). CODEQL_BIN is a shell script that
    forks a Java process: on timeout, subprocess.run() kills ONLY the direct child (the codeql script)
    and leaves the Java process ORPHANED, running in the background and consuming CPU/memory/disk.

    Here the process runs in its OWN process group (start_new_session=True) and on timeout the WHOLE
    group is killed (killpg), including the Java children and grandchildren.

    Popen() does not understand "capture_output" (only run() does), so it is translated to
    stdout=PIPE / stderr=PIPE before calling Popen() (used by the pip install call below).
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
    """
    Find the third-party packages imported by the package's own .py files (absolute imports that are
    neither standard library, build tooling, nor modules of the package itself). With NO_VENDOR the
    sorted distribution names are returned without installing anything; otherwise each is installed
    into vendor/ (90 s timeout per package) and the list of installed ones is returned.
    """
    vendor_path = os.path.join(source_directory, vendor_folder)
    if not NO_VENDOR and not os.path.exists(vendor_path):
        os.makedirs(vendor_path)

    print("\nAutomatic dependency analysis")

    found_imports = []
    # Names of modules/packages that exist INSIDE the code itself: an `import boto3` inside boto3 is not
    # a dependency - otherwise pip would download the package itself (or its legitimate namesake, for
    # malware) into vendor/ and it would be analysed twice.
    local_names = set()
    for root, dirs, files in os.walk(source_directory):
        rel_parts = os.path.relpath(root, source_directory).split(os.sep)
        if rel_parts[0] == vendor_folder or ".venv" in rel_parts:
            continue
        local_names.update(dirs)
        local_names.update(f[:-3] for f in files if f.endswith(".py"))

        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        file_content = f.read()
                        tree = ast.parse(file_content)

                    # top-level name of every absolute import
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
                    print(f"Could not parse file {file}: {e}")

    # keep third-party names only, in first-seen order, without duplicates
    external_packages = []
    for pkg in found_imports:
        if pkg in BUILD_TOOLING_EXCLUDE or pkg in local_names:
            continue
        if pkg not in sys.stdlib_module_names:
            if pkg not in external_packages:
                external_packages.append(pkg)

    if len(external_packages) == 0:
        return []

    if NO_VENDOR:
        deps = sorted({IMPORT_TO_PACKAGE.get(p, p) for p in external_packages})
        print(f"CODEQL_NO_VENDOR=1: {len(deps)} dependencies recorded without installation: {deps[:15]}")
        return deps

    installed_packages = []
    for pkg in external_packages:
        if pkg in IMPORT_TO_PACKAGE:
            dist_name = IMPORT_TO_PACKAGE[pkg]
        else:
            dist_name = pkg

        print(f"Downloading: {dist_name} -> vendor/")

        # --no-cache-dir: these vendor installs are one-off - vendor/ is deleted before the NEXT package
        # anyway (clean_staging()). Otherwise the pip cache grows without bound over thousands of
        # installations.
        pip_command = [
            sys.executable, "-m", "pip", "install", dist_name,
            "--target", vendor_path, "--no-deps", "--no-cache-dir",
        ]
        try:
            result = run_with_hard_timeout(pip_command, timeout=90, capture_output=True)
        except subprocess.TimeoutExpired:
            print(f"  [!] Timeout (90s) while installing {dist_name} - skipped.")
            continue

        if result.returncode == 0:
            installed_packages.append(dist_name)

    strip_noise_dirs(vendor_path)

    return installed_packages


def strip_noise_dirs(vendor_path):
    """Delete documentation/test/example folders (NOISE_DIR_NAMES) from the installed vendor packages."""
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
        dirs[:] = keep_dirs  # do not descend into removed folders
    if removed:
        print(f"Removed {len(removed)} 'noise' vendor folders (docs/tests/examples/static).")


def generate_dependency_tree(source_directory, vendor_folder=VENDOR_FOLDER):
    """
    Write results/dependency_tree.json: {installed package: sorted Requires-Dist names}, read from the
    METADATA file of every *.dist-info folder in vendor/.
    """
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
                        # "name (>=1.0); extra == 'x'" -> "name"
                        dependency = line.split(":", 1)[1].strip()
                        dependency_name = dependency.split(";")[0].split()[0]
                        requires.append(dependency_name)
        except Exception as e:
            print(f"Problem reading file {meta_file}: {e}")

        if package_name != "":
            dependency_tree[package_name] = sorted(list(set(requires)))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dependency_tree, f, indent=4)

    return dependency_tree


def safe_remove_db(db_name, retries=5, delay=1.0):
    """Delete an old CodeQL database folder, retrying (files may still be held briefly); raise if it survives."""
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
            f"Could not delete the old database {db_name} after {retries} attempts: {last_err}"
        )


def run_codeql(target_dir, queries_list, language=LANGUAGE):
    """
    Create a fresh CodeQL database of target_dir for one language and run every (query, csv) pair:
    query run -> .bqrs -> decoded to CSV. Any failure raises (the caller skips the language).
    """
    # databases live next to the analysed folder, never inside it
    db_root = os.path.join(os.path.dirname(os.path.normpath(target_dir)), "codeql_dbs")
    if not os.path.exists(db_root):
        os.makedirs(db_root)

    db_name = os.path.join(db_root, f"codeql_db_{language}")

    safe_remove_db(db_name)

    print(f"Creating the CodeQL database for {language}...")
    create_cmd = [
        CODEQL_BIN, "database", "create", db_name,
        f"--language={language}",
        f"--source-root={target_dir}",
        f"--ram={CODEQL_MAX_RAM_MB}",
    ]
    run_with_hard_timeout(create_cmd, timeout=DB_CREATE_TIMEOUT, check=True)

    for query_file, csv_output in queries_list:
        print(f"Running query: {os.path.basename(query_file)}")
        raw_bqrs = os.path.splitext(csv_output)[0] + ".bqrs"

        run_cmd = [
            CODEQL_BIN, "query", "run", query_file, f"--database={db_name}",
            f"--output={raw_bqrs}", f"--ram={CODEQL_MAX_RAM_MB}",
        ]
        run_with_hard_timeout(run_cmd, timeout=QUERY_TIMEOUT, check=True)

        # binary query results -> CSV for build_behavior_chain.py
        decode_cmd = [CODEQL_BIN, "bqrs", "decode", raw_bqrs, "--format=csv", f"--output={csv_output}"]
        run_with_hard_timeout(decode_cmd, timeout=120, check=True)

        if os.path.exists(raw_bqrs):
            os.remove(raw_bqrs)


if __name__ == "__main__":

    # 1. dependencies: recorded by name (NO_VENDOR) or installed into vendor/ with their metadata tree
    deps = auto_fetch_dependencies(TARGET_DIR)
    if NO_VENDOR:
        with open(os.path.join(RESULTS_DIR, "dependency_tree.json"), "w", encoding="utf-8") as f:
            json.dump({d: [] for d in deps}, f, indent=4)
    else:
        generate_dependency_tree(TARGET_DIR)

    QUERY_FOLDERS = {
        "python": "python_queries",
        "javascript": "js_queries"
    }

    # (query file, CSV output) per language
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

    # 2. one CodeQL pass per language; a failing language is skipped, the other still runs
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
            # NOTE: rerun_chains.py and fetch_benign_test_set.py look for "Skipping language 'python'"
            print(f"[!] Skipping language '{lang}': {e}")
            continue

    print(f"\nThe CodeQL results were saved in: {RESULTS_DIR}")

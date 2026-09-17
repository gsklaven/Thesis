"""
heuristic_scanner.py — lightweight malware pattern scanner.

Fallback for when CodeQL produces 0 behavior chains (NO_CHAINS_FOUND).
Scans setup.py, __init__.py, and root-level .py files for known
obfuscation/exfiltration patterns using regex matching.

Output format matches build_behavior_chain.py so query_rag.py
consumes it unchanged. Each hit becomes one behavior_chain entry.

Chains carry  heuristic_source=True  and  heuristic_description
so query_rag.py can inject a calibration note for the LLM.

Usage (standalone):
    python3 heuristic_scanner.py /path/to/package_dir

Usage (imported from batch_analyzer.py):
    from heuristic_scanner import scan_package
    result = scan_package(staging_dir)
"""
import json
import os
import re
import sys

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

MAX_FILE_SIZE = 300_000   # 300 KB — skip pathologically large files
MAX_FILES     = 40        # cap total files to avoid blowup on huge packages

# Files that carry the highest malware signal — always scanned first
PRIORITY_FILENAMES = {
    "setup.py", "__init__.py", "install.py", "post_install.py",
    "_install.py", "installer.py",
}

# ── Pattern catalogue ────────────────────────────────────────────────────────
PATTERNS = [
    {
        "id": "exec_obfuscated",
        "regex": re.compile(
            r"exec\s*\([^)]*?"
            r"(?:base64|b64decode|codecs|zlib|gzip|bz2|lzma|\.decode\b|decompress)"
            r"[^)]*?\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": "crypto_obfuscation",
        "api": "exec(obfuscated_payload)",
        "description": (
            "exec() wrapping a base64/compressed decode — classic dropper pattern: "
            "the real payload is stored encoded and executed at runtime to evade "
            "static scanners."
        ),
    },
    {
        "id": "eval_obfuscated",
        "regex": re.compile(
            r"eval\s*\([^)]*?"
            r"(?:base64|b64decode|codecs|compile|\.decode\b|decompress)"
            r"[^)]*?\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": "crypto_obfuscation",
        "api": "eval(obfuscated_payload)",
        "description": (
            "eval() on encoded/compressed data — dynamic payload evaluation used "
            "to hide malicious code from static analysis tools."
        ),
    },
    {
        "id": "compile_from_encoded",
        "regex": re.compile(
            r"compile\s*\([^)]*?(?:base64|b64decode|decode|decompress)[^)]*?\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "category": "crypto_obfuscation",
        "api": "compile(encoded_string)",
        "description": (
            "compile() called on a decoded/deobfuscated string — typically precedes "
            "exec() of an obfuscated payload to produce executable code objects."
        ),
    },
    {
        "id": "marshal_pickle_payload",
        "regex": re.compile(
            r"(?:marshal\.loads|pickle\.loads|pickle\.load)\s*\(",
        ),
        "category": "crypto_obfuscation",
        "api": "marshal/pickle_deserialization",
        "description": (
            "Deserializing marshal/pickle bytecode — advanced payload delivery; "
            "pickle.loads() executes arbitrary Python code during deserialization."
        ),
    },
    {
        "id": "dynamic_import_sensitive",
        "regex": re.compile(
            r"""__import__\s*\(\s*['"](os|subprocess|socket|requests|urllib|ftplib|smtplib|paramiko|pty)['"]\s*\)""",
        ),
        "category": "process_exec",
        "api": "__import__(sensitive_module)",
        "description": (
            "Dynamic import of sensitive stdlib/network module via __import__() — "
            "used to bypass simple import-statement static scanners."
        ),
    },
    {
        "id": "setup_install_hook",
        "regex": re.compile(
            r"class\s+\w*[Ii]nstall\w*\s*\([^)]*\binstall\b[^)]*\)\s*:",
        ),
        "category": "process_exec",
        "api": "setup.py_install_hook",
        "description": (
            "Custom install command class in setup.py (cmdclass override) — "
            "code in run() executes at pip install time on the victim machine, "
            "before any import, without user awareness."
        ),
    },
    {
        "id": "shell_true_subprocess",
        "regex": re.compile(
            r"subprocess\s*\.\s*(?:run|Popen|call|check_output|check_call)\s*\("
            r"[^;]{0,300}?shell\s*=\s*True",
            re.DOTALL,
        ),
        "category": "process_exec",
        "api": "subprocess(shell=True)",
        "description": (
            "subprocess call with shell=True — enables arbitrary shell command "
            "execution; in setup.py/install context this runs at pip install time."
        ),
    },
    {
        "id": "os_system",
        "regex": re.compile(r"os\s*\.\s*system\s*\("),
        "category": "process_exec",
        "api": "os.system()",
        "description": (
            "os.system() call — executes shell commands; in install hooks this "
            "runs arbitrary code at pip install time without user awareness."
        ),
    },
    {
        "id": "network_at_import",
        "regex": re.compile(
            r"(?:requests|urllib\.request|urllib2|http\.client|httplib)\s*\.\s*"
            r"(?:get|post|urlopen|urlretrieve|Request)\s*\(",
        ),
        "category": "network",
        "api": "http_request_at_import",
        "description": (
            "HTTP request at module-level or install-time — potential C2 callback, "
            "data exfiltration, or payload download triggered on import/install."
        ),
    },
    {
        "id": "raw_socket",
        "regex": re.compile(
            r"socket\s*\.\s*(?:socket\s*\(|connect\s*\(|AF_INET\b)",
        ),
        "category": "network",
        "api": "socket_connection",
        "description": (
            "Raw socket creation/connection — characteristic of reverse shells, "
            "C2 beacons, or direct network data exfiltration."
        ),
    },
    {
        "id": "env_credential_harvest",
        "regex": re.compile(
            r"os\s*\.\s*environ(?:\.get)?\s*(?:\[|\.get\s*\()\s*"
            r"""['"](?:AWS|TOKEN|SECRET|KEY|PASS|API_KEY|AUTH|CREDENTIAL|GITHUB|PRIVATE)""",
            re.IGNORECASE,
        ),
        "category": "network",
        "api": "os.environ_credential_harvest",
        "description": (
            "Reading sensitive environment variables (API keys, tokens, AWS credentials) "
            "— consistent with credential theft / supply-chain exfiltration."
        ),
    },
]


# ── File discovery ───────────────────────────────────────────────────────────

def _candidate_files(target_dir: str) -> list:
    """
    Return (absolute_path, is_priority) tuples for Python files to scan.
    Priority files first, total capped at MAX_FILES.
    """
    seen_paths = []
    seen_set   = set()

    def _add(path, priority):
        real = os.path.realpath(path)
        if real not in seen_set and os.path.isfile(path):
            seen_set.add(real)
            seen_paths.append((path, priority))

    # 1. Priority filenames anywhere in the tree
    for root, _dirs, files in os.walk(target_dir):
        for fname in files:
            if fname in PRIORITY_FILENAMES and fname.endswith(".py"):
                _add(os.path.join(root, fname), True)

    # 2. Root-level .py files
    try:
        for fname in sorted(os.listdir(target_dir)):
            if fname.endswith(".py"):
                _add(os.path.join(target_dir, fname), False)
    except OSError:
        pass

    # 3. __init__.py of immediate subdirectories
    try:
        for item in sorted(os.listdir(target_dir)):
            sub = os.path.join(target_dir, item)
            if os.path.isdir(sub):
                _add(os.path.join(sub, "__init__.py"), False)
    except OSError:
        pass

    return seen_paths[:MAX_FILES]


# ── Core scanner ─────────────────────────────────────────────────────────────

def scan_package(target_dir: str) -> dict:
    """
    Scan *target_dir* for malware heuristics.

    Returns a dict in the same top-level format as build_behavior_chain.py
    so query_rag.py consumes it without modification:
        {
          "summary": {..., "heuristic_scan": True},
          "behavior_chains": [...],
          "full_call_graphs": {},
          "package_dependency_graph": {},
        }

    Each chain carries heuristic_source=True so query_rag.py can inject
    an appropriate calibration note for the LLM.
    """
    candidates = _candidate_files(target_dir)
    chains     = []
    seen_hits  = set()       # (rel_path, pattern_id, line_no) — dedup

    for filepath, is_priority in candidates:
        try:
            if os.path.getsize(filepath) > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        rel_path = os.path.relpath(filepath, target_dir)

        for pat in PATTERNS:
            for m in pat["regex"].finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                hit_key = (rel_path, pat["id"], line_no)
                if hit_key in seen_hits:
                    continue
                seen_hits.add(hit_key)

                matched_text = m.group(0).replace("\n", " ").strip()[:200]

                chains.append({
                    "language": "python",
                    "flow_boundary": "App-Internal",
                    "sensitive_api": pat["api"],
                    "category": pat["category"],
                    "location": f"{rel_path}:{line_no}",
                    # Empty CodeQL-style fields — flatten_chain_to_text handles []
                    "confirmed_source_flows": [],
                    "control_conditions": [],
                    "relevant_call_graph": [],
                    # Matched snippet → appears as "Contributing data-flow nodes" in text
                    "data_flow_slice": [
                        {
                            "file": rel_path,
                            "line": str(line_no),
                            "text": matched_text,
                        }
                    ],
                    # Heuristic metadata used by query_rag.py to calibrate the prompt
                    "heuristic_source": True,
                    "heuristic_pattern_id": pat["id"],
                    "heuristic_description": pat["description"],
                    "heuristic_priority_file": is_priority,
                })

    by_category: dict = {}
    for c in chains:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1

    return {
        "summary": {
            "total_behavior_chains": len(chains),
            "by_category": by_category,
            "total_package_dependencies": 0,
            "heuristic_scan": True,
        },
        "behavior_chains": chains,
        "full_call_graphs": {},
        "package_dependency_graph": {},
    }


# ── Standalone entry point ───────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Χρήση: python3 heuristic_scanner.py /path/to/package_dir")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isdir(target):
        print(f"[!] Δεν βρέθηκε ο φάκελος: {target}")
        sys.exit(1)

    result = scan_package(target)
    n = result["summary"]["total_behavior_chains"]
    print(f"[+] {n} heuristic pattern(s) βρέθηκαν στο: {target}")
    for c in result["behavior_chains"]:
        print(
            f"  [{c['category']:20s}] {c['heuristic_pattern_id']:30s} @ {c['location']}"
        )

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "sliced_behavior_chain.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=4, ensure_ascii=False)
    print(f"[+] Output → {out_path}")

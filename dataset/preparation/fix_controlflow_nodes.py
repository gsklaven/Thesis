"""
Post-hoc fix για τα "ControlFlowNode for X" strings στα behavior chain JSONs.
Αντί να ξανατρέξουμε το CodeQL pipeline, διαβάζουμε τη γραμμή source code
που αντιστοιχεί σε κάθε entry (file + line) και την βάζουμε σαν text.

Χρήση:
    python3 fix_controlflow_nodes.py                          # benign_test_set
    python3 fix_controlflow_nodes.py --dataset rag_train      # malicious
    python3 fix_controlflow_nodes.py --dry-run                # preview μόνο
"""

import argparse
import io
import json
import os
import re
import tarfile

BASE_DIR = os.environ.get("THESIS_BASE_DIR", "/Users/giorgos/Documents/Thesis")
USB_PYPI = "/Volumes/GIORGOS_128/pypi_malregistry"

DATASETS = {
    "benign_test_set": {
        "json_dir": os.path.join(BASE_DIR, "dataset", "benign_test_set"),
        "get_source_root": lambda pkg: os.path.join(
            BASE_DIR, "benign_downloads", pkg, "extracted"
        ),
        "mode": "filesystem",
    },
    "rag_train": {
        "json_dir": os.path.join(BASE_DIR, "dataset", "rag_train"),
        "get_pkg_dir": lambda pkg: os.path.join(USB_PYPI, pkg),
        "mode": "tarball",
    },
}

IS_CFN = re.compile(r"^ControlFlowNode for ")


# ─── Filesystem mode (benign) ────────────────────────────────────────────────

def find_source_file_fs(source_root, relative_path):
    candidate = os.path.join(source_root, relative_path)
    if os.path.isfile(candidate):
        return candidate
    try:
        subdirs = [d for d in os.listdir(source_root)
                   if os.path.isdir(os.path.join(source_root, d))]
    except FileNotFoundError:
        return None
    for sub in subdirs:
        candidate = os.path.join(source_root, sub, relative_path)
        if os.path.isfile(candidate):
            return candidate
    return None


_fs_cache = {}


def get_line_fs(source_root, relative_path, line_no):
    full_path = find_source_file_fs(source_root, relative_path)
    if not full_path:
        return None
    if full_path not in _fs_cache:
        try:
            with open(full_path, encoding="utf-8", errors="replace") as fh:
                _fs_cache[full_path] = fh.readlines()
        except OSError:
            return None
    lines = _fs_cache[full_path]
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return None


# ─── Tarball mode (malicious / USB) ─────────────────────────────────────────

_tar_cache = {}    # pkg → {member_path → lines[]}
_tar_root  = {}    # pkg → root_dir_inside_tar (e.g. "bussardweg4a-1.0.0")


def _open_tar_for_pkg(pkg_dir):
    """Finds and opens the first .tar.gz inside pkg_dir (any version subdir)."""
    if not os.path.isdir(pkg_dir):
        return None
    for ver in os.listdir(pkg_dir):
        ver_path = os.path.join(pkg_dir, ver)
        if not os.path.isdir(ver_path):
            continue
        for fname in os.listdir(ver_path):
            if fname.endswith((".tar.gz", ".tgz")):
                return os.path.join(ver_path, fname)
    return None


def _resolve_tar_member(pkg, json_rel_path, root_in_tar):
    """
    Maps a JSON file path → member path inside the tar.

    Two conventions seen in the data:
      A) "1.0.0/bussardweg4a-1.0.0/setup.py"  →  "bussardweg4a-1.0.0/setup.py"
         (CodeQL was run from pypi_malregistry/<pkg>/, path = <ver>/<root>/file)
      B) "vendor/requests/packages.py"          →  "10Cent10-999.0.4/vendor/requests/packages.py"
         (CodeQL was run from inside the extracted package, path = file relative to pkg root)
    """
    parts = json_rel_path.split("/")

    # Convention A: first segment is a version-like string and second = root_in_tar
    if len(parts) >= 2 and parts[1] == root_in_tar:
        # Strip the version prefix
        candidate = "/".join(parts[1:])
        return candidate

    # Convention B: prepend root_in_tar
    candidate = root_in_tar + "/" + json_rel_path
    return candidate


def _load_pkg_tar(pkg, pkg_dir):
    """Loads all lines from all .py members of the package tar into _tar_cache."""
    if pkg in _tar_cache:
        return True
    tar_path = _open_tar_for_pkg(pkg_dir)
    if not tar_path:
        return False
    try:
        with tarfile.open(tar_path, "r:gz") as tf:
            members = tf.getnames()
            # Determine root dir (first directory-level member)
            root = None
            for m in members:
                top = m.split("/")[0]
                if top:
                    root = top
                    break
            _tar_root[pkg] = root or ""
            _tar_cache[pkg] = {}
            for m in members:
                if not m.endswith(".py"):
                    continue
                try:
                    fobj = tf.extractfile(m)
                    if fobj is None:
                        continue
                    lines = io.TextIOWrapper(fobj, encoding="utf-8", errors="replace").readlines()
                    _tar_cache[pkg][m] = lines
                except Exception:
                    pass
    except Exception:
        return False
    return True


def get_line_tar(pkg, pkg_dir, json_rel_path, line_no):
    if not _load_pkg_tar(pkg, pkg_dir):
        return None
    root = _tar_root.get(pkg, "")
    member = _resolve_tar_member(pkg, json_rel_path, root)

    lines = _tar_cache[pkg].get(member)
    if lines is None:
        # Fallback: suffix match (handles edge-cases)
        suffix = json_rel_path.lstrip("/")
        for key, val in _tar_cache[pkg].items():
            if key.endswith(suffix):
                lines = val
                _tar_cache[pkg][member] = val  # cache resolved
                break
    if lines is None:
        return None
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return None


# ─── Generic fix logic ───────────────────────────────────────────────────────

def fix_text_generic(text, file_path, line_no, mode, source_root=None,
                     pkg=None, pkg_dir=None):
    if not IS_CFN.match(text):
        return text, False
    if mode == "filesystem":
        actual = get_line_fs(source_root, file_path, line_no)
    else:
        actual = get_line_tar(pkg, pkg_dir, file_path, line_no)
    if actual and actual.strip():
        return actual, True
    return text, False


def fix_chain(chain, mode, source_root=None, pkg=None, pkg_dir=None):
    stats = {"fixed": 0, "unfixable": 0}

    def try_fix(text, file_path, line_str):
        try:
            line_no = int(line_str)
        except (ValueError, TypeError):
            return text, False
        return fix_text_generic(text, file_path, line_no, mode,
                                source_root=source_root, pkg=pkg, pkg_dir=pkg_dir)

    # sensitive_api
    api = chain.get("sensitive_api", "")
    if IS_CFN.match(api):
        loc = chain.get("location", "")
        if ":" in loc:
            loc_file, loc_line = loc.rsplit(":", 1)
            new, ok = try_fix(api, loc_file, loc_line)
            chain["sensitive_api"] = new
            stats["fixed" if ok else "unfixable"] += 1

    # data_flow_slice
    for entry in chain.get("data_flow_slice", []):
        if IS_CFN.match(entry.get("text", "")):
            new, ok = try_fix(entry["text"], entry.get("file", ""), entry.get("line", 0))
            entry["text"] = new
            stats["fixed" if ok else "unfixable"] += 1

    # control_conditions
    for cond in chain.get("control_conditions", []):
        if IS_CFN.match(cond.get("condition", "")):
            new, ok = try_fix(cond["condition"], cond.get("file", ""), cond.get("line", 0))
            cond["condition"] = new
            stats["fixed" if ok else "unfixable"] += 1

    return stats


def fix_json_file(json_path, mode, source_root=None, pkg=None, pkg_dir=None,
                  dry_run=False):
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    total = {"fixed": 0, "unfixable": 0}
    for chain in data.get("behavior_chains", []):
        s = fix_chain(chain, mode, source_root=source_root, pkg=pkg, pkg_dir=pkg_dir)
        total["fixed"] += s["fixed"]
        total["unfixable"] += s["unfixable"]

    if not dry_run and total["fixed"] > 0:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    return total


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=list(DATASETS.keys()),
                        default="benign_test_set")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cfg = DATASETS[args.dataset]
    json_dir = cfg["json_dir"]
    mode = cfg["mode"]

    json_files = sorted(f for f in os.listdir(json_dir) if f.endswith(".json"))
    print(f"[*] Dataset: {args.dataset} ({len(json_files)} αρχεία), "
          f"mode={mode}, dry-run={args.dry_run}\n")

    total_fixed = 0
    total_unfixable = 0
    files_improved = 0
    files_skipped = 0

    for fname in json_files:
        pkg = fname.replace(".json", "")
        json_path = os.path.join(json_dir, fname)

        if mode == "filesystem":
            source_root = cfg["get_source_root"](pkg)
            if not os.path.isdir(source_root):
                print(f"  [!] {pkg}: source dir δεν βρέθηκε")
                files_skipped += 1
                continue
            stats = fix_json_file(json_path, mode, source_root=source_root,
                                  dry_run=args.dry_run)
        else:  # tarball
            pkg_dir = cfg["get_pkg_dir"](pkg)
            if not os.path.isdir(pkg_dir):
                files_skipped += 1
                continue
            stats = fix_json_file(json_path, mode, pkg=pkg, pkg_dir=pkg_dir,
                                  dry_run=args.dry_run)
            # Free memory after each package (tar cache can be large)
            _tar_cache.pop(pkg, None)
            _tar_root.pop(pkg, None)

        total_fixed += stats["fixed"]
        total_unfixable += stats["unfixable"]
        if stats["fixed"] > 0:
            files_improved += 1
            mark = "(dry)" if args.dry_run else "✓"
            print(f"  [{mark}] {pkg}: {stats['fixed']} fixed, "
                  f"{stats['unfixable']} unfixable")
        # (silent for unchanged files to keep output clean)

    print(f"\n{'='*60}")
    print(f"[✓] Συνολικά fixed:       {total_fixed}")
    print(f"[!] Unfixable (no match): {total_unfixable}")
    print(f"[*] Αρχεία βελτιώθηκαν:  {files_improved}/{len(json_files)}")
    if files_skipped:
        print(f"[!] Παραλείφθηκαν:       {files_skipped} (source δεν βρέθηκε)")
    print(f'\nΈλεγχος: grep -l "ControlFlowNode for" "{json_dir}"/*.json | wc -l')


if __name__ == "__main__":
    main()

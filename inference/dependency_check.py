"""
dependency_check.py - interpackage analysis at the level of the dependency graph.

The rest of the pipeline analyses the code of ONE package (CodeQL, Behavior Chains, RAG, LLM). This module
adds the edges of the dependency graph: the packages a package DECLARES (install_requires, setup_requires,
Requires-Dist, pyproject dependencies and build requirements, requirements files) and, through the PyPI
metadata of each of them, their own dependencies (transitively, up to MAX_DEPTH). Every node of the graph is
checked against a registry of known malicious PyPI packages (OpenSSF malicious-packages, OSV format). A
package that pulls in a malicious package is itself malicious, whatever its own code does: the typical
"dropper" is an innocuous package whose only payload is the malicious dependency it installs. Import names
are not used, because a module name is not a PyPI project name (see check()).

Dependencies are analysed as packages of their own (each with its own verdict), not by mixing their code
into the Behavior Chains of the package that uses them: this keeps every Behavior Chain attributed to the
package that contains it.

A dependency counts as malicious when:
  - an OSV entry marks EVERY version of it as malicious (range introduced=0, no fix), or
  - an OSV entry lists specific malicious versions and the project no longer exists on PyPI (PyPI removes
    confirmed malicious projects), or
  - the requirement pins exactly one of the listed malicious versions.
A legitimate project with a few compromised releases that is still on PyPI with other versions is NOT
flagged for an unpinned requirement (the installed version cannot be resolved statically).

Second registry - the verdicts of this system (load_own_verdicts): a dependency that this system has
itself judged MALICIOUS (its own Behavior Chains, final_verdict of a report) counts as well, so that a
malicious dependency is caught before it is listed in OSV (typically an attacker uploads the dropper and
its payload package together). To keep a single wrong verdict on a popular library from flagging every
package that depends on it, this applies only to projects outside the ESTABLISHED list (the 15,000 most
downloaded PyPI projects); compromised releases of established projects are covered by OSV.

Usage: python3 inference/dependency_check.py PATH [PATH ...]   (a package folder or archive)
"""
import ast
import atexit
import configparser
import json
import os
import re
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
import warnings
import zipfile

from packaging.requirements import InvalidRequirement, Requirement

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_ROOT, "dataset", "preparation"))
from utils import SOURCES_DIR  # noqa: E402  (also loads the .env)

OSV_DIR = os.environ.get("THESIS_OSV_DIR") or os.path.join(SOURCES_DIR, "malicious-packages", "osv", "malicious", "pypi")
# PyPI existence lookups are cached, so that a re-run gives the same answer and needs no network
PYPI_CACHE = os.path.join(_ROOT, "work", "pypi_project_cache.json")
# established projects (see the docstring): hugovk/top-pypi-packages, 15,000 most downloaded (30 days)
TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
TOP_PYPI_CACHE = os.path.join(_ROOT, "work", "top_pypi.json")

METADATA_FILES = {"PKG-INFO", "METADATA", "requires.txt", "setup.py", "setup.cfg", "pyproject.toml"}
REQUIREMENTS_FILE = re.compile(r"requirements[\w.-]*\.txt$", re.I)
# folders whose metadata files belong to test fixtures, documentation, bundled or installed code
SKIP_DIRS = {"test", "tests", "testing", "doc", "docs", "example", "examples", "vendor", "site-packages",
             "node_modules", ".venv", "venv", "__pycache__", ".git"}
ARCHIVES = (".tar.gz", ".tgz", ".tar.bz2", ".tar", ".zip", ".whl", ".egg")
MAX_FILE_BYTES = 1_000_000


def norm(name):
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


# ---------------------------------------------------------------- declared dependencies
def _requirement(text):
    """(name, pinned version or None) of one requirement string; None for optional (extra) or unusable lines."""
    text = text.split(" #", 1)[0].strip()
    if not text or text.startswith(("#", "-", "git+", "http://", "https://", "file:")):
        return None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", text)
        return (norm(m.group(0)), None) if m else None
    if req.marker is not None and "extra" in str(req.marker):
        return None  # only installed on request (pip install pkg[extra])
    pins = [s.version for s in req.specifier if s.operator in ("==", "===") and "*" not in s.version]
    return norm(req.name), (pins[0] if len(pins) == 1 else None)


def _from_setup_py(source):
    """install_requires / setup_requires / requires of the setup() call (literal lists, or a module-level
    variable holding one)."""
    try:
        with warnings.catch_warnings():  # the analysed code is not ours: silence its SyntaxWarnings
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    consts[t.id] = node.value
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "setup":
            for kw in node.keywords:
                if kw.arg in ("install_requires", "setup_requires", "requires"):
                    value = consts.get(kw.value.id) if isinstance(kw.value, ast.Name) else kw.value
                    if isinstance(value, (ast.List, ast.Tuple)):
                        out += [e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return out


def _from_setup_cfg(source):
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read_string(source)
    except configparser.Error:
        return []
    out = []
    for key in ("install_requires", "setup_requires"):
        out += [l for l in cfg.get("options", key, fallback="").splitlines() if l.strip()]
    return out


def _from_pyproject(source):
    try:
        data = tomllib.loads(source)
    except tomllib.TOMLDecodeError:
        return []
    out = list(data.get("project", {}).get("dependencies", []) or [])
    out += list(data.get("build-system", {}).get("requires", []) or [])  # fetched when the package is built
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    out += [k for k in poetry if k.lower() != "python"]
    return out


def _from_metadata(source):
    """Requires-Dist lines of PKG-INFO / METADATA."""
    return [l.split(":", 1)[1].strip() for l in source.splitlines() if l.lower().startswith("requires-dist:")]


def _from_requires_txt(source):
    """egg-info requires.txt: the unconditional part and the environment-marker sections ([:marker]), not
    the named extras."""
    out, keep = [], True
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("["):
            keep = line.startswith("[:")
        elif line and keep:
            out.append(line)
    return out


def _parse_file(name, source):
    base = os.path.basename(name)
    if base == "setup.py":
        return _from_setup_py(source)
    if base == "setup.cfg":
        return _from_setup_cfg(source)
    if base == "pyproject.toml":
        return _from_pyproject(source)
    if base in ("PKG-INFO", "METADATA"):
        return _from_metadata(source)
    if base == "requires.txt":
        return _from_requires_txt(source)
    return [l for l in source.splitlines()]  # requirements*.txt


def _wanted(path):
    parts = path.replace("\\", "/").split("/")
    return ((parts[-1] in METADATA_FILES or REQUIREMENTS_FILE.search(parts[-1]))
            and not any(p.lower() in SKIP_DIRS for p in parts[:-1]))


def _archive_files(path):
    """(member name, text) of the metadata files inside an sdist / wheel / egg archive."""
    try:
        if path.endswith((".zip", ".whl", ".egg")):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if _wanted(info.filename) and info.file_size <= MAX_FILE_BYTES:
                        yield info.filename, z.read(info).decode("utf-8", "replace")
        else:
            with tarfile.open(path) as t:
                for m in t.getmembers():
                    if m.isfile() and _wanted(m.name) and m.size <= MAX_FILE_BYTES:
                        yield m.name, t.extractfile(m).read().decode("utf-8", "replace")
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, RuntimeError):
        return


def _files(path):
    """(name, text) of every metadata file of a package folder or archive (archives inside folders too)."""
    if os.path.isfile(path):
        if path.endswith(ARCHIVES):
            yield from _archive_files(path)
        elif _wanted(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                yield path, f.read(MAX_FILE_BYTES)
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            full = os.path.join(root, f)
            if f.endswith(ARCHIVES):
                yield from _archive_files(full)
            elif _wanted(full) and os.path.getsize(full) <= MAX_FILE_BYTES:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    yield full, fh.read()


def declared_dependencies(path):
    """{normalised name: pinned version or None} of every dependency the package declares."""
    deps = {}
    for name, text in _files(path):
        for line in _parse_file(name, text):
            r = _requirement(line)
            if r:
                deps[r[0]] = deps.get(r[0]) or r[1]
    return deps


# ---------------------------------------------------------------- known-malicious registry
_REGISTRY = None


def registry():
    """{normalised name: {"ids", "all_versions", "versions"}} from the OSV malicious-packages folder."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = {}
        if not os.path.isdir(OSV_DIR):
            raise SystemExit(f"OSV folder not found: {OSV_DIR} (set THESIS_OSV_DIR or THESIS_SOURCES_DIR)")
        for pkg in os.listdir(OSV_DIR):
            folder = os.path.join(OSV_DIR, pkg)
            if not os.path.isdir(folder):
                continue
            for fname in os.listdir(folder):
                if not fname.endswith(".json"):
                    continue
                with open(os.path.join(folder, fname), encoding="utf-8") as f:
                    entry = json.load(f)
                if entry.get("withdrawn"):
                    continue
                rec = _REGISTRY.setdefault(norm(pkg), {"ids": [], "all_versions": False, "versions": set()})
                rec["ids"].append(entry.get("id"))
                for aff in entry.get("affected", []):
                    events = [e for r in aff.get("ranges", []) for e in r.get("events", [])]
                    if any(e.get("introduced") == "0" for e in events) and not any(
                            "fixed" in e or "last_affected" in e for e in events):
                        rec["all_versions"] = True
                    rec["versions"].update(aff.get("versions", []))
    return _REGISTRY


_PYPI = None
_UNSAVED = 0


def _save_cache():
    """Write the PyPI cache (called every 50 new lookups and at exit)."""
    global _UNSAVED
    if _PYPI is not None and _UNSAVED:
        os.makedirs(os.path.dirname(PYPI_CACHE), exist_ok=True)
        with open(PYPI_CACHE, "w", encoding="utf-8") as f:
            json.dump(_PYPI, f, sort_keys=True)
        _UNSAVED = 0


atexit.register(_save_cache)


def _pypi_info(name):
    """{"releases": [...], "requires": {name: pin}} of a project on PyPI - "requires" are the unconditional
    dependencies of its latest release; {"releases": [], "requires": {}} if the project does not exist;
    None if PyPI could not be reached (not cached). Answers are cached in work/."""
    global _PYPI, _UNSAVED
    if _PYPI is None:
        _PYPI = json.load(open(PYPI_CACHE, encoding="utf-8")) if os.path.exists(PYPI_CACHE) else {}
    if not isinstance(_PYPI.get(name), dict):
        for attempt in range(4):
            try:
                with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=20) as r:
                    data = json.load(r)
                reqs = dict(filter(None, (_requirement(t) for t in data.get("info", {}).get("requires_dist") or [])))
                _PYPI[name] = {"releases": sorted(data.get("releases", {})), "requires": reqs}
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    _PYPI[name] = {"releases": [], "requires": {}}
                    break
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                pass
            time.sleep(2 ** attempt)
        else:
            return None
        _UNSAVED += 1
        if _UNSAVED >= 50:
            _save_cache()
    return _PYPI[name]


def pypi_requires(name, version):
    """{name: pin} of the unconditional Requires-Dist of ONE release on PyPI (None if unavailable), cached."""
    global _PYPI, _UNSAVED
    _pypi_info("pip")  # makes sure the cache is loaded
    key = f"{norm(name)}=={version}"
    if key not in _PYPI:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{norm(name)}/{version}/json", timeout=20) as r:
                reqs = json.load(r).get("info", {}).get("requires_dist") or []
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
        _PYPI[key] = dict(filter(None, (_requirement(t) for t in reqs)))
        _UNSAVED += 1
    return _PYPI[key]


_OWN = {}
_ESTABLISHED = None


def load_own_verdicts(result_dirs):
    """Second registry: {package: report} of every package this system judged MALICIOUS from its own code
    (final_verdict of the reports in result_dirs). Obfuscated evaluation copies are not real projects."""
    for d in result_dirs:
        for fname in os.listdir(d):
            if not (fname.startswith("report_") and fname.endswith(".json")) or "--obf" in fname:
                continue
            with open(os.path.join(d, fname), encoding="utf-8") as f:
                report = json.load(f)
            if report.get("final_verdict") == "MALICIOUS":
                _OWN[norm(report.get("package_name") or fname[7:-5])] = os.path.relpath(os.path.join(d, fname), _ROOT)
    return _OWN


def established():
    """Normalised names of the established PyPI projects (TOP_PYPI_URL), downloaded once into work/."""
    global _ESTABLISHED
    if _ESTABLISHED is None:
        if not os.path.exists(TOP_PYPI_CACHE):
            req = urllib.request.Request(TOP_PYPI_URL, headers={"User-Agent": "thesis-dependency-check"})
            os.makedirs(os.path.dirname(TOP_PYPI_CACHE), exist_ok=True)
            with urllib.request.urlopen(req, timeout=60) as r, open(TOP_PYPI_CACHE, "wb") as out:
                out.write(r.read())
        with open(TOP_PYPI_CACHE, encoding="utf-8") as f:
            _ESTABLISHED = {norm(r["project"]) for r in json.load(f)["rows"]}
    return _ESTABLISHED


def is_malicious(name, pinned=None):
    """(True, reason, OSV ids) if the dependency is a known malicious package, else (False, None, ids)."""
    rec = registry().get(norm(name))
    if rec:
        if rec["all_versions"]:
            return True, "every version is malicious (OSV)", rec["ids"]
        if pinned and pinned in rec["versions"]:
            return True, f"pinned version {pinned} is malicious (OSV)", rec["ids"]
        info = _pypi_info(norm(name))
        if info is not None and not [v for v in info["releases"] if v not in rec["versions"]]:
            return True, "malicious versions listed in OSV and no other release on PyPI", rec["ids"]
    own = _OWN.get(norm(name))
    if own and norm(name) not in established():
        return True, f"judged MALICIOUS by this system ({own})", rec["ids"] if rec else []
    return False, None, rec["ids"] if rec else []


# Transitive dependencies are followed through the PyPI metadata of each dependency (its latest release)
MAX_DEPTH = 3
MAX_NODES = 400


def check(own_name, declared):
    """Findings for one package: every known malicious package in its dependency graph - the dependencies
    it declares (depth 1) and, through PyPI metadata, their own dependencies (up to MAX_DEPTH). Import
    names are not used: a module name (e.g. win32con of pywin32) is not a PyPI project name, and attackers
    register such names on purpose. The package's own name is never counted."""
    own = norm(own_name or "")
    findings, seen = [], {own}
    frontier = [(dep, pin, [dep]) for dep, pin in sorted((declared or {}).items())]
    for depth in range(1, MAX_DEPTH + 1):
        nxt = []
        for dep, pin, path in frontier:
            if dep in seen or len(seen) > MAX_NODES:
                continue
            seen.add(dep)
            bad, reason, ids = is_malicious(dep, pin)
            if bad:
                findings.append({"dependency": dep, "depth": depth, "via": path, "reason": reason, "osv_ids": ids})
            elif depth < MAX_DEPTH:
                info = _pypi_info(dep)
                if info:
                    nxt += [(d, p, path + [d]) for d, p in sorted(info["requires"].items())]
        frontier = nxt
    return findings


if __name__ == "__main__":
    for p in sys.argv[1:]:
        d = declared_dependencies(p)
        print(json.dumps({"path": p, "declared": d, "findings": check(os.path.basename(p.rstrip("/")), d)},
                         indent=2))

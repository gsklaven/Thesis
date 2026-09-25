"""
harvest_policy_sources.py - collect the third-party sources of the security knowledge base.

Every source is written to policy_sources/<file>.json in the format {source, rules: [{id, name,
description}]} that build_policy_dataset.py loads:

  source                                          file                          taken from
  GuardDog detection rules (Semgrep + YARA)       guarddog_rules.json           DataDog/guarddog
  GuardDog metadata heuristics (PyPI + npm)       guarddog_metadata_rules.json  DataDog/guarddog
  Bandit security checks (B1xx-B7xx)              bandit_rules.json             PyCQA/bandit
  Semgrep community rules, Python security  (*)   semgrep_rules.json            semgrep/semgrep-rules
  Registry acceptable-use policies (verbatim)     registry_policies.json        pypi.org, docs.npmjs.com,
                                                                                docs.github.com
No LLM is involved: the tool rules are already structured (each has an id and a description) and the
registry clauses are copied verbatim. The other files of policy_sources/ (OWASP, SLSA, threat-hunting
heuristics) are written by hand.

(*) Semgrep Rules License v1.0 (https://semgrep.dev/legal/rules-license): internal use only, the rules may
    NOT be distributed. semgrep_rules.json is git-ignored and every rule carries a "license" field; do not
    publish it or any file that embeds its text (policy_rules.json, indexes/policy_index/policy_metadata.json).

Usage: python3 dataset/preparation/harvest_policy_sources.py [REPOS_DIR]
  REPOS_DIR (default: work/policy_repos) holds shallow clones of the three repositories; missing ones are
  cloned. Next steps: build_policy_dataset.py, build_policy_index.py (./run_pipeline.sh policy runs all three).
"""
import ast
import html
import json
import os
import re
import subprocess
import sys
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "policy_sources")
DEFAULT_REPOS_DIR = os.path.join(HERE, "..", "..", "work", "policy_repos")
REPOS = ("DataDog/guarddog", "PyCQA/bandit", "semgrep/semgrep-rules")
SEMGREP_LICENSE = ("Semgrep Rules License v1.0 - (c) Semgrep, Inc. - https://semgrep.dev/legal/rules-license"
                   " - internal use only, do not distribute")
PYPI = "https://pypi.org/policy/acceptable-use-policy/"
NPM = "https://docs.npmjs.com/policies/open-source-terms"
GH = "https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits"


def squash(text):
    """Collapse all whitespace (newlines, indentation) into single spaces."""
    return re.sub(r"\s+", " ", text).strip()


def write(fname, source, rules):
    """Write one policy_sources file ({source, rules}), keeping the first rule of every id."""
    seen, uniq = set(), []
    for r in rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            uniq.append(r)
    with open(os.path.join(OUT_DIR, fname), "w", encoding="utf-8") as f:
        json.dump({"source": source, "rules": uniq}, f, indent=4, ensure_ascii=False)
    print(f"[+] {fname}: {len(uniq)} rules")


# ------------------------------------------------------------------ GuardDog detection rules
def _guarddog_semgrep(fpath):
    """Rules of one GuardDog Semgrep .yml file (a file may contain several rules under 'rules:')."""
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"  [!] Skipped {fpath}: {e}")
        return []
    if not data or "rules" not in data:
        return []
    entries = []
    for rule in data["rules"]:
        rule_id = rule.get("id", os.path.basename(fpath))
        metadata = rule.get("metadata", {}) or {}
        # prefer the documented description, fall back to the rule's message
        description = metadata.get("description") or rule.get("message", "")
        entries.append({"id": f"GUARDDOG-SEMGREP-{rule_id}", "name": rule_id, "description": description})
    return entries


def _guarddog_yara(fpath):
    """Rule name + meta.description of each rule of a GuardDog .yar file, by regex (no YARA parser needed)."""
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"  [!] Skipped {fpath}: {e}")
        return []
    entries = []
    # every "rule <name> { ... }" block
    for match in re.finditer(r'rule\s+(\w+)\s*\{(.*?)\n\}', content, re.DOTALL):
        desc_match = re.search(r'description\s*=\s*"([^"]*)"', match.group(2))
        entries.append({"id": f"GUARDDOG-YARA-{match.group(1)}", "name": match.group(1),
                        "description": desc_match.group(1) if desc_match else ""})
    return entries


def guarddog_rules(repo):
    """GuardDog source-code rules (Semgrep .yml and YARA .yar under analyzer/sourcecode), with a description."""
    rules = []
    for root, _, files in os.walk(repo):
        # only inside analyzer/sourcecode - that is where the rules live, not tests/CI configs
        if "sourcecode" not in root:
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname.endswith((".yml", ".yaml")):
                rules.extend(_guarddog_semgrep(fpath))
            elif fname.endswith(".yar"):
                rules.extend(_guarddog_yara(fpath))
    # rules without any description add nothing to retrieval
    return [r for r in rules if r["description"].strip()]


# ------------------------------------------------------------------ GuardDog metadata heuristics
def guarddog_metadata(repo):
    """GuardDog metadata heuristics (PyPI + npm): rule name from RULE_NAME, description from the first
    paragraph of the module (or class) docstring; very short descriptions are dropped."""
    rules = []
    base = os.path.join(repo, "guarddog", "analyzer", "metadata")
    for eco in ("pypi", "npm"):
        d = os.path.join(base, eco)
        for fname in sorted(os.listdir(d)):
            if fname in ("__init__.py", "utils.py") or not fname.endswith(".py"):
                continue
            src = open(os.path.join(d, fname), encoding="utf-8").read()
            doc = ast.get_docstring(ast.parse(src)) or ""
            # the rule name is the RULE_NAME constant of the detector (fallback: file name)
            m = re.search(r'RULE_NAME\s*=\s*"([^"]+)"', src)
            name = m.group(1) if m else fname[:-3]
            desc = squash(doc.split("\n\n")[0] if doc else "")
            if not desc:
                cls = re.search(r'class\s+\w+\(.*?\):\s*"""(.*?)"""', src, re.S)
                desc = squash(cls.group(1)) if cls else ""
            if len(desc) >= 40:
                rules.append({"id": f"GUARDDOG-META-{eco}-{name}", "name": f"{name} ({eco})",
                              "description": desc})
    return rules


# ------------------------------------------------------------------ Bandit
# section header of a Bandit docstring:  ====\nB101: title\n====
BANDIT_HEADER = re.compile(r"^={3,}\n(B\d{3}): (.+?)\n={3,}$", re.M)
# first line of a Bandit check function docstring: **B301: title**
BANDIT_FUNC_HEAD = re.compile(r"^\*\*(B\d{3}): (.+?)\*\*\s*", re.S)


def _bandit_from_docstring(doc, rules):
    """Append the rules documented in a Bandit plugin's module docstring (sections headed 'Bxxx: title'
    between ==== lines), without the example/see-also parts."""
    heads = list(BANDIT_HEADER.finditer(doc))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(doc)
        body = doc[h.end():end]
        body = re.split(r"\n:Example:|\n\.\. seealso::|\n\.\. versionadded::|\n:Example", body)[0]
        cwe = re.search(r"CWE: (CWE-\d+)", doc[h.end():end])
        desc = squash(body)
        if desc:
            rules.append({"id": f"BANDIT-{h.group(1)}", "name": f"{h.group(1)}: {h.group(2)}",
                          "description": desc + (f" (Related: {cwe.group(1)})" if cwe else "")})


def bandit_rules(repo):
    """Bandit checks from three places: plugin module docstrings, plugin function docstrings
    ('**Bxxx: title**') and the blacklist definitions (calls.py / imports.py)."""
    rules = []
    pdir = os.path.join(repo, "bandit", "plugins")
    for fname in sorted(os.listdir(pdir)):
        if not fname.endswith(".py") or fname == "__init__.py":
            continue
        tree = ast.parse(open(os.path.join(pdir, fname), encoding="utf-8").read())
        _bandit_from_docstring(ast.get_docstring(tree) or "", rules)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                d = ast.get_docstring(node) or ""
                m = BANDIT_FUNC_HEAD.match(d)
                if m:
                    body = re.split(r"\n:Example:|\n\.\. seealso::|\n\.\. versionadded::", d[m.end():])[0]
                    desc = squash(body)
                    if desc:
                        rules.append({"id": f"BANDIT-{m.group(1)}", "name": f"{m.group(1)}: {m.group(2)}",
                                      "description": desc})
    # blacklist checks (eval, pickle, marshal, urllib, telnet, ...) are data, not plugins
    for fname in ("calls.py", "imports.py"):
        tree = ast.parse(open(os.path.join(repo, "bandit", "blacklists", fname), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "build_conf_dict" and len(node.args) >= 5:
                a = node.args
                try:
                    name, bid = a[0].value, a[1].value
                    names = [e.value for e in a[3].elts if isinstance(e, ast.Constant)]
                    msg = squash(a[4].value)
                except (AttributeError, TypeError):
                    continue
                kind = "calls" if fname == "calls.py" else "imports"
                rules.append({"id": f"BANDIT-{bid}", "name": f"{bid}: {name}",
                              "description": f"{msg} Flags use of ({kind}): {', '.join(names[:8])}."})
    return rules


# ------------------------------------------------------------------ Semgrep
def semgrep_rules(repo):
    """Every Python rule with metadata.category == security of semgrep-rules (message + CWE, license noted
    on every rule)."""
    rules = []
    for dp, _, files in os.walk(os.path.join(repo, "python")):
        for fn in sorted(files):
            if not fn.endswith((".yaml", ".yml")):
                continue
            try:
                data = yaml.safe_load(open(os.path.join(dp, fn), encoding="utf-8"))
            except Exception:
                continue
            for r in (data or {}).get("rules", []) or []:
                md = r.get("metadata") or {}
                # security rules for Python only
                if str(md.get("category", "")).lower() != "security" or "python" not in (r.get("languages") or []):
                    continue
                msg = squash(str(r.get("message", "")))
                rid = r.get("id")
                if not rid or not msg:
                    continue
                cwe = md.get("cwe")
                cwe = ", ".join(cwe) if isinstance(cwe, list) else (cwe or "")
                rules.append({"id": f"SEMGREP-{rid}", "name": rid.split(".")[-1].replace("-", " "),
                              "description": msg + (f" (CWE: {cwe})" if cwe else ""), "license": SEMGREP_LICENSE})
    return rules


# ------------------------------------------------------------------ registry policies
def _paragraphs(url, article_only=False):
    """Visible text paragraphs of a web page (scripts, styles, navigation, header and footer removed);
    optionally only the <article>/<main> part."""
    raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}),
                                 timeout=60).read().decode("utf-8", "replace")
    if article_only:
        m = re.search(r"<article.*?</article>|<main.*?</main>", raw, re.S)
        raw = m.group(0) if m else raw
    raw = re.sub(r"<script.*?</script>|<style.*?</style>|<nav.*?</nav>|<header.*?</header>|<footer.*?</footer>",
                 "", raw, flags=re.S)
    raw = re.sub(r"</?(p|li|ul|ol|h[1-6]|div|br|tr|table|section|article)[^>]*>", "\n", raw)
    text = html.unescape(re.sub(r"<[^>]+>", "", raw))
    return [re.sub(r"\s+", " ", p).strip() for p in text.split("\n") if p.strip()]


def _span(paras, start, end=None, include_end=False):
    """The paragraph that starts with `start`, or the joined paragraphs from it up to the one starting
    with `end` (inclusive if include_end)."""
    i = next(k for k, p in enumerate(paras) if p.startswith(start))
    if end is None:
        return paras[i]
    j = next(k for k in range(i + 1, len(paras)) if paras[k].startswith(end))
    return " ".join(paras[i:j + (1 if include_end else 0)])


def registry_policies():
    """The verbatim clauses of the PyPI / npm / GitHub acceptable-use policies about malware and name
    squatting (fetched from the live pages)."""
    py, npm, gh = _paragraphs(PYPI), _paragraphs(NPM), _paragraphs(GH, article_only=True)
    # (id, name, verbatim text, source url) of every clause
    clauses = [
        ("PYPI-AUP-ACTIVE-MALWARE", "PyPI AUP: Active Malware or Exploits",
         _span(py, "Being part of a community includes not taking advantage", "Advertising"), PYPI),
        ("PYPI-AUP-UNAUTHORIZED-ACCESS", "PyPI AUP: Unauthorized access / disruption",
         _span(py, "You may not use our servers to disrupt", "You may not use information from PyPI"), PYPI),
        ("NPM-TERMS-MALICIOUS-CODE", "npm Terms: Acceptable Content - malicious computer code",
         _span(npm, "Content containing malicious computer code"), NPM),
        ("NPM-TERMS-NAME-SQUATTING", "npm Terms: Acceptable Content - name reservation / squatting",
         _span(npm, 'Content that exists only to "reserve" a name'), NPM),
        ("GITHUB-AUP-ACTIVE-MALWARE", "GitHub AUP: Active Malware or Exploits",
         _span(gh, "Being part of a community includes not taking advantage"), GH),
        ("GITHUB-AUP-NPM-REGISTRY", "GitHub AUP: npm registry is for installation and run-time use, not research",
         _span(gh, "GitHub considers the npm registry"), GH),
    ]
    return [{"id": i, "name": n, "description": f"{d} [Source: {u}]"} for i, n, d, u in clauses]


# ------------------------------------------------------------------ main
def clone_missing(repos_dir):
    """Shallow-clone every repository of REPOS that is not in repos_dir yet; return {name: path}."""
    os.makedirs(repos_dir, exist_ok=True)
    paths = {}
    for repo in REPOS:
        name = repo.split("/")[1]
        paths[name] = os.path.join(repos_dir, name)
        if not os.path.isdir(paths[name]):
            print(f"[*] git clone --depth=1 {repo}")
            subprocess.run(["git", "clone", "-q", "--depth=1", f"https://github.com/{repo}.git", paths[name]],
                           check=True)
    return paths


def main():
    """Clone the missing repositories and write every harvested source to policy_sources/."""
    repos_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPOS_DIR)
    repo = clone_missing(repos_dir)
    os.makedirs(OUT_DIR, exist_ok=True)
    write("guarddog_rules.json", "GuardDog (Datadog) Detection Rules", guarddog_rules(repo["guarddog"]))
    write("guarddog_metadata_rules.json", "GuardDog (Datadog) Metadata Heuristics",
          guarddog_metadata(repo["guarddog"]))
    write("bandit_rules.json", "Bandit (PyCQA) Security Checks", bandit_rules(repo["bandit"]))
    write("semgrep_rules.json",
          "Semgrep Community Rules - Python security [Semgrep Rules License v1.0, internal use]",
          semgrep_rules(repo["semgrep-rules"]))
    write("registry_policies.json", "Package Registry Acceptable-Use Policies (PyPI / npm / GitHub)",
          registry_policies())
    print(f"[✓] -> {OUT_DIR}\nNext: build_policy_dataset.py && build_policy_index.py")


if __name__ == "__main__":
    main()

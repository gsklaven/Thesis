"""
harvest_extra_policy_sources.py

Additive policy sources (nothing existing is modified or removed). Extracts
third-party rules into policy_sources/*.json in the same {source, rules:[{id,
name, description}]} format the policy index builder already loads:

  * GuardDog (Datadog) metadata heuristics  (PyPI + npm detectors)
  * Bandit (PyCQA) security checks           (B1xx-B7xx plugins)

Usage:
    git clone --depth=1 https://github.com/DataDog/guarddog.git /tmp/guarddog
    git clone --depth=1 https://github.com/PyCQA/bandit.git /tmp/bandit
    python3 dataset/preparation/harvest_extra_policy_sources.py /tmp/guarddog /tmp/bandit
Then (once, together with the RAG index rebuild):
    python3 build_policy_dataset.py && python3 build_policy_index.py
"""
import ast
import json
import os
import re
import sys

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy_sources")


def squash(text):
    """Collapse all whitespace (newlines, indentation) into single spaces."""
    return re.sub(r"\s+", " ", text).strip()


def guarddog_metadata(repo):
    """GuardDog metadata heuristics (PyPI + npm): rule name from RULE_NAME, description from the first paragraph of the module (or class) docstring; very short descriptions are dropped."""
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


# section header of a Bandit docstring:  ====\nB101: title\n====
HEADER = re.compile(r"^={3,}\n(B\d{3}): (.+?)\n={3,}$", re.M)


def _bandit_from_docstring(doc, rules):
    """Append the rules documented in a Bandit plugin's module docstring (sections headed 'Bxxx: title' between ==== lines), without the example/see-also parts."""
    heads = list(HEADER.finditer(doc))
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(doc)
        body = doc[h.end():end]
        body = re.split(r"\n:Example:|\n\.\. seealso::|\n\.\. versionadded::|\n:Example", body)[0]
        cwe = re.search(r"CWE: (CWE-\d+)", doc[h.end():end])
        desc = squash(body)
        if desc:
            rules.append({"id": f"BANDIT-{h.group(1)}", "name": f"{h.group(1)}: {h.group(2)}",
                          "description": desc + (f" (Related: {cwe.group(1)})" if cwe else "")})


# first line of a Bandit check function docstring: **B301: title**
FUNC_HEAD = re.compile(r"^\*\*(B\d{3}): (.+?)\*\*\s*", re.S)


def bandit_rules(repo):
    """Bandit checks from three places: plugin module docstrings, plugin function docstrings ('**Bxxx: title**') and the blacklist definitions (calls.py / imports.py)."""
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
                m = FUNC_HEAD.match(d)
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


def main():
    """Usage: harvest_extra_policy_sources.py <guarddog repo> <bandit repo>."""
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    write("guarddog_metadata_rules.json", "GuardDog (Datadog) Metadata Heuristics", guarddog_metadata(sys.argv[1]))
    write("bandit_rules.json", "Bandit (PyCQA) Security Checks", bandit_rules(sys.argv[2]))


if __name__ == "__main__":
    main()

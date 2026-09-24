"""
harvest_semgrep_python_rules.py

Extracts the Python SECURITY rules (metadata.category == security) of the
Semgrep community rules (semgrep/semgrep-rules).

LICENSE: Semgrep Rules License v1.0 (https://semgrep.dev/legal/rules-license):
internal use only, the rules may NOT be distributed, and licence notices must be
kept. The output file is therefore git-ignored, and each rule carries a
"license" field. Do not publish policy_sources/semgrep_rules.json or any file
that embeds its text (policy_rules.json, indexes/policy_index/policy_metadata.json).

Usage: python3 harvest_semgrep_python_rules.py /path/to/semgrep-rules
"""
import json
import os
import re
import sys

import yaml

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy_sources", "semgrep_rules.json")
LICENSE = "Semgrep Rules License v1.0 - (c) Semgrep, Inc. - https://semgrep.dev/legal/rules-license - internal use only, do not distribute"


def main():
    root = os.path.join(sys.argv[1], "python")
    rules, seen = [], set()
    for dp, _, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith((".yaml", ".yml")):
                continue
            try:
                data = yaml.safe_load(open(os.path.join(dp, fn), encoding="utf-8"))
            except Exception:
                continue
            for r in (data or {}).get("rules", []) or []:
                md = r.get("metadata") or {}
                if str(md.get("category", "")).lower() != "security" or "python" not in (r.get("languages") or []):
                    continue
                msg = re.sub(r"\s+", " ", str(r.get("message", ""))).strip()
                rid = r.get("id")
                if not rid or not msg or rid in seen:
                    continue
                seen.add(rid)
                cwe = md.get("cwe")
                cwe = ", ".join(cwe) if isinstance(cwe, list) else (cwe or "")
                rules.append({"id": f"SEMGREP-{rid}", "name": rid.split(".")[-1].replace("-", " "),
                              "description": msg + (f" (CWE: {cwe})" if cwe else ""), "license": LICENSE})
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"source": "Semgrep Community Rules - Python security [Semgrep Rules License v1.0, internal use]",
                   "rules": rules}, f, indent=4, ensure_ascii=False)
    print(f"[+] {len(rules)} Python security rules -> {OUT}")


if __name__ == "__main__":
    main()

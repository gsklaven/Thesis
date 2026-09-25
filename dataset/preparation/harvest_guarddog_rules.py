"""
Extract the detection rules of GuardDog (Datadog) - Semgrep (.yml) and YARA (.yar) - into the
modular format of policy_sources/ ({source, rules: [{id, name, description}]}).

No LLM is involved: the rules are already structured, each with an explicit id and description.
They complement the Datadog SAMPLES of the dataset with the RULES of the same vendor.

Usage:
    git clone --depth=1 https://github.com/DataDog/guarddog.git /tmp/guarddog
    python3 harvest_guarddog_rules.py /tmp/guarddog
Output: policy_sources/guarddog_rules.json
"""

import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("[!] Required: pip install pyyaml --break-system-packages")
    sys.exit(1)

OUTPUT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "policy_sources", "guarddog_rules.json"
)


def parse_semgrep_yaml(fpath):
    """Rules of one Semgrep .yml file (a file may contain several rules under 'rules:')."""
    entries = []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"  [!] Skipped {fpath}: {e}")
        return entries

    if not data or "rules" not in data:
        return entries

    for rule in data["rules"]:
        rule_id = rule.get("id", os.path.basename(fpath))
        metadata = rule.get("metadata", {}) or {}
        # prefer the documented description, fall back to the rule's message
        description = metadata.get("description") or rule.get("message", "")
        entries.append({
            "id": f"GUARDDOG-SEMGREP-{rule_id}",
            "name": rule_id,
            "description": description,
        })
    return entries


def parse_yara_file(fpath):
    """Rule name + meta.description of each rule of a .yar file, by regex (no full YARA parser needed)."""
    entries = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"  [!] Skipped {fpath}: {e}")
        return entries

    # every "rule <name> { ... }" block
    for match in re.finditer(r'rule\s+(\w+)\s*\{(.*?)\n\}', content, re.DOTALL):
        rule_name = match.group(1)
        body = match.group(2)
        desc_match = re.search(r'description\s*=\s*"([^"]*)"', body)
        description = desc_match.group(1) if desc_match else ""
        entries.append({
            "id": f"GUARDDOG-YARA-{rule_name}",
            "name": rule_name,
            "description": description,
        })
    return entries


def main():
    """Walk the GuardDog repository, parse every rule file and write guarddog_rules.json."""
    if len(sys.argv) != 2:
        print("Usage: python3 harvest_guarddog_rules.py /path/to/guarddog_repo")
        sys.exit(1)

    repo_path = sys.argv[1]
    if not os.path.isdir(repo_path):
        print(f"[!] Not found: {repo_path}")
        sys.exit(1)

    all_rules = []
    yml_count = yar_count = 0

    for root, dirs, files in os.walk(repo_path):
        # only inside analyzer/sourcecode - that is where the rules live, not tests/CI configs
        if "sourcecode" not in root:
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname.endswith((".yml", ".yaml")):
                new_entries = parse_semgrep_yaml(fpath)
                all_rules.extend(new_entries)
                if new_entries:
                    yml_count += 1
            elif fname.endswith(".yar"):
                new_entries = parse_yara_file(fpath)
                all_rules.extend(new_entries)
                if new_entries:
                    yar_count += 1

    # rules without any description add nothing to retrieval
    all_rules = [r for r in all_rules if r["description"].strip()]

    print(f"[*] {yml_count} Semgrep files, {yar_count} YARA files read.")
    print(f"[+] {len(all_rules)} rules with a real description extracted.")

    output = {
        "source": "GuardDog (Datadog) Detection Rules",
        "rules": all_rules,
    }

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    print(f"[✓] -> {OUTPUT_FILE}")
    print(f"\nThen: python3 build_policy_dataset.py && python3 build_policy_index.py")


if __name__ == "__main__":
    main()

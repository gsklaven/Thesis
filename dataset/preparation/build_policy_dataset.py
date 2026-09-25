"""
Build the security knowledge base (policy store) of the Hybrid RAG: dataset/policy_rules.json.

Two kinds of sources:
  1. Downloaded at build time: MITRE ATT&CK Enterprise (STIX JSON), CWE and CAPEC (CSV archives).
     Only entries whose name/description mention a keyword relevant to malicious packages
     (RELEVANT_KEYWORDS) are kept.
  2. Local JSON files in policy_sources/ (tool rules such as GuardDog, Bandit and Semgrep, OWASP,
     SLSA, registry acceptable-use policies, heuristics). Every file is loaded as is, so a new
     category of rules only needs a new JSON file, no code change.

Every entry gets a text_for_embedding = "<name>. <description>" (see build_dataset()); the vector
index itself is built by build_policy_index.py.
"""
import json
import os
import io
import csv
import zipfile
import requests

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
OUTPUT_JSON = os.path.join(BASE_DIR, "policy_rules.json")
POLICY_SOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy_sources")

# ==========================================
# 1. DOWNLOADED SOURCES (APIs & repositories)
# ==========================================
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CAPEC_CSV_URL = "https://capec.mitre.org/data/csv/3000.csv.zip"

# an ATT&CK/CWE/CAPEC entry is kept only if its text mentions one of these
RELEVANT_KEYWORDS = [
    "injection", "supply chain", "download", "execution", "deserialization",
    "malicious", "authentication", "credential", "obfuscation", "dependency",
    "exfiltration", "backdoor", "typosquatting", "evasion", "stealth",
    "persistence", "payload", "socket", "reverse shell", "crypto", "miner"
]

# ==========================================
# 2. LOCAL SOURCES - one JSON file per source in policy_sources/
#    (see load_policy_source_files())
# ==========================================


def load_policy_source_files(directory=POLICY_SOURCES_DIR):
    """
    Load ALL .json files of policy_sources/. Each file has the form
        {"source": "...", "rules": [{"id": ..., "name": ..., "description": ...}, ...]}
    and every rule is returned with its "source" attached. A new category of rules only needs a
    new .json file here - no change to the Python code.
    """
    all_rules = []
    if not os.path.exists(directory):
        print(f"[!] Folder {directory} not found - create it and put .json files in it.")
        return all_rules

    json_files = sorted(f for f in os.listdir(directory) if f.endswith(".json"))
    for fname in json_files:
        path = os.path.join(directory, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            source = data.get("source", fname)
            rules = data.get("rules", [])
            for rule in rules:
                all_rules.append({"source": source, **rule})
            print(f"  [+] {fname}: {len(rules)} rules (source: {source})")
        except Exception as e:
            print(f"  [!] Error loading {fname}: {e}")

    print(f"[+] Total from policy_sources/: {len(all_rules)} rules from {len(json_files)} files.")
    return all_rules


# ==========================================
# DOWNLOAD AND FILTERING FUNCTIONS
# ==========================================

def is_relevant(text):
    """True if the text mentions at least one of RELEVANT_KEYWORDS (case-insensitive)."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in RELEVANT_KEYWORDS)


def fetch_mitre_attack():
    """Relevant, non-deprecated ATT&CK Enterprise techniques (attack-pattern objects of the STIX bundle)."""
    print("[*] Downloading MITRE ATT&CK Enterprise...")
    try:
        response = requests.get(MITRE_ATTACK_URL, timeout=30)
        response.raise_for_status()
        stix_data = response.json()
    except Exception as e:
        print(f"[!] MITRE download failed: {e}")
        return []

    mitre_rules = []
    for obj in stix_data.get("objects", []):
        # techniques only; skip revoked and deprecated ones
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # the technique id (e.g. T1059) is the external reference of source "mitre-attack"
        external_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), "UNKNOWN")
        name = obj.get("name", "")
        description = obj.get("description", "")

        if external_id != "UNKNOWN" and name and is_relevant(f"{name} {description}"):
            mitre_rules.append({
                "source": "MITRE ATT&CK", "id": external_id, "name": name, "description": description
            })

    print(f"[+] Fetched {len(mitre_rules)} techniques from MITRE ATT&CK.")
    return mitre_rules


def fetch_mitre_csv(url, source_name, id_prefix):
    """Generic download + parse of the CWE and CAPEC CSV archives published by MITRE (relevant rows only)."""
    print(f"[*] Downloading {source_name} from {url}...")
    rules = []
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # the archive contains a single CSV file
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                content = f.read().decode('utf-8', errors='ignore')
                reader = csv.DictReader(content.splitlines())

                # CWE names its id column 'CWE-ID', CAPEC 'ID'
                id_col = 'CWE-ID' if 'CWE-ID' in reader.fieldnames else 'ID'

                for row in reader:
                    rule_id = f"{id_prefix}-{row.get(id_col, '')}"
                    name = row.get('Name', '')
                    desc = row.get('Description', '')

                    if is_relevant(f"{name} {desc}"):
                        rules.append({
                            "source": source_name, "id": rule_id, "name": name, "description": desc
                        })
    except Exception as e:
        print(f"[!] {source_name} download failed: {e}")

    print(f"[+] Fetched {len(rules)} entries from {source_name}.")
    return rules


def build_dataset():
    """Collect all sources, add the embedding text of every entry and write policy_rules.json."""
    all_policies = []

    # 1. downloaded sources
    all_policies.extend(fetch_mitre_attack())
    all_policies.extend(fetch_mitre_csv(CWE_CSV_URL, "CWE Database", "CWE"))
    all_policies.extend(fetch_mitre_csv(CAPEC_CSV_URL, "CAPEC Attack Patterns", "CAPEC"))

    # 2. local sources (policy_sources/)
    print("[*] Adding the local policy_sources/...")
    all_policies.extend(load_policy_source_files())

    # The embedding text holds only semantic content (name + description): sentence-transformer
    # models were not trained on structured ids ("CWE-94", "CICD-SEC-3"), which would only add noise
    # to retrieval. Source and id are kept as metadata in policy_metadata.json.
    for policy in all_policies:
        policy["text_for_embedding"] = f"{policy['name']}. {policy['description']}"

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(all_policies, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Policy dataset built! Total rules: {len(all_policies)} -> {OUTPUT_JSON}")


if __name__ == "__main__":
    build_dataset()

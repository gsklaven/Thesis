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
# 1. ΔΥΝΑΜΙΚΕΣ ΠΗΓΕΣ (APIs & Repositories) - ΑΝΕΓΓΙΧΤΟ
# ==========================================
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CAPEC_CSV_URL = "https://capec.mitre.org/data/csv/3000.csv.zip"

RELEVANT_KEYWORDS = [
    "injection", "supply chain", "download", "execution", "deserialization",
    "malicious", "authentication", "credential", "obfuscation", "dependency",
    "exfiltration", "backdoor", "typosquatting", "evasion", "stealth",
    "persistence", "payload", "socket", "reverse shell", "crypto", "miner"
]

# ==========================================
# 2. ΣΤΑΤΙΚΕΣ ΠΗΓΕΣ - ΤΩΡΑ modular, βλ. policy_sources/*.json
#    (OWASP_CICD / SLSA_REQUIREMENTS / THREAT_HUNTING_HEURISTICS
#    μετακομίσαν σε ξεχωριστά .json αρχεία - βλ. load_policy_source_files())
# ==========================================


def load_policy_source_files(directory=POLICY_SOURCES_DIR):
    """
    Σαρώνει το policy_sources/ και φορτώνει ΟΛΑ τα .json αρχεία. Κάθε αρχείο:
        {"source": "...", "rules": [{"id":..., "name":..., "description":...}, ...]}
    Για νέα κατηγορία κανόνων στο μέλλον: απλά πρόσθεσε ένα νέο .json εδώ -
    ΔΕΝ χρειάζεται καμία αλλαγή στον Python κώδικα.
    """
    all_rules = []
    if not os.path.exists(directory):
        print(f"[!] Δεν βρέθηκε ο φάκελος {directory} - δημιούργησέ τον και βάλε .json αρχεία μέσα.")
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
            print(f"  [+] {fname}: {len(rules)} κανόνες (source: {source})")
        except Exception as e:
            print(f"  [!] Σφάλμα φόρτωσης {fname}: {e}")

    print(f"[+] Σύνολο από policy_sources/: {len(all_rules)} κανόνες από {len(json_files)} αρχεία.")
    return all_rules


# ==========================================
# ΣΥΝΑΡΤΗΣΕΙΣ ΑΝΤΛΗΣΗΣ ΚΑΙ ΦΙΛΤΡΑΡΙΣΜΑΤΟΣ - ΑΝΕΓΓΙΧΤΟ
# ==========================================

def is_relevant(text):
    text_lower = text.lower()
    return any(kw in text_lower for kw in RELEVANT_KEYWORDS)


def fetch_mitre_attack():
    print("[*] Δυναμική λήψη MITRE ATT&CK Enterprise...")
    try:
        response = requests.get(MITRE_ATTACK_URL, timeout=30)
        response.raise_for_status()
        stix_data = response.json()
    except Exception as e:
        print(f"[!] Αποτυχία λήψης MITRE: {e}")
        return []

    mitre_rules = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        external_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), "UNKNOWN")
        name = obj.get("name", "")
        description = obj.get("description", "")

        if external_id != "UNKNOWN" and name and is_relevant(f"{name} {description}"):
            mitre_rules.append({
                "source": "MITRE ATT&CK", "id": external_id, "name": name, "description": description
            })

    print(f"[+] Αντλήθηκαν {len(mitre_rules)} τεχνικές από MITRE ATT&CK.")
    return mitre_rules


def fetch_mitre_csv(url, source_name, id_prefix):
    """Γενική συνάρτηση για λήψη και parse των CWE και CAPEC από το MITRE."""
    print(f"[*] Δυναμική λήψη {source_name} από {url}...")
    rules = []
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                content = f.read().decode('utf-8', errors='ignore')
                reader = csv.DictReader(content.splitlines())

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
        print(f"[!] Αποτυχία λήψης {source_name}: {e}")

    print(f"[+] Αντλήθηκαν {len(rules)} εγγραφές από {source_name}.")
    return rules


def build_dataset():
    all_policies = []

    # 1. Δυναμικά Δεδομένα (ανέγγιχτο)
    all_policies.extend(fetch_mitre_attack())
    all_policies.extend(fetch_mitre_csv(CWE_CSV_URL, "CWE Database", "CWE"))
    all_policies.extend(fetch_mitre_csv(CAPEC_CSV_URL, "CAPEC Attack Patterns", "CAPEC"))

    # 2. Στατικά Δεδομένα - modular, από policy_sources/
    print("[*] Ενσωμάτωση modular policy_sources/...")
    all_policies.extend(load_policy_source_files())

    # M5 FIX: Embedding text = μόνο semantic content (name + description).
    # Τα sentence transformer models δεν εκπαιδεύτηκαν να κατανοούν
    # structured IDs ("CWE-94", "CICD-SEC-3") — αυτά μειώνουν τη ποιότητα
    # retrieval. Τα metadata (source, id) υπάρχουν στο policy_metadata.json.
    for policy in all_policies:
        policy["text_for_embedding"] = f"{policy['name']}. {policy['description']}"

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(all_policies, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Το Ισχυρό Policy Dataset χτίστηκε! Συνολικοί κανόνες: {len(all_policies)} -> {OUTPUT_JSON}")


if __name__ == "__main__":
    build_dataset()

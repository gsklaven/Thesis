"""
Προσθέτει ΣΗΜΑΣΙΟΛΟΓΙΚΕΣ ετικέτες attack-type σε κάθε δείγμα του
malware_dataset_matched.json (ουσιαστικά μόνο σε πακέτα με γνωστό source_code_path),
ξεχωριστές από τις χαμηλού-επιπέδου CodeQL κατηγορίες
(process_exec/network/file_ops/crypto_obfuscation).

Τρεις πηγές:
  1. Keyword tagging πάνω στο summary/description.
  2. Typosquatting detection (edit distance στο όνομα του πακέτου).
  3. campaign_signature - πολλά OSV/Checkmarx reports περιγράφουν
     ολόκληρη καμπάνια με πανομοιότυπο κείμενο ανά μέλος της καμπάνιας,
     διαφέρει μόνο το per-report hash. Η λογική αυτή βρίσκεται στο
     utils.py ως campaign_signature() (κοινή υλοποίηση).
"""

import json
import os
import re
import sys

# Βεβαιωνόμαστε ότι ο φάκελος preparation είναι στο path
sys.path.insert(0, os.path.dirname(__file__))
from utils import campaign_signature  # noqa: E402

# Χρησιμοποιούμε malware_dataset_matched.json (μετά την extract_samples.py)
# ώστε να μην χρησιμοποιούμε χρόνο σε πακέτα χωρίς κώδικα (unmatched).
DATASET_JSON = "/home/sklavenitis/thesis/dataset/malware_dataset_matched.json"
OUTPUT_JSON = "/home/sklavenitis/thesis/dataset/attack_type_tags.json"

POPULAR_PACKAGES_FILE = "/home/sklavenitis/thesis/dataset/top_pypi_packages.json"

POPULAR_PACKAGES_FALLBACK = [
    "requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3",
    "setuptools", "pip", "wheel", "six", "pyyaml", "cryptography", "click",
    "pytest", "certifi", "idna", "charset-normalizer", "colorama", "jinja2",
    "markupsafe", "attrs", "packaging", "pyparsing", "typing-extensions",
    "protobuf", "grpcio", "pillow", "sqlalchemy", "cffi", "pycparser",
    "wrapt", "s3transfer", "botocore", "python-dateutil", "pytz", "rsa",
    "pyasn1", "google-api-core", "googleapis-common-protos", "docutils",
    "pygments", "babel", "tqdm", "psutil", "lxml", "beautifulsoup4",
    "selenium", "scrapy", "aiohttp", "async-timeout", "multidict", "yarl",
    "websockets", "twisted", "gunicorn", "uvicorn", "fastapi", "pydantic",
    "starlette", "httpx", "httpcore", "h11", "anyio", "sniffio", "tornado",
    "redis", "pymongo", "psycopg2", "mysqlclient", "paramiko", "fabric",
    "docker", "kubernetes", "ansible", "pyjwt", "oauthlib", "requests-oauthlib",
    "cachetools", "google-auth", "grpcio-tools", "matplotlib", "scipy",
    "scikit-learn", "torch", "tensorflow", "keras", "opencv-python",
    "pyopenssl", "cryptodome", "pycryptodome", "bcrypt", "passlib",
    "pytorch", "nvidia",
]

ATTACK_TYPE_RULES = {
    "typosquatting": [r"\btyposquat", r"\bsimilarly named\b", r"\bmisspell"],
    "dependency_confusion": [r"dependency confusion", r"\bnamespace confusion\b"],
    "backdoor": [r"\bbackdoor\b", r"reverse shell", r"remote access", r"\brat\b"],
    "credential_stealer": [
        r"\bcredential", r"\bpassword", r"steal.*token", r"aws.*key",
        r"ssh key", r"api key",
    ],
    "spyware_infostealer": [
        r"\bspyware\b", r"information.?steal", r"info.?steal", r"\bstealer\b",
    ],
    "clipboard_wallet_hijacker": [
        r"\bclipboard\b", r"crypto wallet", r"wallet address", r"\bclipper\b",
    ],
    "cryptominer": [r"crypto.?miner", r"\bmining\b", r"\bmonero\b", r"\bxmrig\b"],
    "ransomware": [r"ransomware", r"\bencrypt.*files\b.*ransom"],
    "keylogger": [r"keylog"],
    "supply_chain_downloader": [
        r"download.*execut", r"\bdropper\b", r"\bstager\b", r"second.?stage",
        r"fetch.*payload",
    ],
    "obfuscated_payload": [r"\bobfuscat", r"base64.*decode", r"\bencoded payload\b"],
    "data_exfiltration": [r"\bexfiltrat", r"send.*data.*to", r"\bsystem information\b.*send"],
}

# Τα HASH_PATTERN / SOURCE_LINE_PATTERN βρίσκονται πλέον στο utils.py
# (μέσα στην κοινή campaign_signature()). Δεν χρειάζονται εδώ.


def load_popular_packages():
    if os.path.exists(POPULAR_PACKAGES_FILE):
        try:
            with open(POPULAR_PACKAGES_FILE, "r", encoding="utf-8") as f:
                return set(p.lower() for p in json.load(f))
        except Exception:
            pass
    return set(p.lower() for p in POPULAR_PACKAGES_FALLBACK)


def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def detect_typosquat(pkg_name, popular_packages):
    name = pkg_name.lower().strip()
    if name in popular_packages:
        return None
    best_match, best_dist = None, 99
    for pop in popular_packages:
        if abs(len(pop) - len(name)) > 2:
            continue
        d = levenshtein(name, pop)
        if d < best_dist:
            best_dist, best_match = d, pop
    if best_match and best_dist <= 2 and len(name) > 3:
        return {"typosquat_of": best_match, "edit_distance": best_dist}
    return None


def detect_keyword_tags(text):
    text = (text or "").lower()
    tags = []
    for tag, patterns in ATTACK_TYPE_RULES.items():
        if any(re.search(p, text) for p in patterns):
            tags.append(tag)
    return tags


# campaign_signature εισάγεται από utils.py (κοινή υλοποίηση με prepare_dataset_diverse.py)


def main():
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    popular_packages = load_popular_packages()
    print(f"[*] Χρήση λίστας {len(popular_packages)} δημοφιλών πακέτων για typosquat detection.")

    results = {}
    tag_counts = {}
    campaign_counts = {}
    typosquat_count = 0

    for item in dataset:
        pkg_name = item.get("package_name", "")
        if not pkg_name:
            continue

        combined_text = f"{item.get('summary', '')} {item.get('description', '')}"
        keyword_tags = detect_keyword_tags(combined_text)
        typosquat = detect_typosquat(pkg_name, popular_packages)
        camp_sig = campaign_signature(item.get("description", ""))

        all_tags = list(keyword_tags)
        if typosquat:
            all_tags.append("typosquatting")
            typosquat_count += 1
        if not all_tags:
            all_tags = ["unclassified"]

        for t in set(all_tags):
            tag_counts[t] = tag_counts.get(t, 0) + 1

        if camp_sig:
            campaign_counts[camp_sig] = campaign_counts.get(camp_sig, 0) + 1

        results[pkg_name] = {
            "attack_type_tags": sorted(set(all_tags)),
            "typosquat_details": typosquat,
            "campaign_signature": camp_sig,
        }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"\n[+] {len(results)} πακέτα ταξινομήθηκαν.")
    print(f"[+] {typosquat_count} πιθανά typosquats εντοπίστηκαν (edit distance <= 2).")

    print("\n[+] Κατανομή attack-type tags:")
    for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
        print(f"    {tag:28s} {count}")

    print(f"\n[+] {len(campaign_counts)} distinct campaign signatures εντοπίστηκαν.")
    print("[+] Top 10 μεγαλύτερες καμπάνιες:")
    for sig, count in sorted(campaign_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {count:4d} πακέτα | {sig[:100]}")

    print(f"\n[+] Αποτελέσματα -> {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
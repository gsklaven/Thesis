"""
Attack-type tagging of the malware samples.

Adds SEMANTIC attack-type tags to every sample of malware_dataset_matched.json (in practice, the
packages whose source code was found), separate from the low-level CodeQL categories
(process_exec / network / file_ops / crypto_obfuscation). The tags are shown to the LLM as metadata
of the retrieved examples (Section B of the prompt).

Three mechanisms:
  1. Keyword tagging of the OSV summary/description (ATTACK_TYPE_RULES).
  2. Typosquatting detection: Levenshtein edit distance of the package name to popular packages.
  3. Campaign signature: many OSV/Checkmarx reports describe a whole campaign with the same text
     for every member, differing only in a per-report hash (utils.campaign_signature()).

Output: dataset/attack_type_tags.json  {package: {attack_type_tags, typosquat_details, campaign_signature}}
"""

import json
import os
import re
import sys

# make the preparation folder importable (utils.py)
sys.path.insert(0, os.path.dirname(__file__))
from utils import campaign_signature  # noqa: E402

# Input is malware_dataset_matched.json (after extract_samples.py), so no time is spent on
# packages without source code.
_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
_DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
DATASET_JSON = os.path.join(_DATASET_DIR, "malware_dataset_matched.json")
OUTPUT_JSON = os.path.join(_DATASET_DIR, "attack_type_tags.json")

# Optional list of popular package names; the fallback below is used when it does not exist.
POPULAR_PACKAGES_FILE = os.path.join(_DATASET_DIR, "top_pypi_packages.json")

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

# tag -> regular expressions searched in the lower-cased summary + description
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

# The hash / source-line patterns live in utils.py (inside the shared campaign_signature()).


def load_popular_packages():
    """Lower-cased set of popular package names (from POPULAR_PACKAGES_FILE, else the fallback list)."""
    if os.path.exists(POPULAR_PACKAGES_FILE):
        try:
            with open(POPULAR_PACKAGES_FILE, "r", encoding="utf-8") as f:
                return set(p.lower() for p in json.load(f))
        except Exception:
            pass
    return set(p.lower() for p in POPULAR_PACKAGES_FALLBACK)


def levenshtein(a, b):
    """Levenshtein edit distance of two strings (dynamic programming, one row at a time)."""
    if a == b:
        return 0
    # iterate over the longer string, keep a row as long as the shorter one
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            # deletion, insertion, substitution (free when the characters are equal)
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def detect_typosquat(pkg_name, popular_packages):
    """
    If the name is within edit distance 2 of a popular package (and is not itself popular),
    return {"typosquat_of": <popular name>, "edit_distance": d}, otherwise None.
    """
    name = pkg_name.lower().strip()
    if name in popular_packages:
        return None
    best_match, best_dist = None, 99
    for pop in popular_packages:
        # names whose lengths differ by more than 2 cannot be within distance 2
        if abs(len(pop) - len(name)) > 2:
            continue
        d = levenshtein(name, pop)
        if d < best_dist:
            best_dist, best_match = d, pop
    # very short names are too close to everything to be meaningful
    if best_match and best_dist <= 2 and len(name) > 3:
        return {"typosquat_of": best_match, "edit_distance": best_dist}
    return None


def detect_keyword_tags(text):
    """Attack-type tags whose keyword patterns (ATTACK_TYPE_RULES) occur in the text."""
    text = (text or "").lower()
    tags = []
    for tag, patterns in ATTACK_TYPE_RULES.items():
        if any(re.search(p, text) for p in patterns):
            tags.append(tag)
    return tags


# campaign_signature is imported from utils.py (shared with prepare_dataset_diverse.py).


def main():
    """Tag every sample, write attack_type_tags.json and print tag / campaign statistics."""
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    popular_packages = load_popular_packages()
    print(f"[*] Using a list of {len(popular_packages)} popular packages for typosquat detection.")

    results = {}
    tag_counts = {}
    campaign_counts = {}
    typosquat_count = 0

    for item in dataset:
        pkg_name = item.get("package_name", "")
        if not pkg_name:
            continue

        # the three mechanisms: keywords, typosquatting, campaign signature
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

    print(f"\n[+] {len(results)} packages tagged.")
    print(f"[+] {typosquat_count} possible typosquats found (edit distance <= 2).")

    print("\n[+] Attack-type tag distribution:")
    for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
        print(f"    {tag:28s} {count}")

    print(f"\n[+] {len(campaign_counts)} distinct campaign signatures found.")
    print("[+] Top 10 largest campaigns:")
    for sig, count in sorted(campaign_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {count:4d} packages | {sig[:100]}")

    print(f"\n[+] Results -> {OUTPUT_JSON}")


if __name__ == "__main__":
    main()

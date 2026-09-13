"""
Pre-CodeQL Code-based Deduplication (Phase 2.5).

FIX: το ast.dump() στο ΚΑΝΟΝΙΚΟ (επιτυχές parse) μονοπάτι ΔΕΝ αφαίρεσε ποτέ
τις τιμές strings/constants - κρατούσε τις ΑΚΡΙΒΕΙΣ τιμές, οπότε ένα malware
script που αναφέρει το ΔΙΚΟ ΤΟΥ όνομα πακέτου (π.χ. σε setup.py name=... ή σε
ένα exfiltration beacon) παρήγαγε ΔΙΑΦΟΡΕΤΙΚΟ hash για κάθε typosquat
παραλλαγή, ακόμα κι αν η υπόλοιπη λογική ήταν πανομοιότυπη. Αποτέλεσμα: μόνο
13/13009 duplicates εντοπίστηκαν, ενώ ξέρουμε (από check_stale_reuse.py) ότι
υπάρχουν χιλιάδες πραγματικά ταυτόσημα payloads.

Τώρα αντικαθιστούμε ΟΛΕΣ τις τιμές Constant (strings/numbers) με placeholders
ΠΡΙΝ το ast.dump(), ώστε το hash να αντανακλά μόνο τη ΔΟΜΗ του κώδικα, όχι
τα συγκεκριμένα strings/ονόματα.
"""

import ast
import hashlib
import json
import os
import re
import sys
import warnings

sys.path.insert(0, os.path.dirname(__file__))
from utils import campaign_signature  # noqa: E402

warnings.filterwarnings("ignore", category=SyntaxWarning)

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
TAGS_JSON = os.path.join(BASE_DIR, "attack_type_tags.json")
OUTPUT_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")

MAX_PER_CODE_HASH = 3


def _normalize_python(source_code):
    """Αφαιρεί strings/comments/whitespace -> ΚΑΘΑΡΑ δομικό skeleton.
    FIX: αντικαθιστά ΤΙΣ ΤΙΜΕΣ constants πριν το dump, ώστε δύο αρχεία με
    ίδια δομή αλλά διαφορετικά strings (π.χ. διαφορετικό όνομα πακέτου
    ενσωματωμένο) να παράγουν το ΙΔΙΟ hash."""
    try:
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    node.value = "<STR>"
                elif isinstance(node.value, bytes):
                    node.value = b"<BYTES>"
                elif isinstance(node.value, (int, float, complex)) and not isinstance(node.value, bool):
                    node.value = 0
        return ast.dump(tree, annotate_fields=False)
    except SyntaxError:
        text = re.sub(r'#.*', '', source_code)
        text = re.sub(r'""".*?"""', '""', text, flags=re.DOTALL)
        text = re.sub(r"'''.*?'''", "''", text, flags=re.DOTALL)
        text = re.sub(r'"[^"]*"', '""', text)
        text = re.sub(r"'[^']*'", "''", text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text


def _normalize_js(source_code):
    text = re.sub(r'//.*', '', source_code)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'"[^"]*"', '""', text)
    text = re.sub(r"'[^']*'", "''", text)
    text = re.sub(r'`[^`]*`', '``', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def code_hash_for_package(pkg_dir):
    if not pkg_dir or not os.path.exists(pkg_dir):
        return None

    file_hashes = []
    total_size = 0
    MAX_READ_SIZE = 10 * 1024 * 1024

    # setup.py εξαιρείται ρητά - σχεδόν σίγουρα διαφέρει ΔΟΜΙΚΑ ανά typosquat
    # "γενιά" (διαφορετικό πλήθος classifiers/install_requires κ.λπ.), ακόμα
    # κι όταν το ΠΡΑΓΜΑΤΙΚΟ malicious payload σε άλλο αρχείο είναι πανομοιότυπο.
    EXCLUDED_FILENAMES = {"setup.py", "conftest.py"}

    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in (
            'node_modules', '.git', '__pycache__', '.venv', 'venv',
            '.egg-info', 'dist', 'build', 'vendor'
        )]
        for fname in sorted(files):
            if fname in EXCLUDED_FILENAMES:
                continue
            if not fname.endswith(('.py', '.js', '.ts', '.mjs', '.cjs')):
                continue
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size > 1 * 1024 * 1024:
                    continue
                total_size += size
                if total_size > MAX_READ_SIZE:
                    break
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                normalized = _normalize_python(content) if fname.endswith('.py') else _normalize_js(content)
                file_hashes.append(hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16])
            except Exception:
                continue

    if not file_hashes:
        return None

    # ΣΥΝΟΛΟ (όχι ακολουθία) από per-file hashes - η ΣΕΙΡΑ/ΟΝΟΜΑΤΑ αρχείων
    # πλέον ΔΕΝ επηρεάζουν το τελικό hash, μόνο το ΠΟΛΥΣΥΝΟΛΟ δομικών
    # αποτυπωμάτων που υπάρχουν στο πακέτο.
    canonical = "|".join(sorted(set(file_hashes)))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:16]


def main():
    if not os.path.exists(MATCHED_JSON):
        print(f"[!] Δεν βρέθηκε: {MATCHED_JSON}")
        return

    with open(MATCHED_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    tags = {}
    if os.path.exists(TAGS_JSON):
        with open(TAGS_JSON, "r", encoding="utf-8") as f:
            tags = json.load(f)

    print(f"[*] {len(dataset)} πακέτα στο matched dataset.")

    has_campaign = []
    needs_code_dedup = []
    no_source = []

    for item in dataset:
        pkg = item.get("package_name", "")
        src = item.get("source_code_path")

        desc = item.get("description", "")
        camp_sig = campaign_signature(desc)

        if not camp_sig and pkg in tags:
            camp_sig = tags[pkg].get("campaign_signature")

        if camp_sig:
            has_campaign.append(item)
        elif src and os.path.exists(src):
            needs_code_dedup.append(item)
        else:
            no_source.append(item)

    print(f"  [*] Με campaign signature (ήδη deduped): {len(has_campaign)}")
    print(f"  [*] Χωρίς campaign, χρειάζεται code dedup: {len(needs_code_dedup)}")
    print(f"  [*] Χωρίς source code (θα αγνοηθούν): {len(no_source)}")

    code_hash_groups = {}
    hash_errors = 0

    print("[*] Υπολογισμός code hashes (fixed normalization)...")
    for i, item in enumerate(needs_code_dedup):
        if (i + 1) % 1000 == 0:
            print(f"  [{i+1}/{len(needs_code_dedup)}]...")

        ch = code_hash_for_package(item.get("source_code_path"))
        if ch:
            code_hash_groups.setdefault(ch, []).append(item)
        else:
            has_campaign.append(item)
            hash_errors += 1

    code_deduped = []
    total_removed = 0
    for ch, group in code_hash_groups.items():
        selected = group[:MAX_PER_CODE_HASH]
        code_deduped.extend(selected)
        total_removed += len(group) - len(selected)

    print(f"\n[*] Code hash families: {len(code_hash_groups)}")
    print(f"[*] Top 10 μεγαλύτερα code-hash clusters:")
    top_clusters = sorted(code_hash_groups.items(), key=lambda x: -len(x[1]))
    for ch, group in top_clusters[:10]:
        names = [g["package_name"] for g in group[:5]]
        print(f"    {len(group):5d} πακέτα | hash={ch} | π.χ. {', '.join(names)}")

    final = has_campaign + code_deduped
    print(f"\n[+] Πριν: {len(dataset)} → Μετά: {len(final)} πακέτα")
    print(f"    Αφαιρέθηκαν {total_removed} code-duplicate πακέτα")
    if hash_errors:
        print(f"    ({hash_errors} πακέτα χωρίς parseable κώδικα κρατήθηκαν ως μοναδικά)")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=4, ensure_ascii=False)

    print(f"[✓] Αποθηκεύτηκε: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()

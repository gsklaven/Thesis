"""
Διαβάζει ΟΛΑ τα διαθέσιμα OSV reports από διάφορες πηγές (PyPI, npm).
Ομαδοποιεί ανά campaign και επιλέγει αντιπροσωπευτικά δείγματα για να
δημιουργήσει ένα ποικιλόμορφο dataset (malware_dataset.json).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils import campaign_signature, find_target_dir  # noqa: E402

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
OUTPUT_FILE = os.path.join(BASE_DIR, "malware_dataset.json")
BACKUP_FILE = os.path.join(BASE_DIR, "malware_dataset_backup.json")

MAX_PER_CAMPAIGN = 15


def _resolve_osv_directories():
    """
    ΙΔΙΟ pattern με collect_all_samples.py/extract_samples.py: ψάχνει ΚΑΘΕ
    subpath ξεχωριστά σε ΟΛΟΥΣ τους candidate δίσκους (utils.CANDIDATE_SOURCES_DIRS),
    αντί για ένα hardcoded path που έσπαγε κάθε φορά που άλλαζε/αποσυνδεόταν
    ο συγκεκριμένος δίσκος. Ελέγχει και τα δύο πιθανά ονόματα του OSSF repo
    ("malicious-packages" ή "ossf-malicious-packages", ανάλογα πώς το
    ονόμασες όταν έκανες clone) - καθένα σωστά μέχρι το osv/malicious/{pypi,npm}.
    """
    dirs = []
    for repo_name in ("malicious-packages", "ossf-malicious-packages"):
        base = find_target_dir(repo_name)
        if not base:
            continue
        for eco in ("pypi", "npm"):
            candidate = os.path.join(base, "osv", "malicious", eco)
            if os.path.exists(candidate):
                dirs.append(candidate)
    return dirs


OSV_DIRECTORIES = _resolve_osv_directories()


def parse_osv_files(directory):
    samples = []
    if not os.path.exists(directory):
        return samples

    parse_errors = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith(".json"):
                continue
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                pkg_name = ""
                if "affected" in data and len(data["affected"]) > 0:
                    pkg_name = data["affected"][0].get("package", {}).get("name", "")

                if not pkg_name:
                    continue

                summary = data.get("summary", "")
                details = data.get("details", "")

                samples.append({
                    "package_name": pkg_name,
                    "summary": summary,
                    "description": details,
                    "osv_id": data.get("id", "")
                })
            except Exception as e:
                parse_errors += 1
                print(f"  [!] Σφάλμα ανάλυσης {path}: {e}")

    if parse_errors:
        print(f"  [!] {parse_errors} αρχεία JSON αγνοήθηκαν λόγω σφαλμάτων στο {directory}")
    return samples


def diverse_select(all_samples):
    campaigns = {}
    no_campaign = []

    for s in all_samples:
        sig = campaign_signature(s["description"])
        if sig:
            campaigns.setdefault(sig, []).append(s)
        else:
            no_campaign.append(s)

    selected = list(no_campaign)
    for sig, entries in campaigns.items():
        selected.extend(entries[:MAX_PER_CAMPAIGN])

    print(f"  [*] {len(campaigns)} distinct campaign signatures, {len(no_campaign)} μοναδικά πακέτα.")
    return selected


def main():
    if not OSV_DIRECTORIES:
        print("[!!!] ΚΑΝΕΝΑ OSV directory δεν βρέθηκε σε κανέναν candidate δίσκο.")
        print("      Έλεγξε ότι το malicious-packages/ossf-malicious-packages έχει clone-αριστεί κάπου.")
        return

    all_samples = []
    for osv_dir in OSV_DIRECTORIES:
        print(f"[*] Σάρωση αναφορών στο: {osv_dir}")
        all_samples.extend(parse_osv_files(osv_dir))

    if not all_samples:
        print("[!] Δεν βρέθηκαν OSV reports στους φακέλους.")
        return

    if os.path.exists(OUTPUT_FILE):
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = f"{OUTPUT_FILE}.{ts}.bak"
        os.rename(OUTPUT_FILE, backup)
        print(f"  [*] Backup: {backup}")

    selected = diverse_select(all_samples)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Δημιουργήθηκε το {OUTPUT_FILE} με {len(selected)} δείγματα.")


if __name__ == "__main__":
    main()

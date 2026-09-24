"""
Cross-reference: πακέτα με ΚΕΝΟ description (bulk-sourced, π.χ.
pypi_malregistry) εναντίον του OSV directory (11.678 ονόματα, πολύ
μεγαλύτερο από τα 2.475 αρχικά ταιριασμένα) - αν το ΙΔΙΟ όνομα υπάρχει
ΚΑΙ στα δύο, "δανειζόμαστε" την πραγματική OSV περιγραφή. Ο κώδικας ήδη
υπάρχει (ήδη αναλυμένος) - εμπλουτίζουμε ΜΟΝΟ το μεταδεδομένο.
"""

import json
import os
import re

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
DATASET_JSON = os.path.join(_THESIS_ROOT, "dataset", "malware_dataset_matched.json")
_SOURCES = os.environ.get("THESIS_SOURCES_DIR") or os.environ.get("THESIS_USB_MOUNT") or "/Volumes/GIORGOS_128"
OSV_DIR = os.environ.get("THESIS_OSV_DIR") or next(
    (d for d in (os.path.join(_SOURCES, "malicious-packages", "osv", "malicious", "pypi"),
                 os.path.expanduser("~/Downloads/malicious-packages/osv/malicious/pypi")) if os.path.isdir(d)),
    os.path.join(_SOURCES, "malicious-packages", "osv", "malicious", "pypi"))


def norm(name):
    """PEP 503 normalisation: Ailynitro == ailynitro, a_b == a-b."""
    return re.sub(r"[-_.]+", "-", name).lower()


def extract_description(pkg_folder):
    texts = []
    for root, dirs, files in os.walk(pkg_folder):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            summary = data.get("summary", "") or ""
            details = data.get("details", "") or ""
            if summary:
                texts.append(summary)
            if details:
                texts.append(details)
    return " ".join(texts).strip()


def main():
    print("[*] Φόρτωση dataset...")
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    zero_desc_items = [item for item in dataset if not item.get("description", "").strip()]
    print(f"    {len(zero_desc_items)} πακέτα με κενό description.")

    if not os.path.exists(OSV_DIR):
        print(f"[!] Δεν βρέθηκε OSV φάκελος: {OSV_DIR}")
        return

    osv_map = {norm(n): n for n in os.listdir(OSV_DIR)}
    osv_names = set(osv_map)
    print(f"    {len(osv_names)} πακέτα διαθέσιμα στο OSV directory.\n")

    enriched, still_empty, lengths = 0, 0, []

    for item in zero_desc_items:
        pkg = item["package_name"]
        if norm(pkg) not in osv_names:
            still_empty += 1
            continue
        description = extract_description(os.path.join(OSV_DIR, osv_map[norm(pkg)]))
        if description:
            item["description"] = description
            item["description_backfilled_from"] = "osv_cross_reference"
            enriched += 1
            lengths.append(len(description))
        else:
            still_empty += 1

    print(f"[+] {enriched} πακέτα εμπλουτίστηκαν με πραγματική OSV περιγραφή.")
    print(f"[+] {still_empty} παραμένουν χωρίς περιγραφή (ούτε το OSV τα έχει).")
    if lengths:
        import statistics
        print(f"[*] Μέσο μήκος νέας περιγραφής: {statistics.mean(lengths):.0f} χαρακτήρες "
              f"(διάμεσος: {statistics.median(lengths):.0f})")

    with open(DATASET_JSON, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Ενημερώθηκε: {DATASET_JSON}")
    print("    Επόμενο βήμα: python3 build_rag_index.py (ξαναχτίζει με τα εμπλουτισμένα δεδομένα)")


if __name__ == "__main__":
    main()

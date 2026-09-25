"""
Read ALL available OSV reports (OpenSSF Malicious Packages, PyPI and npm), group them by campaign
and keep a limited number of reports per campaign, producing the initial list of malicious packages
(dataset/malware_dataset.json) that the later collection steps build on. The previous file, if any,
is kept as a timestamped backup.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from utils import campaign_signature, find_target_dir  # noqa: E402

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
OUTPUT_FILE = os.path.join(BASE_DIR, "malware_dataset.json")
BACKUP_FILE = os.path.join(BASE_DIR, "malware_dataset_backup.json")

# reports kept per campaign at this early stage (the final, code-aware cap is in build_final_dataset.py)
MAX_PER_CAMPAIGN = 15


def _resolve_osv_directories():
    """
    The osv/malicious/{pypi,npm} folders of the OpenSSF repository, looked up in EVERY candidate
    sources location (utils.CANDIDATE_SOURCES_DIRS) instead of a hard-coded path. Both possible
    clone names are accepted ("malicious-packages" or "ossf-malicious-packages").
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
    """One entry {package_name, summary, description, osv_id} per OSV report (JSON) under directory."""
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

                # the package is the first "affected" entry of the report
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
                print(f"  [!] Parse error in {path}: {e}")

    if parse_errors:
        print(f"  [!] {parse_errors} JSON files ignored because of errors in {directory}")
    return samples


def diverse_select(all_samples):
    """All reports without a campaign, plus at most MAX_PER_CAMPAIGN reports of every campaign."""
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

    print(f"  [*] {len(campaigns)} distinct campaign signatures, {len(no_campaign)} unique packages.")
    return selected


def main():
    """Parse every OSV folder, back up the previous output, select and write malware_dataset.json."""
    if not OSV_DIRECTORIES:
        print("[!!!] NO OSV directory was found in any candidate sources location.")
        print("      Check that malicious-packages / ossf-malicious-packages has been cloned somewhere.")
        return

    all_samples = []
    for osv_dir in OSV_DIRECTORIES:
        print(f"[*] Scanning reports in: {osv_dir}")
        all_samples.extend(parse_osv_files(osv_dir))

    if not all_samples:
        print("[!] No OSV reports found in the folders.")
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

    print(f"\n[✓] Created {OUTPUT_FILE} with {len(selected)} samples.")


if __name__ == "__main__":
    main()

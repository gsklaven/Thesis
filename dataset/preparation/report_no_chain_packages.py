"""
Ενιαία αναφορά: ΟΛΑ τα πακέτα που ΔΕΝ έχουν δώσει χρήσιμο behavior chain
μέχρι στιγμής, κατηγοριοποιημένα με ΑΚΡΙΒΗ αιτία - ώστε να ξέρεις τι
ΑΚΡΙΒΩΣ πάει λάθος, χωρίς να χρειάζεται να τρέξεις πολλά ξεχωριστά scripts.
"""

import json
import os

BASE_DIR = "/home/sklavenitis/thesis/dataset"
ANALYZED_CHAINS_DIR = os.path.join(BASE_DIR, "analyzed_chains")

_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

ARCHIVE_EXTENSIONS = (".tar.gz", ".tgz", ".tar", ".zip", ".whl")


def has_archive_but_no_code(path):
    """True = μόνο archive, καμία εξαγωγή. False = πραγματικός κώδικας
    υπάρχει. None = κενός φάκελος ή δεν μπορούμε καν να τον διαβάσουμε."""
    if not path or not os.path.exists(path):
        return None
    has_archive = False
    has_any_file = False
    for root, dirs, files in os.walk(path):
        for fname in files:
            has_any_file = True
            lower = fname.lower()
            if lower.endswith(('.py', '.js', '.ts', '.mjs', '.cjs')):
                return False
            if lower.endswith(ARCHIVE_EXTENSIONS):
                has_archive = True
    if not has_any_file:
        return None
    return has_archive


def main():
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    path_by_pkg = {item["package_name"]: item.get("source_code_path") for item in dataset}

    categories = {
        "oversized": [],
        "failed_timeout_analysis": [],
        "failed_timeout_build": [],
        "failed_codeql_error": [],
        "failed_builder_error": [],
        "failed_no_result": [],
        "failed_unknown_reason": [],
        "zero_chains_archive_only": [],
        "zero_chains_empty_folder": [],
        "zero_chains_missing_path": [],
        "zero_chains_real_code": [],
        "not_yet_attempted": [],
    }

    existing_files = set(os.listdir(ANALYZED_CHAINS_DIR))
    print(f"[*] {len(path_by_pkg)} πακέτα συνολικά στο dataset, {len(existing_files)} αρχεία στο analyzed_chains/...")

    for i, pkg in enumerate(sorted(path_by_pkg.keys())):
        if (i + 1) % 3000 == 0:
            print(f"    [{i+1}/{len(path_by_pkg)}]...")

        real_file = f"{pkg}.json"
        oversized_marker = f"_oversized_{pkg}.marker"
        failed_marker = f"_failed_{pkg}.marker"

        if oversized_marker in existing_files:
            categories["oversized"].append(pkg)
            continue

        if failed_marker in existing_files:
            marker_path = os.path.join(ANALYZED_CHAINS_DIR, failed_marker)
            try:
                with open(marker_path, "r", encoding="utf-8") as f:
                    reason_line = f.read().strip()
            except Exception:
                reason_line = ""
            if "timeout_analysis_py" in reason_line:
                categories["failed_timeout_analysis"].append(pkg)
            elif "timeout_build_behavior_chain" in reason_line:
                categories["failed_timeout_build"].append(pkg)
            elif "codeql_error" in reason_line:
                categories["failed_codeql_error"].append(pkg)
            elif "builder_error" in reason_line:
                categories["failed_builder_error"].append(pkg)
            elif "no_result_produced" in reason_line:
                categories["failed_no_result"].append(pkg)
            else:
                categories["failed_unknown_reason"].append(pkg)
            continue

        if real_file not in existing_files:
            categories["not_yet_attempted"].append(pkg)
            continue

        fpath = os.path.join(ANALYZED_CHAINS_DIR, real_file)
        try:
            if os.path.getsize(fpath) > 2 * 1024 * 1024:
                continue  # μεγάλο αλλά χωρίς marker - σπάνιο edge case, αγνόησε
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        n_chains = data.get("summary", {}).get("total_behavior_chains", -1)
        if n_chains != 0:
            continue  # έχει πραγματικά chains - δεν μας ενδιαφέρει εδώ

        path = path_by_pkg.get(pkg)
        archive_status = has_archive_but_no_code(path)
        if archive_status is True:
            categories["zero_chains_archive_only"].append(pkg)
        elif archive_status is None:
            if path and os.path.exists(path):
                categories["zero_chains_empty_folder"].append(pkg)
            else:
                categories["zero_chains_missing_path"].append(pkg)
        else:
            categories["zero_chains_real_code"].append(pkg)

    print(f"\n{'Κατηγορία':35s} {'Πλήθος'}")
    print("-" * 50)
    for cat, pkgs in categories.items():
        print(f"{cat:35s} {len(pkgs)}")

    out_path = os.path.join(BASE_DIR, "no_chain_packages_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(categories, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Πλήρης λίστα ανά κατηγορία -> {out_path}")


if __name__ == "__main__":
    main()

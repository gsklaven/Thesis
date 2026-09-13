"""
Διαγνωστικό: ψάχνει στα ΗΔΗ αναλυμένα analyzed_chains/*.json για ύποπτα
σημάδια του "stale CSV reuse" bug - όταν δύο ΔΙΑΔΟΧΙΚΑ επεξεργασμένα πακέτα
έχουν πανομοιότυπο payload_signature.

ΔΙΟΡΘΩΣΗ: προστέθηκε το ΙΔΙΟ size guard με το build_final_dataset.py
(MAX_FILE_SIZE_MB) - ΧΩΡΙΣ αυτό, το json.load() σε ένα από τα γνωστά
τερατώδη αρχεία (50-290MB, π.χ. "chellow"/"automslc"/"telethon2") γεμίζει
απότομα τη μνήμη και μπορεί να παγώσει ολόκληρο το σύστημα. Τα τερατώδη
αρχεία έτσι κι αλλιώς αγνοούνται ήδη από το build_final_dataset.py - δεν
θα κατέληγαν ποτέ στο τελικό dataset, οπότε δεν έχει νόημα να τα ελέγχουμε
ούτε εδώ.
"""

import hashlib
import json
import os
import re

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
ANALYZED_DIR = os.path.join(BASE_DIR, "analyzed_chains")

_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

MAX_FILE_SIZE_MB = 2
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


def normalize_text(text):
    if not isinstance(text, str):
        return ""
    t = text
    t = re.sub(r"[0-9]+\.[0-9]+", "<VER>", t)
    t = re.sub(r"\b[0-9]{2,}\b", "<NUM>", t)
    t = re.sub(r"[A-Za-z0-9+/]{20,}={0,2}", "<BLOB>", t)
    t = re.sub(r"(/[\w.\-]+)+", "<PATH>", t)
    t = re.sub(r"['\"].*?['\"]", "<STR>", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def payload_signature(data):
    chains = data.get("behavior_chains", [])
    texts = []
    for c in chains:
        for node in c.get("data_flow_slice", []):
            texts.append(normalize_text(node.get("text", "")))
        for flow in c.get("confirmed_source_flows", []):
            texts.append(normalize_text(flow.get("source", {}).get("node", "")))
            texts.append(normalize_text(flow.get("sink_node", "")))
    canonical = "|".join(sorted(set(texts)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def main():
    with open(DATASET_JSON, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[*] {len(dataset)} πακέτα στη σειρά επεξεργασίας ({os.path.basename(DATASET_JSON)}).")

    sigs = []
    zero_chain_count = 0
    skipped_oversized = 0

    for item in dataset:
        pkg = item.get("package_name", "")
        path = os.path.join(ANALYZED_DIR, f"{pkg}.json")
        if not os.path.exists(path):
            continue

        size_bytes = os.path.getsize(path)
        if size_bytes > MAX_FILE_SIZE_BYTES:
            skipped_oversized += 1
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        n_chains = data.get("summary", {}).get("total_behavior_chains", 0)
        if n_chains == 0:
            zero_chain_count += 1

        sigs.append((pkg, payload_signature(data), n_chains))

    print(f"[*] {len(sigs)} πακέτα ελέγχθηκαν (κάτω από {MAX_FILE_SIZE_MB}MB).")
    print(f"[*] {skipped_oversized} πακέτα παραλείφθηκαν (> {MAX_FILE_SIZE_MB}MB - εξαιρούνται ούτως ή άλλως από το τελικό dataset).")
    print(f"[*] {zero_chain_count} πακέτα με 0 behavior chains (πιθανό 'δεν βρέθηκε κώδικας' - ΟΧΙ απαραίτητα bug).")

    suspects = []
    for i in range(len(sigs) - 1):
        pkg_a, sig_a, n_a = sigs[i]
        pkg_b, sig_b, n_b = sigs[i + 1]
        if sig_a == sig_b and n_a > 0 and pkg_a != pkg_b:
            suspects.append((pkg_a, pkg_b, sig_a, n_a))

    print(f"\n[{'!' if suspects else '✓'}] {len(suspects)} ύποπτα διαδοχικά ζευγάρια με ΤΑΥΤΟΣΗΜΟ payload_signature.")
    if suspects:
        print("    (πιθανή μόλυνση από stale CSV reuse - άξιζε χειροκίνητος έλεγχος)")
        for pkg_a, pkg_b, sig, n in suspects[:30]:
            print(f"    {pkg_a!r:40s} <-> {pkg_b!r:40s} | sig={sig} | {n} chains")
        if len(suspects) > 30:
            print(f"    ... και {len(suspects) - 30} ακόμα.")

        out_path = os.path.join(BASE_DIR, "suspected_stale_reuse_pairs.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(
                [{"package_a": a, "package_b": b, "payload_signature": s, "n_chains": n}
                 for a, b, s, n in suspects],
                f, indent=2, ensure_ascii=False,
            )
        print(f"\n    Πλήρης λίστα -> {out_path}")


if __name__ == "__main__":
    main()
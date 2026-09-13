"""
Τελική επιλογή ισορροπημένου dataset για το RAG.

ΕΠΑΝΑΦΟΡΑ: το "χωρίς campaign" bucket (bulk πηγές χωρίς OSV περιγραφή) περνούσε
ΑΝΕΞΕΛΕΓΚΤΑ ("κράτα όλα") - αλλά το check_stale_reuse.py μόλις έδειξε ότι
εκεί ζουν μαζικές typosquatting καμπάνιες με ΤΑΥΤΟΣΗΜΟ payload (π.χ. 17+
παραλλαγές του "BeautifulSoup"), αφού το code_dedup.py δεν είχε τρέξει
ακόμα όταν έγινε το batch analysis. Ξαναπροσθέτουμε το ίδιο technique/payload
-based capping που είχαμε στήσει νωρίτερα, με MAX_PER_TECHNIQUE_NO_CAMPAIGN.
"""

import glob
import hashlib
import json
import os
import re
import shutil

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
_DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
ANALYZED_DIR = os.path.join(_DATASET_DIR, "analyzed_chains")
ATTACK_TAGS_JSON = os.path.join(_DATASET_DIR, "attack_type_tags.json")
REPORT_OUT = os.path.join(_DATASET_DIR, "final_dataset_report.json")
FINAL_SUBSET_DIR = os.path.join(_DATASET_DIR, "final_diverse_subset")
FINAL_LIST_OUT = os.path.join(_DATASET_DIR, "final_diverse_subset_packages.json")
SKIPPED_OVERSIZED_OUT = os.path.join(_DATASET_DIR, "skipped_oversized_packages.json")

MAX_PER_CAMPAIGN = 5

# ΕΠΑΝΑΦΟΡΑ: πόσα δείγματα ΚΑΤ' ΑΝΩΤΑΤΟ ΟΡΙΟ ανά distinct payload_signature
# ΜΕΣΑ στα "χωρίς campaign" (bulk πηγές). Ίδια λογική/όριο με το
# MAX_PER_CODE_HASH του code_dedup.py, εφαρμοσμένη εδώ σαν safety net για
# ό,τι αναλύθηκε ΠΡΙΝ υπάρξει το code_dedup.py στο pipeline.
MAX_PER_TECHNIQUE_NO_CAMPAIGN = 3

MAX_FILE_SIZE_MB = 2
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


def load_analyzed_samples():
    samples = {}
    skipped_oversized = []
    skipped_total_bytes = 0

    for path in glob.glob(os.path.join(ANALYZED_DIR, "*.json")):
        fname = os.path.basename(path)
        if fname.startswith("_error_"):
            continue
        pkg_name = fname[:-5]

        size_bytes = os.path.getsize(path)
        if size_bytes > MAX_FILE_SIZE_BYTES:
            skipped_oversized.append({"package": pkg_name, "size_mb": round(size_bytes / 1e6, 1)})
            skipped_total_bytes += size_bytes
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                samples[pkg_name] = json.load(f)
        except UnicodeDecodeError as e:
            print(f"[!] Αγνοήθηκε {fname}: μη έγκυρο UTF-8 στη θέση {e.start}")
        except Exception as e:
            print(f"[!] Αγνοήθηκε {fname}: {e}")

    if skipped_oversized:
        print(f"\n[*] Παραλείφθηκαν {len(skipped_oversized)} πακέτα > {MAX_FILE_SIZE_MB}MB "
              f"(πιθανό vendor-bloat) - σύνολο {skipped_total_bytes / 1e9:.2f}GB.")
        skipped_oversized.sort(key=lambda x: -x["size_mb"])
        with open(SKIPPED_OVERSIZED_OUT, "w", encoding="utf-8") as f:
            json.dump(skipped_oversized, f, indent=4, ensure_ascii=False)
        print(f"    Πλήρης λίστα -> {SKIPPED_OVERSIZED_OUT}")

    return samples


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


def technique_signature(data):
    chains = data.get("behavior_chains", [])
    shape = []
    for c in sorted(chains, key=lambda x: x.get("category", "")):
        conditions = sorted(
            (cc.get("condition", ""), cc.get("must_be", ""))
            for cc in c.get("control_conditions", [])
        )
        shape.append({
            "language": c.get("language"),
            "category": c.get("category"),
            "flow_boundary": c.get("flow_boundary"),
            "num_confirmed_flows": len(c.get("confirmed_source_flows", [])),
            "num_data_flow_nodes": len(c.get("data_flow_slice", [])),
            "control_condition_shape": conditions,
        })
    canonical = json.dumps(shape, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


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
    analyzed = load_analyzed_samples()
    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    print(f"\n[*] {len(analyzed)} behavior-chain δείγματα (μετά το size filter), "
          f"{len(attack_tags)} attack-type tagged πακέτα.")

    untagged = [p for p in analyzed if p not in attack_tags]
    if untagged:
        print(f"\n[!] ΠΡΟΕΙΔΟΠΟΙΗΣΗ: {len(untagged)} analyzed πακέτα δεν έχουν attack-type tag!")
        print(f"    Παραδείγματα: {untagged[:5]}")

    campaigns = {}
    no_campaign = []
    missing_analysis = 0

    for pkg_name, tag_info in attack_tags.items():
        if pkg_name not in analyzed:
            missing_analysis += 1
            continue
        camp_sig = tag_info.get("campaign_signature")
        entry = {
            "pkg": pkg_name,
            "attack_type_tags": tag_info.get("attack_type_tags", []),
            "technique_signature": technique_signature(analyzed[pkg_name]),
            "payload_signature": payload_signature(analyzed[pkg_name]),
        }
        if camp_sig:
            campaigns.setdefault(camp_sig, []).append(entry)
        else:
            no_campaign.append(entry)

    print(f"[*] {missing_analysis} πακέτα με attack-type tag αλλά χωρίς analyzed_chain - αγνοήθηκαν.")
    print(f"[*] {len(campaigns)} campaigns, {len(no_campaign)} μοναδικά (χωρίς campaign) πακέτα.")

    selected = []
    campaign_report = []

    for camp_sig, entries in campaigns.items():
        seen_tech = set()
        ordered = []
        remaining = list(entries)
        while remaining:
            picked_this_round = []
            still_remaining = []
            for e in remaining:
                if e["technique_signature"] not in seen_tech:
                    picked_this_round.append(e)
                    seen_tech.add(e["technique_signature"])
                else:
                    still_remaining.append(e)
            ordered.extend(picked_this_round)
            remaining = still_remaining
            if not picked_this_round:
                ordered.extend(remaining)
                break

        chosen = ordered[:MAX_PER_CAMPAIGN]
        selected.extend(e["pkg"] for e in chosen)

        campaign_report.append({
            "campaign_signature_preview": camp_sig[:120],
            "total_in_campaign": len(entries),
            "distinct_technique_signatures": len(set(e["technique_signature"] for e in entries)),
            "kept": len(chosen),
            "kept_packages": [e["pkg"] for e in chosen],
        })

    # ΕΠΑΝΑΦΟΡΑ: "χωρίς campaign" ΤΩΡΑ ΕΠΙΣΗΣ dedup, με βάση το payload_signature.
    # Χωρίς αυτό, οι 17+ typosquat παραλλαγές του "BeautifulSoup" (ίδιο payload,
    # καμία OSV περιγραφή άρα κανένα campaign_signature) θα κρατούνταν ΟΛΕΣ.
    no_campaign_by_payload = {}
    for e in no_campaign:
        no_campaign_by_payload.setdefault(e["payload_signature"], []).append(e)

    no_campaign_kept = []
    for sig, entries in no_campaign_by_payload.items():
        no_campaign_kept.extend(entries[:MAX_PER_TECHNIQUE_NO_CAMPAIGN])

    print(f"[*] No-campaign πακέτα: {len(no_campaign)} -> {len(no_campaign_kept)} "
          f"μετά το payload-based dedup ({len(no_campaign_by_payload)} distinct payloads, "
          f"max {MAX_PER_TECHNIQUE_NO_CAMPAIGN}/καθένα).")

    selected.extend(e["pkg"] for e in no_campaign_kept)

    campaign_report.sort(key=lambda r: -r["total_in_campaign"])

    final_attack_type_counts = {}
    for pkg in selected:
        for t in attack_tags.get(pkg, {}).get("attack_type_tags", []):
            final_attack_type_counts[t] = final_attack_type_counts.get(t, 0) + 1

    report = {
        "total_analyzed_samples": len(analyzed),
        "total_selected": len(selected),
        "campaigns": campaign_report,
        "unique_no_campaign_before_dedup": len(no_campaign),
        "unique_no_campaign_after_dedup": len(no_campaign_kept),
        "final_attack_type_distribution": final_attack_type_counts,
    }

    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    with open(FINAL_LIST_OUT, "w", encoding="utf-8") as f:
        json.dump(sorted(set(selected)), f, indent=4, ensure_ascii=False)

    if os.path.exists(FINAL_SUBSET_DIR):
        shutil.rmtree(FINAL_SUBSET_DIR)
    os.makedirs(FINAL_SUBSET_DIR)
    for pkg in set(selected):
        src = os.path.join(ANALYZED_DIR, f"{pkg}.json")
        dst = os.path.join(FINAL_SUBSET_DIR, f"{pkg}.json")
        if os.path.exists(src):
            shutil.copy2(src, dst)

    print(f"\n[+] Πριν: {len(analyzed)} πακέτα -> Μετά: {len(set(selected))} πακέτα")
    print("\n[+] Top 10 μεγαλύτερες καμπάνιες (πριν/μετά):")
    for r in campaign_report[:10]:
        print(f"    {r['total_in_campaign']:4d} -> {r['kept']:2d} | distinct techniques={r['distinct_technique_signatures']} | {r['campaign_signature_preview']}")

    print("\n[+] Τελική κατανομή attack-type (μετά την επιλογή):")
    for tag, count in sorted(final_attack_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {tag:28s} {count}")

    print(f"\n[+] Πλήρης αναφορά -> {REPORT_OUT}")
    print(f"[+] Λίστα επιλεγμένων -> {FINAL_LIST_OUT}")
    print(f"[+] Αντίγραφα -> {FINAL_SUBSET_DIR}/")


if __name__ == "__main__":
    main()

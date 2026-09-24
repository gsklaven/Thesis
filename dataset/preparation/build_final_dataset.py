"""
Τελική επιλογή ισορροπημένου dataset για το RAG.

Ποικιλία με βάση τον κώδικα: ένα πακέτο ανά payload_signature (κανονικοποιημένος κώδικας των
Behavior Chains) σε όλο το σύνολο, έως MAX_PER_CAMPAIGN ανά πραγματική καμπάνια, και τα πακέτα
χωρίς chains με την αναλογία του πληθυσμού (βλ. σχόλιο στις σταθερές παρακάτω).
"""

import collections
import glob
import hashlib
import json
import os
import random
import re
import shutil

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
_DATASET_DIR = os.path.join(_THESIS_ROOT, "dataset")
ANALYZED_DIR = os.path.join(_DATASET_DIR, "analyzed_chains")
ATTACK_TAGS_JSON = os.path.join(_DATASET_DIR, "attack_type_tags.json")
REPORT_OUT = os.path.join(_DATASET_DIR, "final_dataset_report.json")
FINAL_SUBSET_DIR = os.path.join(_DATASET_DIR, "final_diverse_subset")
FINAL_LIST_OUT = os.path.join(_DATASET_DIR, "final_diverse_subset_packages.json")
SKIPPED_OVERSIZED_OUT = os.path.join(_DATASET_DIR, "skipped_oversized_packages.json")
EXCLUDED_NO_PAYLOAD_OUT = os.path.join(_DATASET_DIR, "excluded_no_payload_packages.json")

MAX_PER_CAMPAIGN = 5

# 2026-09-24 - επιλογή με βάση τον ΚΩΔΙΚΑ, όχι μόνο το κείμενο της αναφοράς:
# Το campaign_signature είναι hash του κειμένου της αναφοράς OSV. (α) Ο ίδιος κακόβουλος
# κώδικας σε 44-55 πακέτα είχε 44-55 διαφορετικά κείμενα -> 44-55 "καμπάνιες", που
# σκορπίζονταν σε train/test (26% του test είχε πανομοιότυπο payload στο train).
# (β) Η μεγαλύτερη "καμπάνια" (1.638 πακέτα, 864 διαφορετικά payloads) ήταν απλώς το κενό
# boilerplate του OSV ("Malicious code in X (PyPI)") και το όριο των 30 πετούσε ~1.000
# διαφορετικά δείγματα. Τώρα:
#   - το πολύ MAX_PER_PAYLOAD πακέτο ανά payload_signature σε ΟΛΟ το σύνολο,
#   - "καμπάνιες" με >= HETEROGENEOUS_MIN_PAYLOADS διαφορετικά payloads είναι γενικό
#     κείμενο και ΔΕΝ λειτουργούν ως καμπάνιες (ούτε για όριο ούτε για το split),
#   - πακέτα χωρίς chains (static misses) μπαίνουν με την ΠΡΑΓΜΑΤΙΚΗ τους αναλογία,
#     ώστε η end-to-end ανάκληση να μην είναι αισιόδοξη.
# Το split_train_test.py χωρίζει ανά οικογένεια (καμπάνια Ή ίδιος κώδικας) από το META_OUT.
HETEROGENEOUS_MIN_PAYLOADS = 30
MAX_PER_PAYLOAD = 1
SEED = 42
META_OUT = os.path.join(_DATASET_DIR, "final_diverse_subset_meta.json")

# Ήταν 2MB: έκοβε σιωπηλά ~1.700 πακέτα (12%) - σχεδόν όλα φουσκωμένα από το (πλέον
# διορθωμένο) call graph. Μετά το compact_chains.py το μέγεθος δεν είναι πια ένδειξη
# bloat· ένα μικρό όριο θα απέκλειε πραγματικά μεγάλα malware (ενώ τα benign δεν έχουν
# κανένα όριο -> ασυμμετρία που μπορεί να λειτουργήσει ως shortcut). Μένει μόνο ως
# δίχτυ ασφαλείας μνήμης.
MAX_FILE_SIZE_MB = 200
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


PAYLOAD_SCAN = os.path.join(_DATASET_DIR, "payload_scan.json")

# 2026-09-24: η πηγή MalwareBench (pypi/packages) περιέχει ΚΑΙ πακέτα που επισημάνθηκαν αλλά
# είναι ΝΟΜΙΜΑ (threat_type = false_positive στο pypi_package_info.csv της πηγής): 3.252 από
# τα 3.430 δείγματά της στο dataset (apprise, dbt, paramiko, requests...). Μετρούσαν ως malware
# (~45% του train και του test). Εξαιρούνται, μαζί με 2 ονόματα με ανάμεικτες εκδόσεις.
FALSE_POSITIVE_LIST = os.path.join(_DATASET_DIR, "excluded_malwarebench_false_positive.json")


def load_false_positive():
    if not os.path.exists(FALSE_POSITIVE_LIST):
        raise SystemExit(f"[!] Λείπει {FALSE_POSITIVE_LIST}: χωρίς αυτό τα νόμιμα πακέτα του "
                         f"MalwareBench θα μετρούσαν ως malware.")
    d = json.load(open(FALSE_POSITIVE_LIST, encoding="utf-8"))
    return set(d.get("false_positive", [])) | set(d.get("mixed_versions", []))


def load_no_payload():
    """
    Δείγματα χωρίς ΚΑΝΕΝΑ σήμα κακόβουλου κώδικα (payload_scan.py - κριτήριο ανεξάρτητο
    από το CodeQL): placeholders, typosquats που απλώς εξαρτώνται από το πραγματικό πακέτο,
    νόμιμες εκδόσεις καταχωρημένες ως malware. Δεν είναι έγκυρα δείγματα για ανίχνευση από
    κώδικα και εξαιρούνται ΚΑΙ από το train ΚΑΙ από το test.
    """
    if not os.path.exists(PAYLOAD_SCAN):
        print(f"[!] ΠΡΟΣΟΧΗ: δεν βρέθηκε {PAYLOAD_SCAN} - ΚΑΝΕΝΑ δείγμα δεν εξαιρείται ως no_payload.")
        return set()
    return set(json.load(open(PAYLOAD_SCAN, encoding="utf-8")).get("no_payload", []))


def load_analyzed_samples():
    samples = {}
    skipped_oversized = []
    skipped_total_bytes = 0
    no_payload = load_no_payload()
    excluded_no_payload = []
    false_positive = load_false_positive()
    excluded_fp = 0

    for path in glob.glob(os.path.join(ANALYZED_DIR, "*.json")):
        fname = os.path.basename(path)
        if fname.startswith("_"):  # _error_*, _MANIFEST, _rerun_failures_*, _compact_report
            continue
        pkg_name = fname[:-5]
        if pkg_name in false_positive:
            excluded_fp += 1
            continue
        if pkg_name in no_payload:
            excluded_no_payload.append(pkg_name)
            continue

        size_bytes = os.path.getsize(path)
        if size_bytes > MAX_FILE_SIZE_BYTES:
            skipped_oversized.append({"package": pkg_name, "size_mb": round(size_bytes / 1e6, 1)})
            skipped_total_bytes += size_bytes
            continue

        # Κρατάμε ΜΟΝΟ τις υπογραφές, όχι ολόκληρο το JSON: μετά το compaction τα ~13k
        # αρχεία είναι ~15GB, που φορτωμένα όλα μαζί ξεπερνούν πολύ τη RAM.
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            samples[pkg_name] = {
                "technique_signature": technique_signature(data),
                "payload_signature": payload_signature(data),
                "n_chains": len(data.get("behavior_chains", [])),
            }
            del data
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

    print(f"\n[*] Εξαιρέθηκαν {excluded_fp} νόμιμα πακέτα του MalwareBench (threat_type=false_positive).")
    print(f"[*] Εξαιρέθηκαν {len(excluded_no_payload)} δείγματα χωρίς payload (payload_scan.py).")
    with open(EXCLUDED_NO_PAYLOAD_OUT, "w", encoding="utf-8") as f:
        json.dump(sorted(excluded_no_payload), f, indent=1, ensure_ascii=False)
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

    missing_analysis = sum(1 for p in attack_tags if p not in analyzed)
    print(f"[*] {missing_analysis} πακέτα με attack-type tag αλλά χωρίς analyzed_chain - αγνοήθηκαν.")
    pkgs = sorted(p for p in attack_tags if p in analyzed)
    raw_camp = {p: attack_tags[p].get("campaign_signature") for p in pkgs}
    pay = lambda p: analyzed[p]["payload_signature"]
    has_chains = lambda p: analyzed[p]["n_chains"] > 0

    # "Καμπάνιες" που είναι γενικό κείμενο (πολλά διαφορετικά payloads) -> χωρίς καμπάνια.
    members = collections.defaultdict(list)
    for p in pkgs:
        if raw_camp[p]:
            members[raw_camp[p]].append(p)
    heterogeneous = {c for c, ps in members.items()
                     if len({pay(p) for p in ps if has_chains(p)}) >= HETEROGENEOUS_MIN_PAYLOADS}
    camp = {p: (raw_camp[p] if raw_camp[p] and raw_camp[p] not in heterogeneous else None) for p in pkgs}
    real = collections.defaultdict(list)
    for p in pkgs:
        if camp[p]:
            real[camp[p]].append(p)
    print(f"[*] {len(real)} πραγματικές καμπάνιες, {len(heterogeneous)} γενικά κείμενα αναφοράς "
          f"({sum(len(members[c]) for c in heterogeneous)} πακέτα) που αντιμετωπίζονται ως χωρίς καμπάνια.")

    selected = []
    per_camp = collections.Counter()
    used_payloads = collections.Counter()

    def take(p):
        if camp[p] and per_camp[camp[p]] >= MAX_PER_CAMPAIGN:
            return False
        if has_chains(p):
            if used_payloads[pay(p)] >= MAX_PER_PAYLOAD:
                return False
            used_payloads[pay(p)] += 1
        if camp[p]:
            per_camp[camp[p]] += 1
        selected.append(p)
        return True

    # 1. Πραγματικές καμπάνιες: round-robin σε διακριτά technique_signature (ποικιλία σχημάτων),
    #    με το όριο ανά καμπάνια και το όριο ανά payload.
    campaign_report = []
    for c in sorted(real):
        entries = [p for p in real[c] if has_chains(p)]
        seen_tech, ordered, remaining = set(), [], list(entries)
        while remaining:
            round_, rest = [], []
            for p in remaining:
                t = analyzed[p]["technique_signature"]
                (round_ if t not in seen_tech else rest).append(p)
                seen_tech.add(t)
            if not round_:
                ordered.extend(rest)
                break
            ordered.extend(round_)
            remaining = rest
        kept = [p for p in ordered if take(p)]
        campaign_report.append({
            "campaign_signature_preview": c[:120],
            "total_in_campaign": len(real[c]),
            "distinct_payload_signatures": len({pay(p) for p in entries}),
            "kept": len(kept),
            "kept_packages": kept,
        })

    # 2. Χωρίς καμπάνια (και γενικά κείμενα): ένα πακέτο ανά διαφορετικό κώδικα.
    no_campaign = [p for p in pkgs if not camp[p] and has_chains(p)]
    for p in no_campaign:
        take(p)
    n_with_chains = len(selected)

    # 3. Static misses (0 chains, αλλά με payload): ίδια αναλογία με τον πληθυσμό.
    available_with_chains = sum(1 for p in pkgs if has_chains(p))
    zero = [p for p in pkgs if not has_chains(p)]
    target_zero = round(len(zero) * n_with_chains / max(available_with_chains, 1))
    random.Random(SEED).shuffle(zero)
    n_zero = 0
    for p in zero:
        if n_zero >= target_zero:
            break
        if take(p):
            n_zero += 1
    print(f"[*] Επιλέχθηκαν {n_with_chains} πακέτα με chains ({len(used_payloads)} διαφορετικά payloads, "
          f"από {len({pay(p) for p in pkgs if has_chains(p)})} διαθέσιμα) + {n_zero} χωρίς chains "
          f"(αναλογία {100 * len(zero) / max(len(pkgs), 1):.1f}% στον πληθυσμό).")

    with open(META_OUT, "w", encoding="utf-8") as f:
        json.dump({p: {"campaign": camp[p], "payload_signature": pay(p), "n_chains": analyzed[p]["n_chains"]}
                   for p in selected}, f, indent=1, ensure_ascii=False)

    campaign_report.sort(key=lambda r: -r["total_in_campaign"])

    final_attack_type_counts = {}
    for pkg in selected:
        for t in attack_tags.get(pkg, {}).get("attack_type_tags", []):
            final_attack_type_counts[t] = final_attack_type_counts.get(t, 0) + 1

    report = {
        "total_analyzed_samples": len(analyzed),
        "total_selected": len(selected),
        "campaigns": campaign_report,
        "heterogeneous_report_texts": len(heterogeneous),
        "no_campaign_with_chains": len(no_campaign),
        "selected_with_chains": n_with_chains,
        "selected_zero_chains": n_zero,
        "distinct_payloads_selected": len(used_payloads),
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
        print(f"    {r['total_in_campaign']:4d} -> {r['kept']:2d} | distinct payloads={r['distinct_payload_signatures']} | {r['campaign_signature_preview']}")

    print("\n[+] Τελική κατανομή attack-type (μετά την επιλογή):")
    for tag, count in sorted(final_attack_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {tag:28s} {count}")

    print(f"\n[+] Πλήρης αναφορά -> {REPORT_OUT}")
    print(f"[+] Λίστα επιλεγμένων -> {FINAL_LIST_OUT}")
    print(f"[+] Αντίγραφα -> {FINAL_SUBSET_DIR}/")


if __name__ == "__main__":
    main()

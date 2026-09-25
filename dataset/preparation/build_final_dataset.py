"""
Final, code-aware selection of the malware samples used by the RAG (index + evaluation).

Selection rules (see the comment at the constants below):
  - at most MAX_PER_PAYLOAD package per payload_signature (normalised code of the package's
    Behavior Chains) in the WHOLE set, so no piece of malicious code appears twice;
  - at most MAX_PER_CAMPAIGN packages per real campaign (same OSV report text);
  - report texts that cover >= HETEROGENEOUS_MIN_PAYLOADS different payloads are generic boilerplate
    and are not treated as campaigns;
  - packages without Behavior Chains (static misses) are kept at their population rate.
Excluded beforehand: MalwareBench samples labelled false_positive (legitimate packages) and samples
without any payload code (payload_scan.py).

Inputs : dataset/analyzed_chains/*.json, attack_type_tags.json, payload_scan.json,
         excluded_malwarebench_false_positive.json
Outputs: final_diverse_subset/ (copies), final_diverse_subset_packages.json, final_diverse_subset_meta.json
         (read by split_train_test.py), final_dataset_report.json, excluded_no_payload_packages.json
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

# Selection is based on the CODE, not only on the report text:
# the campaign signature is a hash of the OSV report text. (a) The same malicious code in dozens of
# packages often had a different report text per package, i.e. dozens of "campaigns" that spread
# across train and test (a test sample could have an identical payload in the index). (b) The
# largest "campaign" was just the empty OSV boilerplate ("Malicious code in X (PyPI)"), covering
# hundreds of unrelated payloads, and a per-campaign cap would drop most of them. Therefore:
#   - at most MAX_PER_PAYLOAD package per payload_signature in the WHOLE set,
#   - "campaigns" with >= HETEROGENEOUS_MIN_PAYLOADS different payloads are generic text and do NOT
#     act as campaigns (neither for the cap nor for the split),
#   - packages without chains (static misses) are included at their REAL rate, so that end-to-end
#     recall is not optimistic.
# split_train_test.py splits by family (campaign OR identical code) using META_OUT.
HETEROGENEOUS_MIN_PAYLOADS = 30
MAX_PER_PAYLOAD = 1
SEED = 42
META_OUT = os.path.join(_DATASET_DIR, "final_diverse_subset_meta.json")

# Only a memory safety net. After chain compaction, file size no longer indicates bloat; a small
# limit would exclude genuinely large malware (while benign packages have no limit -> an asymmetry
# that could act as a shortcut).
MAX_FILE_SIZE_MB = 200
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


PAYLOAD_SCAN = os.path.join(_DATASET_DIR, "payload_scan.json")

# The MalwareBench source (pypi/packages) also contains packages that were reported but are
# LEGITIMATE (threat_type = false_positive in the source's pypi_package_info.csv), e.g. apprise, dbt,
# paramiko, requests. They are excluded, together with 2 names that have versions of both labels
# (list written by malwarebench_false_positives.py).
FALSE_POSITIVE_LIST = os.path.join(_DATASET_DIR, "excluded_malwarebench_false_positive.json")


def load_false_positive():
    """Names of the MalwareBench packages to exclude (false_positive + mixed_versions); the list is required."""
    if not os.path.exists(FALSE_POSITIVE_LIST):
        raise SystemExit(f"[!] {FALSE_POSITIVE_LIST} is missing: without it the legitimate packages of "
                         f"MalwareBench would count as malware.")
    d = json.load(open(FALSE_POSITIVE_LIST, encoding="utf-8"))
    return set(d.get("false_positive", [])) | set(d.get("mixed_versions", []))


def load_no_payload():
    """
    Samples without ANY signal of malicious code (payload_scan.py - a criterion independent of
    CodeQL): placeholders, typosquats that merely depend on the real package, legitimate versions
    registered as malware. They are not valid samples for code-based detection and are excluded from
    BOTH train and test.
    """
    if not os.path.exists(PAYLOAD_SCAN):
        print(f"[!] WARNING: {PAYLOAD_SCAN} not found - NO sample is excluded as no_payload.")
        return set()
    return set(json.load(open(PAYLOAD_SCAN, encoding="utf-8")).get("no_payload", []))


def load_analyzed_samples():
    """
    Signatures of every analysed sample that passes the exclusions:
    {package: {technique_signature, payload_signature, n_chains}}. Also writes the lists of
    oversized and no-payload packages.
    """
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

        # Keep ONLY the signatures, not the whole JSON: all chains files together are many GB,
        # far more than the available RAM.
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
            print(f"[!] Skipped {fname}: invalid UTF-8 at position {e.start}")
        except Exception as e:
            print(f"[!] Skipped {fname}: {e}")

    if skipped_oversized:
        print(f"\n[*] Skipped {len(skipped_oversized)} packages > {MAX_FILE_SIZE_MB}MB "
              f"(likely vendor bloat) - {skipped_total_bytes / 1e9:.2f}GB in total.")
        skipped_oversized.sort(key=lambda x: -x["size_mb"])
        with open(SKIPPED_OVERSIZED_OUT, "w", encoding="utf-8") as f:
            json.dump(skipped_oversized, f, indent=4, ensure_ascii=False)
        print(f"    Full list -> {SKIPPED_OVERSIZED_OUT}")

    print(f"\n[*] Excluded {excluded_fp} legitimate MalwareBench packages (threat_type=false_positive).")
    print(f"[*] Excluded {len(excluded_no_payload)} samples without payload (payload_scan.py).")
    with open(EXCLUDED_NO_PAYLOAD_OUT, "w", encoding="utf-8") as f:
        json.dump(sorted(excluded_no_payload), f, indent=1, ensure_ascii=False)
    return samples


def normalize_text(text):
    """
    Normalise a code snippet for the payload signature: versions, numbers, long base64/hex blobs,
    paths and string literals are replaced by placeholders, whitespace is collapsed. Two copies of
    the same code with different URLs/keys/paths get the same text.
    """
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
    """
    Hash of the SHAPE of a package's chains (language, category, flow boundary, number of flows and
    nodes, gating conditions) - used to prefer structurally different packages within a campaign.
    """
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
    """
    Hash of the normalised CODE of a package: the set of normalised texts of all data-flow slice
    nodes and of the source/sink of all confirmed flows. Packages with the same malicious code get
    the same signature regardless of name, version or report text.
    """
    chains = data.get("behavior_chains", [])
    texts = []
    for c in chains:
        for node in c.get("data_flow_slice", []):
            texts.append(normalize_text(node.get("text", "")))
        for flow in c.get("confirmed_source_flows", []):
            texts.append(normalize_text(flow.get("source", {}).get("node", "")))
            texts.append(normalize_text(flow.get("sink_node", "")))
    # a sorted set: independent of chain order and of repeated nodes
    canonical = "|".join(sorted(set(texts)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def main():
    """Apply the selection rules and write the final subset, its metadata and the report."""
    analyzed = load_analyzed_samples()
    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    print(f"\n[*] {len(analyzed)} behavior-chain samples (after the size filter), "
          f"{len(attack_tags)} packages with attack-type tags.")

    untagged = [p for p in analyzed if p not in attack_tags]
    if untagged:
        print(f"\n[!] WARNING: {len(untagged)} analysed packages have no attack-type tag!")
        print(f"    Examples: {untagged[:5]}")

    missing_analysis = sum(1 for p in attack_tags if p not in analyzed)
    print(f"[*] {missing_analysis} packages with an attack-type tag but no analysed chains - ignored.")
    pkgs = sorted(p for p in attack_tags if p in analyzed)
    raw_camp = {p: attack_tags[p].get("campaign_signature") for p in pkgs}
    pay = lambda p: analyzed[p]["payload_signature"]
    has_chains = lambda p: analyzed[p]["n_chains"] > 0

    # "Campaigns" that are generic text (many different payloads) -> no campaign.
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
    print(f"[*] {len(real)} real campaigns, {len(heterogeneous)} generic report texts "
          f"({sum(len(members[c]) for c in heterogeneous)} packages) treated as no campaign.")

    selected = []
    per_camp = collections.Counter()
    used_payloads = collections.Counter()

    def take(p):
        """Select p unless its campaign or its payload has reached the cap; returns True if selected."""
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

    # 1. Real campaigns: round-robin over distinct technique signatures (variety of shapes),
    #    subject to the per-campaign and per-payload caps.
    campaign_report = []
    for c in sorted(real):
        entries = [p for p in real[c] if has_chains(p)]
        seen_tech, ordered, remaining = set(), [], list(entries)
        while remaining:
            # each round takes one package per not-yet-seen technique signature
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

    # 2. No campaign (including generic texts): one package per distinct code.
    no_campaign = [p for p in pkgs if not camp[p] and has_chains(p)]
    for p in no_campaign:
        take(p)
    n_with_chains = len(selected)

    # 3. Static misses (0 chains, but with payload): same rate as in the population.
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
    print(f"[*] Selected {n_with_chains} packages with chains ({len(used_payloads)} distinct payloads, "
          f"out of {len({pay(p) for p in pkgs if has_chains(p)})} available) + {n_zero} without chains "
          f"(rate {100 * len(zero) / max(len(pkgs), 1):.1f}% in the population).")

    # per-package metadata for split_train_test.py (effective campaign, payload, number of chains)
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

    # fresh copy of the selected chains files
    if os.path.exists(FINAL_SUBSET_DIR):
        shutil.rmtree(FINAL_SUBSET_DIR)
    os.makedirs(FINAL_SUBSET_DIR)
    for pkg in set(selected):
        src = os.path.join(ANALYZED_DIR, f"{pkg}.json")
        dst = os.path.join(FINAL_SUBSET_DIR, f"{pkg}.json")
        if os.path.exists(src):
            shutil.copy2(src, dst)

    print(f"\n[+] Before: {len(analyzed)} packages -> After: {len(set(selected))} packages")
    print("\n[+] Top 10 largest campaigns (before/after):")
    for r in campaign_report[:10]:
        print(f"    {r['total_in_campaign']:4d} -> {r['kept']:2d} | distinct payloads={r['distinct_payload_signatures']} | {r['campaign_signature_preview']}")

    print("\n[+] Final attack-type distribution (after selection):")
    for tag, count in sorted(final_attack_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {tag:28s} {count}")

    print(f"\n[+] Full report -> {REPORT_OUT}")
    print(f"[+] List of selected packages -> {FINAL_LIST_OUT}")
    print(f"[+] Copies -> {FINAL_SUBSET_DIR}/")


if __name__ == "__main__":
    main()

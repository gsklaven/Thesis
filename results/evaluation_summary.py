"""
Aggregate statistics of the LLM reports (results/<tag>/report_*.json) of one or more runs.

For every run it prints and saves (results/evaluation_summaries/evaluation_summary_<tag>.json):
  1. the distribution of the final package verdicts (and of prompt versions, if mixed);
  2. which model answered, per chain - methodological transparency;
  3. the confusion matrix and accuracy / precision / recall / F1 / FPR, both end-to-end and for the
     LLM stage only (positive = MALICIOUS or SUSPICIOUS);
  4. the retrieval similarity score per chain verdict - does similarity alone separate benign from
     malicious, or is it just a "something close was found" signal?

Usage:  python3 results/evaluation_summary.py [tag ...]      e.g. v12_samples
        - with arguments: only these runs
        - without arguments, with RAG_MODE in the environment: the run of that RAG_MODE
        - with neither: every results/<PROMPT_VERSION>_* run (except smoke tests), including running ones

Reads: results/<tag>/report_*.json
       expected_labels.json (optional, for the metrics)
"""

import glob
import json
import os

import sys
_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION, RESULTS_TAG  # noqa: E402

RESULTS_ROOT = os.path.join(_THESIS_ROOT, "results")
EXPECTED_LABELS_FILE = os.path.join(_THESIS_ROOT, "expected_labels.json")
# Layout of results/: <tag>/report_*.json, evaluation_summaries/, test_set_summaries/
SUMMARY_DIR = os.path.join(RESULTS_ROOT, "evaluation_summaries")


def select_tags():
    """Runs to summarise: command-line tags, else the RAG_MODE run, else every <PROMPT_VERSION>_* run."""
    if len(sys.argv) > 1:
        return [os.path.basename(os.path.normpath(t)) for t in sys.argv[1:]]
    if os.environ.get("RAG_MODE"):
        return [RESULTS_TAG]
    return sorted(os.path.basename(d) for d in glob.glob(os.path.join(RESULTS_ROOT, f"{PROMPT_VERSION}_*"))
                  if os.path.isdir(d) and "smoke" not in os.path.basename(d))


def load_reports(results_dir):
    """{package: report} of every readable report_*.json in results_dir."""
    reports = {}
    for path in glob.glob(os.path.join(results_dir, "report_*.json")):
        pkg_name = os.path.basename(path)[len("report_"):-len(".json")]
        try:
            with open(path, "r", encoding="utf-8") as f:
                reports[pkg_name] = json.load(f)
        except Exception as e:
            print(f"  [!] Ignored {path}: {e}")
    return reports


def safe_div(a, b):
    """a / b, or 0.0 when b is 0."""
    return a / b if b else 0.0


def compute_confusion(reports, expected_labels, positive_verdicts):
    """
    Confusion counts of the labelled packages: (tp, tn, fp, fn, static_misses, unscored, benign_no_chains).

    NO_CHAINS_FOUND (CodeQL found NO sensitive behaviour) is not the same as "the LLM evaluated it and
    said BENIGN" - it is a limit of the static-analysis stage, not of the LLM reasoning. For benign
    labels it is counted separately (a correct TN end-to-end), for malicious labels it goes to a SEPARATE
    bucket (static_misses) - the same logic as check_test_set.py. Packages without a complete evaluation
    (EVALUATION_FAILED / INCOMPLETE / UNKNOWN) are not scored.
    """
    tp = tn = fp = fn = 0
    static_misses = 0
    unscored = 0
    benign_no_chains = 0  # benign packages the LLM never saw: TN end-to-end only
    for pkg, r in reports.items():
        expected = expected_labels.get(pkg)
        if expected not in ("benign", "malicious"):
            continue  # no label - not part of the confusion matrix at all
        verdict = r.get("final_verdict")
        if verdict in ("EVALUATION_FAILED", "INCOMPLETE", "UNKNOWN", None):
            unscored += 1  # NOT counted as an error - the outcome is simply unknown
            continue
        if verdict == "NO_CHAINS_FOUND":
            if expected == "benign":
                benign_no_chains += 1  # correct end-to-end, but NOT a decision of the LLM
            else:
                static_misses += 1  # SEPARATE from an LLM reasoning miss
            continue
        flagged = verdict in positive_verdicts
        if expected == "malicious":
            tp += flagged
            fn += (not flagged)
        else:
            fp += flagged
            tn += (not flagged)
    return tp, tn, fp, fn, static_misses, unscored, benign_no_chains


def print_metrics(label, tp, tn, fp, fn, static_misses, unscored, benign_no_chains=0):
    """Print the end-to-end and LLM-stage metrics of one confusion matrix and return them as a dict."""
    # END-TO-END: what the SYSTEM did - malware without chains = missed (FN), benign without chains =
    # no alarm (TN).
    fn_end_to_end = fn + static_misses
    tn_end_to_end = tn + benign_no_chains
    total_e2e = tp + tn_end_to_end + fp + fn_end_to_end
    accuracy_e2e = safe_div(tp + tn_end_to_end, total_e2e)
    recall_e2e = safe_div(tp, tp + fn_end_to_end)
    fpr_e2e = safe_div(fp, fp + tn_end_to_end)

    # LLM STAGE ONLY: ONLY packages evaluated by the LLM - NO_CHAINS_FOUND packages of both classes are
    # excluded SYMMETRICALLY.
    total_llm = tp + tn + fp + fn
    accuracy_llm = safe_div(tp + tn, total_llm)
    fpr_llm = safe_div(fp, fp + tn)
    precision = safe_div(tp, tp + fp)
    recall_llm = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall_llm, precision + recall_llm)

    print(f"\n--- {label} ---")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}  static-analysis-misses={static_misses}  "
          f"benign-no-chains={benign_no_chains}  (unclear/ignored: {unscored})")
    print(f"  Accuracy  END-TO-END (NO_CHAINS: malware=FN, benign=TN): {accuracy_e2e:.3f}")
    print(f"  Recall    END-TO-END: {recall_e2e:.3f}")
    print(f"  FPR       END-TO-END: {fpr_e2e:.3f}")
    print(f"  Accuracy  LLM-STAGE ONLY (no NO_CHAINS in either class): {accuracy_llm:.3f}")
    print(f"  FPR       LLM-STAGE ONLY: {fpr_llm:.3f}")
    trivial_note = "  [!] FP=0 -> trivial, 'benign' labels are needed in expected_labels.json" \
        if fp == 0 and tp > 0 else ""
    print(f"  Precision LLM-STAGE ONLY: {precision:.3f}{trivial_note}")
    print(f"  Recall    LLM-STAGE ONLY: {recall_llm:.3f}")
    print(f"  F1        LLM-STAGE ONLY: {f1:.3f}")

    # the same numbers that were printed, so that the caller can save them in the summary JSON
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "static_analysis_misses": static_misses, "unscored": unscored,
        "benign_no_chains": benign_no_chains,
        "accuracy_end_to_end": round(accuracy_e2e, 4),
        "recall_end_to_end": round(recall_e2e, 4),
        "fpr_end_to_end": round(fpr_e2e, 4),
        "accuracy_llm_stage_only": round(accuracy_llm, 4),
        "fpr_llm_stage_only": round(fpr_llm, 4),
        "precision_llm_stage_only": round(precision, 4),
        "recall_llm_stage_only": round(recall_llm, 4),
        "f1_llm_stage_only": round(f1, 4),
        "precision_trivial": (fp == 0 and tp > 0),
    }


def main():
    """Summarise every selected run."""
    expected_labels = {}
    if os.path.exists(EXPECTED_LABELS_FILE):
        with open(EXPECTED_LABELS_FILE, "r", encoding="utf-8") as f:
            expected_labels = json.load(f)
    tags = select_tags()
    if not tags:
        sys.exit(f"[!] No results found ({RESULTS_ROOT}/{PROMPT_VERSION}_*)")
    for tag in tags:
        summarize(tag, expected_labels)


def summarize(tag, expected_labels):
    """Print the statistics of one run and write its evaluation_summary_<tag>.json."""
    results_dir = os.path.join(RESULTS_ROOT, tag)
    summary_out = os.path.join(SUMMARY_DIR, f"evaluation_summary_{tag}.json")
    reports = load_reports(results_dir)
    print(f"\n{'=' * 70}\n{tag}\n{'=' * 70}")
    print(f"[*] {len(reports)} reports found in {results_dir}")
    if not reports:
        return

    # --- 1. Distribution of final verdicts (per package) and of answering models (per chain) ---
    verdict_counts = {}
    model_counts = {}
    total_chains = 0
    for r in reports.values():
        v = r.get("final_verdict", "?")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
        for c in r.get("chain_details", []):
            total_chains += 1
            m = c.get("llm_evaluation", {}).get("model_used", "unknown/error")
            model_counts[m] = model_counts.get(m, 0) + 1

    print(f"\n=== Distribution of final verdicts (per package, {len(reports)} in total) ===")
    for v, n in sorted(verdict_counts.items(), key=lambda x: -x[1]):
        print(f"  {v:20s} {n}")

    # breakdown per prompt_version, shown only when a folder mixes several versions; reports written
    # before version tracking existed show "unversioned"
    version_counts = {}
    for r in reports.values():
        pv = r.get("prompt_version", "unversioned")
        version_counts[pv] = version_counts.get(pv, 0) + 1
    if len(version_counts) > 1:
        print(f"\n=== Distribution of prompt_version (per package) ===")
        for pv, n in sorted(version_counts.items(), key=lambda x: -x[1]):
            print(f"  {pv:20s} {n}")

    print(f"\n=== Which model answered (per chain, {total_chains} in total) ===")
    for m, n in sorted(model_counts.items(), key=lambda x: -x[1]):
        pct = n / total_chains * 100 if total_chains else 0
        print(f"  {m:25s} {n:5d}  ({pct:.1f}%)")

    # --- 2. Confusion matrix / metrics ---
    n_benign_labels = sum(1 for v in expected_labels.values() if v == "benign")
    n_malicious_labels = sum(1 for v in expected_labels.values() if v == "malicious")
    print(f"\n[*] expected_labels.json: {n_malicious_labels} malicious, {n_benign_labels} benign")

    print_metrics_lenient = print_metrics("LENIENT (positive = MALICIOUS or SUSPICIOUS)",
                                          *compute_confusion(reports, expected_labels, {"MALICIOUS", "SUSPICIOUS"}))

    if n_benign_labels == 0:
        print("\n[!] NO 'benign' label in expected_labels.json yet - the Precision/F1 above is "
              "TRIVIAL (FP always 0, so Precision=1.0 automatically).")
        print("    Results on benign packages are needed for a meaningful Precision/F1.")
        print("    Until then, the Accuracy above equals the Recall (True Positive Rate).")

    # --- 3. Retrieval similarity score per chain verdict ---
    by_verdict = {"BENIGN": [], "SUSPICIOUS": [], "MALICIOUS": []}
    for r in reports.values():
        for c in r.get("chain_details", []):
            ev = c.get("llm_evaluation", {})
            verdict = ev.get("verdict")
            sim = c.get("top_malware_similarity")
            if verdict in by_verdict and isinstance(sim, (int, float)):
                by_verdict[verdict].append(sim)

    print(f"\n=== Similarity score (RAG retrieval) per chain verdict ===")
    print(f"{'Verdict':15s} {'N':6s} {'Mean':12s} {'Min':8s} {'Max':8s}")
    print("-" * 55)
    for verdict, sims in by_verdict.items():
        if not sims:
            print(f"{verdict:15s} {0:<6d} {'-':12s} {'-':8s} {'-':8s}")
            continue
        avg = sum(sims) / len(sims)
        print(f"{verdict:15s} {len(sims):<6d} {avg:<12.4f} {min(sims):<8.4f} {max(sims):<8.4f}")

    benign_avg = (sum(by_verdict["BENIGN"]) / len(by_verdict["BENIGN"])) if by_verdict["BENIGN"] else None
    malicious_all = by_verdict["MALICIOUS"] + by_verdict["SUSPICIOUS"]
    malicious_avg = (sum(malicious_all) / len(malicious_all)) if malicious_all else None

    if benign_avg is not None and malicious_avg is not None:
        diff = malicious_avg - benign_avg
        print(f"\nDifference of means (MALICIOUS/SUSPICIOUS − BENIGN): {diff:+.4f}")
        if abs(diff) < 0.05:
            print("[!] Very small difference - the similarity score does NOT seem to separate")
            print("    benign from malicious on its own. The real separation comes")
            print("    mostly from the LLM reasoning, not from the retrieval score.")
        else:
            print("[✓] Noticeable difference - similarity DOES have some discriminative value.")

    # --- 4. Save for reporting ---
    summary = {
        "results_tag": tag,
        "total_reports": len(reports),
        "verdict_counts": verdict_counts,
        "model_used_counts": model_counts,
        "expected_labels_malicious": n_malicious_labels,
        "expected_labels_benign": n_benign_labels,
        "metrics_lenient": print_metrics_lenient,
    }
    os.makedirs(SUMMARY_DIR, exist_ok=True)
    with open(summary_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Summary -> {summary_out}")


if __name__ == "__main__":
    main()

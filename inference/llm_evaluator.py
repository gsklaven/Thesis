"""
LLM evaluation of one package (stage 3 of the system): RAG + prompt per Behavior Chain -> verdict per
chain -> aggregation into the package verdict -> results/<RESULTS_TAG>/report_<package>.json.

The LLM provider is selected in .env (LLM_PROVIDER = deepseek | gemini | lmstudio | openrouter, see
llm_providers.py). EVERYTHING else is shared by all providers: the same prompt, the same parsing of the
answer, the same retries for chains that fail, the same aggregation (INCOMPLETE instead of BENIGN when
chains are missing) and the same report format. The thesis experiments use deepseek (deepseek-flash).

Usage: python3 llm_evaluator.py /path/to/package_chains.json
"""
import sys
import os
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from query_rag import RAGEngine, PROMPT_VERSION, RESULTS_TAG
from llm_providers import INITIAL_RETRY_DELAY, get_provider

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", RESULTS_TAG)
TAGS_FILE = os.path.join(BASE_DIR, "attack_type_tags.json")

# After the first pass, chains that returned ERROR/PARSE_ERROR are sent again up to this many times, so
# that the final verdict is based on ALL chains of the package.
CHAIN_RETRY_ROUNDS = 3
FAILED_VERDICTS = ("ERROR", "PARSE_ERROR")

# (name, model, call function, parallel calls) - this already checks that the provider's key exists
PROVIDER, MODEL, evaluate_prompt, MAX_WORKERS = get_provider()
_LABEL = {"deepseek": "DeepSeek", "gemini": "Gemini", "lmstudio": "LM Studio", "openrouter": "OpenRouter"}[PROVIDER]


def aggregate_verdicts(chain_results):
    """
    Aggregate verdict of the whole package.

    RULE: "any MALICIOUS chain = MALICIOUS package". This keeps full sensitivity - a malicious package
    with a single malicious chain is detected. There is no limit on chains per package; noise is reduced
    by excluding pure vendor chains (query_rag.py / utils.is_pure_vendor_chain) and by the v12 prompt.

    Order of precedence: MALICIOUS > SUSPICIOUS > EVALUATION_FAILED (no chain evaluated) >
    INCOMPLETE (some chains failed) > BENIGN (all chains BENIGN) > UNKNOWN. EVALUATION_FAILED is checked
    BEFORE all(BENIGN), which would be True for an empty list when ALL chains failed (API quota etc.).
    """
    verdicts = []
    for r in chain_results:
        llm_eval = r.get("llm_evaluation", {})
        v = llm_eval.get("verdict", "UNKNOWN")
        verdicts.append(v)

    if "MALICIOUS" in verdicts:
        return "MALICIOUS"
    elif "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"

    non_failed = [v for v in verdicts if v not in ("ERROR", "PARSE_ERROR", "UNKNOWN")]
    if not non_failed:
        return "EVALUATION_FAILED"
    # Partial failure without any MALICIOUS: what the failed chains would have said is unknown, so the
    # package is NOT declared BENIGN.
    if len(non_failed) < len(verdicts):
        return "INCOMPLETE"
    if all(v == "BENIGN" for v in non_failed):
        return "BENIGN"
    return "UNKNOWN"


def _evaluate_one(idx, chain_result):
    """Send one chain's prompt to the LLM (runs in a worker thread); returns (index, parsed answer)."""
    llm_result = evaluate_prompt(chain_result['prompt_for_llm'])
    return idx, llm_result


def main(json_path):
    """Evaluate every chain of one package in parallel (with retry rounds), aggregate and write the report."""
    if not os.path.exists(json_path):
        print(f"[!] The file {json_path} does not exist.")
        sys.exit(1)

    package_name = os.path.basename(json_path).replace(".json", "")
    print(f"[*] Running the RAG pipeline for: {package_name}")

    # The LLM judges ONLY from the behavior chain and the retrieved context: no pre-computed hint about
    # the package (e.g. typosquatting) is passed in the prompt.
    extra_context = ""

    engine = RAGEngine()
    results = engine.analyze_package(json_path, extra_context=extra_context)

    # no chain to evaluate: an explicit NO_CHAINS_FOUND report (never a silent BENIGN)
    if not results:
        print("[-] No behavior chains found to analyse.")
        report = {
            "package_name": package_name, "prompt_version": "n/a",
            "llm_provider": PROVIDER, "llm_model": MODEL,
            "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "final_verdict": "NO_CHAINS_FOUND", "total_chains_analyzed": 0,
            "vendor_chains_excluded": getattr(engine, "last_vendor_excluded", 0),
            "malicious_chains": 0, "suspicious_chains": 0, "chain_details": [],
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)
        with open(os.path.join(RESULTS_DIR, f"report_{package_name}.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return

    print(f"[*] {len(results)} behavior chains found. Sending to {_LABEL} ({MODEL}, "
          f"{MAX_WORKERS} in parallel)...")

    # round 0 sends every chain; each retry round re-sends only the chains that failed, with backoff
    pending = list(range(len(results)))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for round_no in range(1 + CHAIN_RETRY_ROUNDS):
            if round_no:
                print(f"[*] Retry round {round_no}/{CHAIN_RETRY_ROUNDS}: {len(pending)} chains failed, again...")
                time.sleep(INITIAL_RETRY_DELAY * 2 ** round_no)
            futures = {executor.submit(_evaluate_one, i, results[i]): i for i in pending}
            for future in as_completed(futures):
                orig_idx = futures[future]
                try:
                    idx, llm_result = future.result()
                except Exception as exc:
                    idx = orig_idx
                    llm_result = {"verdict": "ERROR", "error": f"Thread exception: {exc}"}
                llm_result["attempts"] = round_no + 1
                results[idx]["llm_evaluation"] = llm_result
                r = results[idx]
                verdict = llm_result.get("verdict", "UNKNOWN")
                print(f"  Chain #{r['chain_index']} ({r['category']}) | "
                      f"Sim: {r['top_malware_similarity']:.3f} | Verdict: {verdict}")
            pending = [i for i in pending if results[i]["llm_evaluation"].get("verdict") in FAILED_VERDICTS]
            if not pending:
                break

    final_verdict = aggregate_verdicts(results)
    report = {
        "package_name": package_name,
        "prompt_version": results[0].get("prompt_version", "unversioned") if results else "unversioned",
        "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "llm_provider": PROVIDER,
        "llm_model": MODEL,
        "final_verdict": final_verdict,
        "total_chains_analyzed": len(results),
        "failed_chains": len(pending),
        "vendor_chains_excluded": getattr(engine, "last_vendor_excluded", 0),
        "malicious_chains": sum(1 for r in results if r.get("llm_evaluation", {}).get("verdict") == "MALICIOUS"),
        "suspicious_chains": sum(1 for r in results if r.get("llm_evaluation", {}).get("verdict") == "SUSPICIOUS"),
        "chain_details": results,
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, f"report_{package_name}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[✓] FINAL VERDICT: {final_verdict} -> {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 llm_evaluator.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)
    main(sys.argv[1])

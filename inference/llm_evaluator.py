"""
Αξιολόγηση ενός πακέτου με LLM: RAG + prompt ανά Behavior Chain -> απόφαση ανά chain ->
συγκέντρωση σε απόφαση πακέτου -> results/<RESULTS_TAG>/report_<πακέτο>.json.

Ο πάροχος του LLM επιλέγεται στο .env (LLM_PROVIDER = deepseek | gemini | lmstudio | openrouter,
βλ. llm_providers.py). ΟΛΑ τα υπόλοιπα είναι κοινά για κάθε πάροχο: ίδιο prompt, ίδια ανάγνωση της
απάντησης, ίδιες επαναλήψεις για όσα chains αποτυγχάνουν, ίδια συγκέντρωση (INCOMPLETE αντί για
BENIGN όταν λείπουν chains), ίδια μορφή αναφοράς. Τα πειράματα της εργασίας: deepseek (deepseek-flash).

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

# Μετά το πρώτο πέρασμα, όσα chains έδωσαν ERROR/PARSE_ERROR ξαναστέλνονται μέχρι τόσες
# φορές, ώστε το τελικό verdict να βγαίνει από ΟΛΑ τα chains του πακέτου.
CHAIN_RETRY_ROUNDS = 3
FAILED_VERDICTS = ("ERROR", "PARSE_ERROR")

# (όνομα, μοντέλο, κλήση, παράλληλες κλήσεις) - ελέγχει ήδη εδώ ότι υπάρχει το κλειδί του παρόχου
PROVIDER, MODEL, evaluate_prompt, MAX_WORKERS = get_provider()
_LABEL = {"deepseek": "DeepSeek", "gemini": "Gemini", "lmstudio": "LM Studio", "openrouter": "OpenRouter"}[PROVIDER]


def aggregate_verdicts(chain_results):
    """
    Συγκεντρωτικό verdict για ολόκληρο το πακέτο.

    ΛΟΓΙΚΗ: "any MALICIOUS chain = MALICIOUS package"
    Αυτό διατηρεί πλήρη sensitivity — ένα malicious package με 1 μόνο
    κακόβουλο chain θα εντοπιστεί. Δεν υπάρχει όριο chains ανά πακέτο· ο
    θόρυβος περιορίζεται με την εξαίρεση των καθαρά vendor chains
    (query_rag.py / utils.is_pure_vendor_chain) και με το v12 prompt.

    ΚΡΙΣΙΜΟ: έλεγχος EVALUATION_FAILED ΠΡΙΝ το all(BENIGN) για ασφάλεια
    από κενά iterables όταν ΟΛΑ τα chains αποτύχουν (API quota κτλ.).
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
    # Μερική αποτυχία χωρίς κανένα MALICIOUS: δεν ξέρουμε τι θα έλεγαν τα chains που
    # απέτυχαν, οπότε ΔΕΝ δίνουμε BENIGN (βλ. v11: python-dotenv/gunicorn/flask).
    if len(non_failed) < len(verdicts):
        return "INCOMPLETE"
    if all(v == "BENIGN" for v in non_failed):
        return "BENIGN"
    return "UNKNOWN"


def _evaluate_one(idx, chain_result):
    llm_result = evaluate_prompt(chain_result['prompt_for_llm'])
    return idx, llm_result


def main(json_path):
    if not os.path.exists(json_path):
        print(f"[!] Το αρχείο {json_path} δεν υπάρχει.")
        sys.exit(1)

    package_name = os.path.basename(json_path).replace(".json", "")
    print(f"[*] Εκτέλεση RAG Pipeline για: {package_name}")

    # Ο LLM κρίνει ΜΟΝΟ από το behavior chain και την ομοιότητα με γνωστά πακέτα: καμία
    # προ-υπολογισμένη ένδειξη (π.χ. typosquatting) δεν περνάει στο prompt.
    extra_context = ""

    engine = RAGEngine()
    results = engine.analyze_package(json_path, extra_context=extra_context)

    if not results:
        print("[-] Δεν βρέθηκαν behavior chains για ανάλυση.")
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

    print(f"[*] {len(results)} behavior chains βρέθηκαν. Αποστολή στο {_LABEL} ({MODEL}, "
          f"{MAX_WORKERS} παράλληλα)...")

    pending = list(range(len(results)))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for round_no in range(1 + CHAIN_RETRY_ROUNDS):
            if round_no:
                print(f"[*] Retry γύρος {round_no}/{CHAIN_RETRY_ROUNDS}: {len(pending)} chains απέτυχαν, ξανά...")
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
    print(f"[✓] ΤΕΛΙΚΟ VERDICT: {final_verdict} -> {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Χρήση: python3 llm_evaluator.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)
    main(sys.argv[1])
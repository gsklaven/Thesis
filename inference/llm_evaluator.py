"""
LLM SSVC Evaluator using local Ollama (Llama 3.1).

ΝΕΟ: Τοπική εκτέλεση για μηδενικό κόστος.
"""
import sys
import os
import re
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from query_rag import RAGEngine, PROMPT_VERSION

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")

RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
TAGS_FILE = os.path.join(BASE_DIR, "attack_type_tags.json")

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 3

# ΚΡΙΣΙΜΟ: Για τοπική εκτέλεση με Ollama, το MAX_WORKERS πρέπει να είναι 1 ή 2
# το πολύ, ώστε να μην εξαντληθεί η μνήμη (RAM) του συστήματος από ταυτόχρονα inferences.
MAX_WORKERS = 3
OLLAMA_MODEL = "llama3.1"
OLLAMA_URL = "http://localhost:11434/api/generate"


def _extract_json(text):
    """
    Προσπαθεί να εξάγει έγκυρο JSON από κείμενο που ΔΕΝ είναι καθαρό JSON.
    """
    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace:last_brace + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None


def evaluate_with_ollama(prompt_text, retries=MAX_RETRIES):
    payload = {
    "model": OLLAMA_MODEL,
    "prompt": prompt_text,
    "stream": False,
    "format": "json",
    "options": {
        "num_ctx": 8192   # δοκίμασε πρώτα αυτό, ανέβασε αν χρειαστεί
    }
}

    for attempt in range(retries):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=300)
            response.raise_for_status()
            
            result_data = response.json()
            content = result_data.get("response", "")

            if not content:
                print(f"  [!] Ollama: κενή απάντηση - retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY)
                    continue
                return {
                    "verdict": "ERROR",
                    "error": f"Ollama: κενή απάντηση μετά από {retries} προσπάθειες",
                    "model_used": OLLAMA_MODEL,
                }
                
            try:
                result = _extract_json(content)
                if result is None:
                    raise json.JSONDecodeError("δεν βρέθηκε έγκυρο JSON", content, 0)
                result["model_used"] = OLLAMA_MODEL
                return result
            except json.JSONDecodeError:
                return {
                    "verdict": "PARSE_ERROR",
                    "raw_response": content[:2000],
                    "error": "Ollama returned non-JSON response",
                    "model_used": OLLAMA_MODEL,
                }
                
        except Exception as e:
            error_str = str(e)
            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY
                print(f"  [!] Ollama retry {attempt+1}/{retries} (σε {delay}s): {error_str[:100]}")
                time.sleep(delay)
            else:
                return {"verdict": "ERROR", "error": f"Ollama request failed: {error_str[:200]}"}


def aggregate_verdicts(chain_results):
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
    if all(v == "BENIGN" for v in non_failed):
        return "BENIGN"
    return "UNKNOWN"


def _evaluate_one(idx, chain_result):
    """Worker function - καλείται παράλληλα (αν MAX_WORKERS > 1)."""
    llm_result = evaluate_with_ollama(chain_result['prompt_for_llm'])
    return idx, llm_result


def main(json_path):
    if not os.path.exists(json_path):
        print(f"[!] Το αρχείο {json_path} δεν υπάρχει.")
        sys.exit(1)

    package_name = os.path.basename(json_path).replace(".json", "")
    print(f"[*] Εκτέλεση RAG Pipeline για: {package_name}")

    extra_context = ""
    if os.path.exists(TAGS_FILE):
        with open(TAGS_FILE, "r", encoding="utf-8") as f:
            tags_data = json.load(f)
        if package_name in tags_data:
            pkg_tags = tags_data[package_name].get("attack_type_tags", [])
            typosquat_info = tags_data[package_name].get("typosquat_details")

            if "typosquatting" in pkg_tags and typosquat_info:
                extra_context = (
                    f"\n[CRITICAL CONTEXT]: This package has been flagged as "
                    f"'TYPOSQUATTING'. It mimics the legitimate package "
                    f"'{typosquat_info.get('typosquat_of', 'unknown')}' "
                    f"(edit distance: {typosquat_info.get('edit_distance', '?')}). "
                    f"Typosquatting is a known supply chain attack vector.\n"
                )

    engine = RAGEngine()
    results = engine.analyze_package(json_path, extra_context=extra_context)

    if not results:
        print("[-] Δεν βρέθηκαν behavior chains για ανάλυση.")
        report = {
            "package_name": package_name,
            "prompt_version": "n/a",
            "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "final_verdict": "NO_CHAINS_FOUND",
            "total_chains_analyzed": 0,
            "malicious_chains": 0,
            "suspicious_chains": 0,
            "chain_details": [],
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)
        output_path = os.path.join(RESULTS_DIR, f"report_{package_name}.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[✓] Report (0 chains) αποθηκεύτηκε: {output_path}")
        return

    print(f"[*] {len(results)} behavior chains βρέθηκαν. Αποστολή στο Ollama "
          f"({MAX_WORKERS} παράλληλα)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(_evaluate_one, i, r): i
            for i, r in enumerate(results)
        }
        for future in as_completed(futures):
            orig_idx = futures[future]
            try:
                idx, llm_result = future.result()
            except Exception as exc:
                idx = orig_idx
                llm_result = {"verdict": "ERROR", "error": f"Thread exception: {exc}"}
                print(f"  [!] Απρόβλεπτο σφάλμα σε chain #{idx}: {exc}")

            results[idx]["llm_evaluation"] = llm_result

            r = results[idx]
            verdict = llm_result.get("verdict", "UNKNOWN")
            confidence = llm_result.get("confidence", "?")
            ssvc = llm_result.get("ssvc_decision", "?")
            summary = llm_result.get("summary", llm_result.get("error", ""))

            print(f"\n{'='*60}")
            print(f"  Chain #{r['chain_index']} ({r['category']}) | "
                  f"Sim: {r['top_malware_similarity']:.3f} | "
                  f"Pre-verdict: {r['pre_verdict']}")
            print(f"  [{'✓' if verdict == 'BENIGN' else '⚠' if verdict == 'SUSPICIOUS' else '✗'}] "
                  f"Verdict: {verdict} | Confidence: {confidence} | SSVC: {ssvc}")
            if summary:
                print(f"  Summary: {summary[:200]}")

    final_verdict = aggregate_verdicts(results)

    report = {
        "package_name": package_name,
        "prompt_version": results[0].get("prompt_version", "unversioned") if results else "unversioned",
        "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "final_verdict": final_verdict,
        "total_chains_analyzed": len(results),
        "malicious_chains": sum(
            1 for r in results
            if r.get("llm_evaluation", {}).get("verdict") == "MALICIOUS"
        ),
        "suspicious_chains": sum(
            1 for r in results
            if r.get("llm_evaluation", {}).get("verdict") == "SUSPICIOUS"
        ),
        "chain_details": results,
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, f"report_{package_name}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"╔══════════════════════════════════════════════════╗")
    print(f"║  ΤΕΛΙΚΟ VERDICT: {final_verdict:33s} ║")
    print(f"║  Chains: {report['total_chains_analyzed']} total | "
          f"{report['malicious_chains']} malicious | "
          f"{report['suspicious_chains']} suspicious"
          f"{' ' * max(0, 14 - len(str(report['total_chains_analyzed'])))}║")
    print(f"╚══════════════════════════════════════════════════╝")
    print(f"\n[✓] Report αποθηκεύτηκε: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Χρήση: python3 llm_evaluator.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)

    main(sys.argv[1])
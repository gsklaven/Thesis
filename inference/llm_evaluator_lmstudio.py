"""
LLM SSVC Evaluator μέσω LM Studio (τοπικό, OpenAI-συμβατό API).

ΣΚΟΠΟΣ: επίδειξη ότι το pipeline μπορεί να τρέξει ΕΝΤΕΛΩΣ τοπικά, χωρίς
κανένα δεδομένο να φύγει από τη συσκευή - σημαντικό επιχείρημα ασφάλειας/
data-residency για οργανισμούς με αυστηρές πολιτικές.

Προαπαιτούμενο: άνοιξε το LM Studio, φόρτωσε ένα μοντέλο, και ενεργοποίησε
το τοπικό server (κουμπί "Start Server" στο tab "Developer" / "Local
Server" - default port 1234).
"""
import sys
import os
import re
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

from query_rag import RAGEngine, PROMPT_VERSION

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
TAGS_FILE = os.path.join(BASE_DIR, "attack_type_tags.json")

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 3
MAX_WORKERS = 1  # συντηρητικό - το τοπικό inference server έχει περιορισμένη παραλληλία

LM_STUDIO_URL = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
LM_STUDIO_MODEL = os.environ.get("LM_STUDIO_MODEL", "local-model")  # LM Studio συνήθως αγνοεί/αυτο-επιλέγει

_thread_local = threading.local()


def get_client():
    if not hasattr(_thread_local, "client"):
        _thread_local.client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
    return _thread_local.client


def _strip_thinking_tags(text):
    """Ασφαλές net αν φορτώσεις reasoning μοντέλο (π.χ. DeepSeek-R1/QwQ) στο
    LM Studio - αφαιρεί <think>...</think> πριν το JSON parsing."""
    if not text:
        return text
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_json(text):
    if not text:
        return None
    text = _strip_thinking_tags(text)
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


def evaluate_with_lm_studio(prompt_text, retries=MAX_RETRIES):
    client = get_client()
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=LM_STUDIO_MODEL,
                messages=[{"role": "user", "content": prompt_text}],
                temperature=0.1,
            )
            content = response.choices[0].message.content if response.choices else None

            if not content:
                print(f"  [!] LM Studio: κενή απάντηση - retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY)
                    continue
                return {"verdict": "ERROR", "error": "LM Studio: κενή απάντηση", "model_used": LM_STUDIO_MODEL}

            result = _extract_json(content)
            if result is None:
                return {
                    "verdict": "PARSE_ERROR", "raw_response": content[:2000],
                    "error": "LM Studio returned non-JSON response", "model_used": LM_STUDIO_MODEL,
                }
            result["model_used"] = LM_STUDIO_MODEL
            return result

        except Exception as e:
            error_str = str(e)
            if attempt < retries - 1:
                print(f"  [!] LM Studio retry {attempt+1}/{retries}: {error_str[:150]}")
                time.sleep(INITIAL_RETRY_DELAY)
            else:
                return {"verdict": "ERROR", "error": f"LM Studio request failed: {error_str[:200]}"}


def aggregate_verdicts(chain_results):
    verdicts = [r.get("llm_evaluation", {}).get("verdict", "UNKNOWN") for r in chain_results]
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
    llm_result = evaluate_with_lm_studio(chain_result['prompt_for_llm'])
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
            "package_name": package_name, "prompt_version": "n/a",
            "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "final_verdict": "NO_CHAINS_FOUND", "total_chains_analyzed": 0,
            "malicious_chains": 0, "suspicious_chains": 0, "chain_details": [],
        }
        os.makedirs(RESULTS_DIR, exist_ok=True)
        with open(os.path.join(RESULTS_DIR, f"report_{package_name}.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return

    print(f"[*] {len(results)} behavior chains βρέθηκαν. Αποστολή στο LM Studio ({MAX_WORKERS} παράλληλα)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_evaluate_one, i, r): i for i, r in enumerate(results)}
        for future in as_completed(futures):
            orig_idx = futures[future]
            try:
                idx, llm_result = future.result()
            except Exception as exc:
                idx = orig_idx
                llm_result = {"verdict": "ERROR", "error": f"Thread exception: {exc}"}
            results[idx]["llm_evaluation"] = llm_result
            r = results[idx]
            verdict = llm_result.get("verdict", "UNKNOWN")
            print(f"  Chain #{r['chain_index']} ({r['category']}) | Sim: {r['top_malware_similarity']:.3f} | Verdict: {verdict}")

    final_verdict = aggregate_verdicts(results)
    report = {
        "package_name": package_name,
        "prompt_version": results[0].get("prompt_version", "unversioned") if results else "unversioned",
        "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "final_verdict": final_verdict,
        "total_chains_analyzed": len(results),
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
        print("Χρήση: python3 llm_evaluator_lmstudio.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)
    main(sys.argv[1])

"""
LLM SSVC Evaluator μέσω DeepSeek API (OpenAI-συμβατό).

Σημαντικά τεχνικά σημεία:
- Endpoint: https://api.deepseek.com (OpenAI format)
- Μοντέλο: deepseek-flash (φθηνότερο/γρηγορότερο tier - κατάλληλο για
  batch evaluation μεγάλου όγκου, σε αντίθεση με το πιο ακριβό/αργό
  flagship deepseek-v4-pro)
- ΚΡΙΣΙΜΟ: thinking mode είναι ΕΝΕΡΓΟ by default. Χωρίς ρητή απενεργο-
  ποίηση, ΚΑΘΕ chain παράγει έξτρα reasoning tokens - περισσότερο κόστος
  ΚΑΙ χρόνο, χωρίς όφελος για το δικό μας δομημένο classification task.
- Ακόμα και σε non-thinking mode, η επίσημη τεκμηρίωση αναφέρει ότι η
  απάντηση μπορεί να ξεκινά με ένα μοναχικό, άδειο "</think>" tag (χωρίς
  αντίστοιχο άνοιγμα) - το _strip_thinking_tags() το χειρίζεται ρητά,
  ξεχωριστά από το κανονικό <think>...</think> ζευγάρι.
- temperature=0.1 (όχι το γενικά προτεινόμενο 1.0 του DeepSeek) - σκόπιμη
  επιλογή: το δικό μας task χρειάζεται συνεπή ταξινόμηση, όχι δημιουργική
  ποικιλομορφία. Το 1.0 είναι tuned για conversational χρήση.
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

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/Users/giorgos/Documents/Thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
TAGS_FILE = os.path.join(BASE_DIR, "attack_type_tags.json")

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 3
# ΝΕΟ: DeepSeek concurrency limit είναι 2.500 (πολύ πάνω από ό,τι
# χρειαζόμαστε) - μπορούμε να είμαστε πολύ πιο επιθετικοί εδώ απ' ό,τι
# με τοπικό μοντέλο (1) ή ακόμα και με το Gemini (4).
MAX_WORKERS = 8

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    print("[!] Σφάλμα: Δεν βρέθηκε το DEEPSEEK_API_KEY στο περιβάλλον.")
    print("    Τρέξε πρώτα: export DEEPSEEK_API_KEY='το_κλειδί_σου'")
    print("    (Κλειδί από https://platform.deepseek.com - χρειάζεται")
    print("     τουλάχιστον $2 υπόλοιπο, αλλιώς 402 Insufficient Balance)")
    sys.exit(1)

DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")

_thread_local = threading.local()


def get_client():
    if not hasattr(_thread_local, "client"):
        _thread_local.client = OpenAI(base_url="https://api.deepseek.com", api_key=DEEPSEEK_API_KEY)
    return _thread_local.client


def _strip_thinking_tags(text):
    """Αφαιρεί κανονικά <think>...</think> ζεύγη, ΚΑΙ ξεχωριστά έναν
    πιθανό μοναχικό "</think>" στην αρχή (χωρίς άνοιγμα) - η επίσημη
    τεκμηρίωση του DeepSeek αναφέρει ρητά ότι ακόμα και σε non-thinking
    mode η απάντηση μπορεί να ξεκινά έτσι."""
    if not text:
        return text
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"^\s*</think>\s*", "", text)
    return text.strip()


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


def evaluate_with_deepseek(prompt_text, retries=MAX_RETRIES):
    client = get_client()
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=DEEPSEEK_MODEL,
                messages=[{"role": "user", "content": prompt_text}],
                temperature=0.1,
                response_format={"type": "json_object"},
                extra_body={"thinking": {"type": "disabled"}},
            )
            content = response.choices[0].message.content if response.choices else None

            if not content:
                print(f"  [!] DeepSeek: κενή απάντηση - retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY)
                    continue
                return {"verdict": "ERROR", "error": "DeepSeek: κενή απάντηση", "model_used": DEEPSEEK_MODEL}

            result = _extract_json(content)
            if result is None:
                return {
                    "verdict": "PARSE_ERROR", "raw_response": content[:2000],
                    "error": "DeepSeek returned non-JSON response", "model_used": DEEPSEEK_MODEL,
                }
            result["model_used"] = DEEPSEEK_MODEL
            return result

        except Exception as e:
            error_str = str(e)
            is_rate_limit = "429" in error_str or "rate" in error_str.lower()
            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY * (2 ** attempt) if is_rate_limit else INITIAL_RETRY_DELAY
                print(f"  [!] DeepSeek retry {attempt+1}/{retries} (σε {delay}s): {error_str[:150]}")
                time.sleep(delay)
            else:
                return {"verdict": "ERROR", "error": f"DeepSeek request failed: {error_str[:200]}"}


def aggregate_verdicts(chain_results):
    """
    Συγκεντρωτικό verdict για ολόκληρο το πακέτο.

    ΛΟΓΙΚΗ: "any MALICIOUS chain = MALICIOUS package"
    Αυτό διατηρεί πλήρη sensitivity — ένα malicious package με 1 μόνο
    κακόβουλο chain θα εντοπιστεί. Το noise πρόβλημα (FPs σε μεγάλα
    packages) λύνεται με chain deduplication (MAX_CHAINS_PER_PACKAGE)
    και με ακριβέστερο per-chain verdict (v12 prompt), όχι με threshold.

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
    if all(v == "BENIGN" for v in non_failed):
        return "BENIGN"
    return "UNKNOWN"


def _evaluate_one(idx, chain_result):
    llm_result = evaluate_with_deepseek(chain_result['prompt_for_llm'])
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

    print(f"[*] {len(results)} behavior chains βρέθηκαν. Αποστολή στο DeepSeek "
          f"({MAX_WORKERS} παράλληλα)...")

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
            print(f"  Chain #{r['chain_index']} ({r['category']}) | "
                  f"Sim: {r['top_malware_similarity']:.3f} | Verdict: {verdict}")

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
        print("Χρήση: python3 llm_evaluator_deepseek.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)
    main(sys.argv[1])
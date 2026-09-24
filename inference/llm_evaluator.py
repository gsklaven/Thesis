"""
LLM SSVC Evaluator using Google Gemini (Modern SDK).

ΝΕΟ: Παράλληλα API calls (ThreadPoolExecutor) αντί για σειριακά με
υποχρεωτική καθυστέρηση 1.5s ανά chain. I/O-bound δουλειά (κάθε request
απλά περιμένει απάντηση δικτύου) - threads αρκούν, δεν χρειάζεται
multiprocessing. Κάθε thread έχει το ΔΙΚΟ ΤΟΥ Client instance (thread-local),
ώστε να μη μοιράζονται κατάσταση μεταξύ ταυτόχρονων κλήσεων.
"""
import sys
import os
import re
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from google import genai
from google.genai import types

try:
    from openai import OpenAI as _OpenAIClient
except ImportError:
    _OpenAIClient = None

from query_rag import RAGEngine, PROMPT_VERSION

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")

# ΝΕΟ: ο φάκελος αποτελεσμάτων είναι πλέον ΑΝΑ prompt version, αυτόματα.
# Χωρίς αυτό, ένα re-run μετά από αλλαγή prompt θα έγραφε ΠΑΝΩ από τα
# προηγούμενα reports (ίδιο filename), χάνοντας τη δυνατότητα before/after
# σύγκρισης. Τώρα: results/v1/, results/v2/, κ.λπ. - ποτέ δεν συγκρούονται,
# χωρίς να χρειάζεται να διαχειρίζεσαι φακέλους χειροκίνητα.
RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)
TAGS_FILE = os.path.join(BASE_DIR, "attack_type_tags.json")


MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 3

# ΝΕΟ: πόσα ταυτόχρονα API calls. Συντηρητική προεπιλογή - ανέβασέ το αν ΔΕΝ
# βλέπεις σφάλματα rate-limit (429) στο output, κατέβασέ το αν βλέπεις.
MAX_WORKERS = 4

API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("[!] Σφάλμα: Δεν βρέθηκε το GEMINI_API_KEY στο περιβάλλον (environment).")
    print("    Τρέξε πρώτα: export GEMINI_API_KEY='το_κλειδί_σου'")
    sys.exit(1)

# ΝΕΟ: OpenRouter fallback - ενεργοποιείται ΜΟΝΟ όταν το Gemini επιστρέψει
# πραγματικό quota-exhaustion σφάλμα (όχι σε κάθε τυχαίο error). Προαιρετικό -
# αν δεν οριστεί το κλειδί, δουλεύει όπως πριν (μόνο Gemini, χωρίς fallback).
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
OPENROUTER_MODEL = "openrouter/free"  # αυτόματος router σε ό,τι δωρεάν μοντέλο δουλεύει τώρα

_thread_local = threading.local()


def get_client():
    """Ένα Client instance ανά thread - όχι κοινόχρηστο, για ασφάλεια."""
    if not hasattr(_thread_local, "client"):
        _thread_local.client = genai.Client(api_key=API_KEY)
    return _thread_local.client


def get_openrouter_client():
    if not hasattr(_thread_local, "openrouter_client"):
        _thread_local.openrouter_client = _OpenAIClient(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
        )
    return _thread_local.openrouter_client


def _is_quota_exhausted(error_str):
    """Ανιχνεύει ΕΙΔΙΚΑ quota exhaustion - όχι κάθε σφάλμα. Το fallback έχει
    νόημα ΜΟΝΟ εδώ (retry στο ίδιο quota δεν βοηθάει ποτέ), όχι σε παροδικά
    network/5xx σφάλματα όπου το κανονικό Gemini retry ήδη αρκεί."""
    markers = ("RESOURCE_EXHAUSTED", "exceeded your current quota", "429")
    return any(m in error_str for m in markers)


def _extract_json(text):
    """
    Προσπαθεί να εξάγει έγκυρο JSON από κείμενο που ΔΕΝ είναι καθαρό JSON -
    συχνό όταν το OpenRouter's δωρεάν router διαλέγει μοντέλο που δεν τηρεί
    αυστηρά το response_format={"type": "json_object"} constraint (π.χ. το
    τυλίγει σε markdown code fence, ή προσθέτει επεξηγηματικό κείμενο πριν/μετά).

    Δοκιμάζει, με σειρά:
      1. Απευθείας parse (ήδη καθαρό JSON)
      2. Αφαίρεση ```json ... ``` ή ``` ... ``` markdown code fence
      3. Bracket-matching: από το πρώτο '{' έως το ΤΕΛΕΥΤΑΙΟ '}' στο κείμενο

    Επιστρέφει το parsed dict, ή None αν αποτύχουν όλα (γνήσιο PARSE_ERROR).
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


def evaluate_with_openrouter(prompt_text, retries=MAX_RETRIES):
    if not OPENROUTER_API_KEY or _OpenAIClient is None:
        return {
            "verdict": "ERROR",
            "error": "OpenRouter fallback μη διαθέσιμο (λείπει OPENROUTER_API_KEY ή 'pip install openai').",
        }

    client = get_openrouter_client()
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=[{"role": "user", "content": prompt_text}],
                temperature=0.1,
                top_p=0.8,
                response_format={"type": "json_object"},
            )
            choice = response.choices[0] if response.choices else None
            content = choice.message.content if choice else None

            if not content:
                finish_reason = getattr(choice, "finish_reason", None) if choice else None
                print(f"  [!] OpenRouter: κενή απάντηση (finish_reason={finish_reason}) - "
                      f"retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY * (2 ** attempt))
                    continue
                return {
                    "verdict": "ERROR",
                    "error": f"OpenRouter: κενή απάντηση μετά από {retries} προσπάθειες "
                             f"(finish_reason={finish_reason})",
                    "model_used": OPENROUTER_MODEL,
                }
            try:
                result = _extract_json(content)
                if result is None:
                    raise json.JSONDecodeError("δεν βρέθηκε έγκυρο JSON", content, 0)
                result["model_used"] = OPENROUTER_MODEL
                return result
            except json.JSONDecodeError:
                return {
                    "verdict": "PARSE_ERROR",
                    "raw_response": content[:2000],
                    "error": "OpenRouter (fallback) returned non-JSON response",
                    "model_used": OPENROUTER_MODEL,
                }
        except Exception as e:
            error_str = str(e)
            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                print(f"  [!] OpenRouter retry {attempt+1}/{retries} (σε {delay}s): {error_str[:100]}")
                time.sleep(delay)
            else:
                return {"verdict": "ERROR", "error": f"OpenRouter fallback failed: {error_str[:200]}"}


def evaluate_with_gemini(prompt_text, retries=MAX_RETRIES):
    client = get_client()
    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model='gemini-3.6-flash',
                contents=prompt_text,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    top_p=0.8,
                    response_mime_type="application/json",
                ),
            )

            if response.text is None:
                return {
                    "verdict": "ERROR",
                    "error": "Response blocked by safety filters",
                    "raw_response": None,
                }

            try:
                result = _extract_json(response.text)
                if result is None:
                    raise json.JSONDecodeError("δεν βρέθηκε έγκυρο JSON", response.text, 0)
                result["model_used"] = "gemini-3.6-flash"
                return result
            except json.JSONDecodeError:
                return {
                    "verdict": "PARSE_ERROR",
                    "raw_response": response.text[:2000],
                    "error": "LLM returned non-JSON response",
                    "model_used": "gemini-3.6-flash",
                }

        except Exception as e:
            error_str = str(e)

            # ΝΕΟ: αν είναι πραγματικό quota exhaustion, ΜΗΝ ξαναδοκιμάσεις
            # Gemini (δεν θα βοηθήσει) - πήγαινε ΑΜΕΣΩΣ σε OpenRouter fallback.
            if _is_quota_exhausted(error_str):
                if OPENROUTER_API_KEY:
                    print(f"  [→] Gemini quota εξαντλήθηκε - fallback σε OpenRouter (δωρεάν)...")
                    return evaluate_with_openrouter(prompt_text)
                else:
                    return {
                        "verdict": "EVALUATION_FAILED",
                        "error": f"Gemini quota εξαντλήθηκε, χωρίς OPENROUTER_API_KEY για fallback: {error_str[:200]}",
                    }

            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                print(f"  [!] Retry {attempt+1}/{retries} (σε {delay}s): {error_str[:100]}")
                time.sleep(delay)
            else:
                return {
                    "verdict": "ERROR",
                    "error": f"API call failed after {retries} retries: {error_str[:200]}",
                }


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
    """Worker function - καλείται παράλληλα, μία φορά ανά behavior chain."""
    llm_result = evaluate_with_gemini(chain_result['prompt_for_llm'])
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
        # ΚΡΙΣΙΜΟ FIX: ΠΡΙΝ, εδώ απλά "return" χωρίς να γράψει τίποτα - το
        # check_test_set.py μετά έβρισκε "κανένα report" και το μέτραγε
        # σιωπηλά σαν "ΔΕΝ ΤΡΕΞΕ" -> λάθος αποτέλεσμα (false negative), ενώ
        # στην πραγματικότητα ΠΟΤΕ δεν δοκιμάστηκε - το CodeQL απλά δεν
        # βρήκε καμία ευαίσθητη συμπεριφορά σε αυτό το πακέτο. Τώρα γράφουμε
        # ΠΑΝΤΑ ένα report, με ρητό, ΞΕΧΩΡΙΣΤΟ verdict "NO_CHAINS_FOUND" -
        # ώστε να είναι σαφές ότι αυτό είναι περιορισμός του στατικού
        # ανάλυσης σταδίου (CodeQL), όχι του LLM reasoning.
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

    print(f"[*] {len(results)} behavior chains βρέθηκαν. Αποστολή στο Gemini "
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
                # ΝΕΟ: αν σκάσει το thread (απρόβλεπτο exception), ΜΗΝ αφήσεις
                # το chain χωρίς llm_evaluation - χωρίς αυτό, ένα crashed chain
                # μπορεί σιωπηλά να οδηγήσει σε λάθος "BENIGN" aggregate αν τα
                # υπόλοιπα chains είναι όλα BENIGN.
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
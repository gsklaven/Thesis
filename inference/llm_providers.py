"""
Κλήση του LLM για ΕΝΑ prompt, για κάθε υποστηριζόμενο πάροχο. Όλη η υπόλοιπη λογική (RAG, prompt,
επαναλήψεις ανά chain, συγκέντρωση σε απόφαση πακέτου, αναφορά) είναι κοινή, στο llm_evaluator.py.

Επιλογή παρόχου στο .env (βλ. .env.example):
  LLM_PROVIDER=deepseek    DEEPSEEK_API_KEY, DEEPSEEK_MODEL (deepseek-flash)          - τα πειράματα της εργασίας
  LLM_PROVIDER=gemini      GEMINI_API_KEY, GEMINI_MODEL (gemini-3.6-flash)
  LLM_PROVIDER=lmstudio    LM_STUDIO_URL (http://localhost:1234/v1), LM_STUDIO_MODEL - τοπικό μοντέλο, κανένα
                           δεδομένο δεν φεύγει από τον υπολογιστή
  LLM_PROVIDER=openrouter  OPENROUTER_API_KEY, OPENROUTER_MODEL (υποχρεωτικό: συγκεκριμένο μοντέλο)
  LLM_MAX_WORKERS          παράλληλες κλήσεις ανά πακέτο (προεπιλογή ανά πάροχο)

Κοινές ρυθμίσεις για όλους: temperature 0.1, απάντηση JSON όπου το υποστηρίζει ο πάροχος, ίδια ανάγνωση
του JSON. Κάθε αποτέλεσμα γράφει ποιο μοντέλο απάντησε (model_used). ΔΕΝ γίνεται ποτέ σιωπηλή αλλαγή
μοντέλου (π.χ. σε άλλο πάροχο όταν τελειώσει το όριο): η κλήση επιστρέφει ERROR και το chain
ξαναδοκιμάζεται, ώστε όλα τα αποτελέσματα μιας εκτέλεσης να προέρχονται από το ίδιο μοντέλο.
"""
import json
import os
import re
import sys
import threading
import time

# Φόρτωση του .env της ρίζας (κλειδιά, LLM_PROVIDER) - βλ. dataset/preparation/utils.load_env_file
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "preparation"))
import utils  # noqa: E402,F401

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "deepseek").strip().lower()
PROVIDERS = ("deepseek", "gemini", "lmstudio", "openrouter")

MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 3
_DEFAULT_WORKERS = {"deepseek": 8, "gemini": 4, "lmstudio": 1, "openrouter": 4}

_thread_local = threading.local()


def _strip_thinking_tags(text):
    """Αφαιρεί κανονικά <think>...</think> ζεύγη, ΚΑΙ ξεχωριστά έναν
    πιθανό μοναχικό "</think>" στην αρχή (χωρίς άνοιγμα) - η επίσημη
    τεκμηρίωση του DeepSeek αναφέρει ρητά ότι ακόμα και σε non-thinking
    mode η απάντηση μπορεί να ξεκινά έτσι. Χρήσιμο και για reasoning μοντέλα στο LM Studio."""
    if not text:
        return text
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"^\s*</think>\s*", "", text)
    return text.strip()


def _extract_json(text):
    """Καθαρό JSON, ή JSON μέσα σε ```json ... ```, ή από το πρώτο '{' έως το τελευταίο '}'."""
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


def _finalize(content, label, model):
    """Κοινή ανάγνωση της απάντησης για όλους τους παρόχους."""
    result = _extract_json(content)
    if result is None:
        return {
            "verdict": "PARSE_ERROR", "raw_response": content[:2000],
            "error": f"{label} returned non-JSON response", "model_used": model,
        }
    result["model_used"] = model
    keys = list(result)
    result["reasoning_before_verdict"] = (
        "reasoning" in keys and "verdict" in keys and keys.index("reasoning") < keys.index("verdict"))
    return result


def _need(var, hint):
    value = os.environ.get(var)
    if not value:
        print(f"[!] Σφάλμα: λείπει το {var} (LLM_PROVIDER={LLM_PROVIDER}).")
        print(f"    Γράψ' το στο .env της ρίζας του έργου: {var}=... (βλ. .env.example)")
        if hint:
            print(f"    {hint}")
        sys.exit(1)
    return value


# ------------------------------------------------------------------ OpenAI-συμβατοί (DeepSeek, LM Studio, OpenRouter)
def _openai_client(base_url, api_key):
    from openai import OpenAI
    if not hasattr(_thread_local, "client"):
        _thread_local.client = OpenAI(base_url=base_url, api_key=api_key)
    return _thread_local.client


def _openai_compatible(prompt_text, *, label, base_url, api_key, model, extra, retries=MAX_RETRIES,
                       backoff_on_rate_limit=True):
    client = _openai_client(base_url, api_key)
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt_text}],
                temperature=0.1,
                **extra,
            )
            content = response.choices[0].message.content if response.choices else None

            if not content:
                print(f"  [!] {label}: κενή απάντηση - retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY)
                    continue
                return {"verdict": "ERROR", "error": f"{label}: κενή απάντηση", "model_used": model}

            return _finalize(content, label, model)

        except Exception as e:
            error_str = str(e)
            is_rate_limit = "429" in error_str or "rate" in error_str.lower()
            if attempt < retries - 1:
                delay = (INITIAL_RETRY_DELAY * (2 ** attempt)
                         if (is_rate_limit and backoff_on_rate_limit) else INITIAL_RETRY_DELAY)
                print(f"  [!] {label} retry {attempt+1}/{retries} (σε {delay}s): {error_str[:150]}")
                time.sleep(delay)
            else:
                return {"verdict": "ERROR", "error": f"{label} request failed: {error_str[:200]}"}


# ------------------------------------------------------------------ Gemini (google-genai)
def _gemini(prompt_text, *, api_key, model, retries=MAX_RETRIES):
    from google import genai
    from google.genai import types
    if not hasattr(_thread_local, "client"):
        _thread_local.client = genai.Client(api_key=api_key)
    client = _thread_local.client
    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt_text,
                config=types.GenerateContentConfig(temperature=0.1, response_mime_type="application/json"),
            )
            if response.text is None:
                return {"verdict": "ERROR", "error": "Gemini: η απάντηση μπλοκαρίστηκε (safety filters)",
                        "model_used": model}
            return _finalize(response.text, "Gemini", model)
        except Exception as e:
            error_str = str(e)
            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                print(f"  [!] Gemini retry {attempt+1}/{retries} (σε {delay}s): {error_str[:150]}")
                time.sleep(delay)
            else:
                # Και το εξαντλημένο όριο (quota) καταλήγει εδώ: ERROR -> το chain ξαναδοκιμάζεται,
                # χωρίς σιωπηλή αλλαγή μοντέλου.
                return {"verdict": "ERROR", "error": f"Gemini request failed: {error_str[:200]}", "model_used": model}


# ------------------------------------------------------------------ επιλογή παρόχου
def get_provider():
    """Επιστρέφει (όνομα, μοντέλο, συνάρτηση prompt -> αποτέλεσμα, παράλληλες κλήσεις)."""
    if LLM_PROVIDER not in PROVIDERS:
        sys.exit(f"[!] Άγνωστο LLM_PROVIDER={LLM_PROVIDER} - επιλογές: {', '.join(PROVIDERS)}")
    workers = int(os.environ.get("LLM_MAX_WORKERS") or _DEFAULT_WORKERS[LLM_PROVIDER])

    if LLM_PROVIDER == "deepseek":
        # thinking mode ΕΝΕΡΓΟ by default στο DeepSeek -> ρητή απενεργοποίηση (κόστος/χρόνος χωρίς όφελος
        # για το δομημένο task). temperature 0.1: συνεπής ταξινόμηση, όχι δημιουργική ποικιλία.
        key = _need("DEEPSEEK_API_KEY", "Κλειδί από https://platform.deepseek.com - χρειάζεται υπόλοιπο, "
                                        "αλλιώς 402 Insufficient Balance.")
        model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
        extra = {"response_format": {"type": "json_object"}, "extra_body": {"thinking": {"type": "disabled"}}}
        return "deepseek", model, lambda p: _openai_compatible(
            p, label="DeepSeek", base_url="https://api.deepseek.com", api_key=key, model=model, extra=extra), workers

    if LLM_PROVIDER == "gemini":
        key = _need("GEMINI_API_KEY", "Κλειδί από https://aistudio.google.com/apikey")
        model = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        return "gemini", model, lambda p: _gemini(p, api_key=key, model=model), workers

    if LLM_PROVIDER == "lmstudio":
        # LM Studio: άνοιξε το server (Developer / Local Server, port 1234) με φορτωμένο μοντέλο.
        url = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
        model = os.environ.get("LM_STUDIO_MODEL", "local-model")
        return "lmstudio", model, lambda p: _openai_compatible(
            p, label="LM Studio", base_url=url, api_key="lm-studio", model=model, extra={},
            backoff_on_rate_limit=False), workers

    key = _need("OPENROUTER_API_KEY", "Κλειδί από https://openrouter.ai/keys")
    model = _need("OPENROUTER_MODEL", "Συγκεκριμένο μοντέλο, π.χ. deepseek/deepseek-chat - όχι αυτόματος router, "
                                      "ώστε όλα τα αποτελέσματα να προέρχονται από το ίδιο μοντέλο.")
    extra = {"response_format": {"type": "json_object"}}
    return "openrouter", model, lambda p: _openai_compatible(
        p, label="OpenRouter", base_url="https://openrouter.ai/api/v1", api_key=key, model=model, extra=extra), workers

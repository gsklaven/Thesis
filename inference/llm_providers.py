"""
Call the LLM for ONE prompt, for every supported provider. All the other logic (RAG, prompt, retries
per chain, aggregation into a package verdict, report) is shared, in llm_evaluator.py.

Provider selection in .env (see .env.example):
  LLM_PROVIDER=deepseek    DEEPSEEK_API_KEY, DEEPSEEK_MODEL (deepseek-flash)          - the thesis experiments
  LLM_PROVIDER=gemini      GEMINI_API_KEY, GEMINI_MODEL (gemini-3.6-flash)
  LLM_PROVIDER=lmstudio    LM_STUDIO_URL (http://localhost:1234/v1), LM_STUDIO_MODEL - a local model, no
                           data leaves the computer; LM_STUDIO_REASONING (default "none": no hidden
                           reasoning, like DeepSeek's disabled thinking mode; "" = the model's default)
  LLM_PROVIDER=openrouter  OPENROUTER_API_KEY, OPENROUTER_MODEL (required: one specific model)
  LLM_MAX_WORKERS          parallel calls per package (default per provider)

Shared settings for all: temperature 0.1, JSON answers where the provider supports them, the same JSON
parsing. Every result records which model answered (model_used). There is NEVER a silent model switch
(e.g. to another provider when a quota runs out): the call returns ERROR and the chain is retried, so
all results of a run come from the same model.
"""
import json
import os
import re
import sys
import threading
import time

# Load the project's .env (keys, LLM_PROVIDER) - see dataset/preparation/utils.load_env_file
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "preparation"))
import utils  # noqa: E402,F401

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "deepseek").strip().lower()
PROVIDERS = ("deepseek", "gemini", "lmstudio", "openrouter")

MAX_RETRIES = 3          # attempts per call (on top of the evaluator's retry rounds per chain)
INITIAL_RETRY_DELAY = 3  # seconds, doubled on every rate-limited retry
# LM Studio serves several requests in parallel (continuous batching): 4 gave ~1.5x the throughput of 1
_DEFAULT_WORKERS = {"deepseek": 8, "gemini": 4, "lmstudio": 4, "openrouter": 4}

# one API client per worker thread (clients are not shared between threads)
_thread_local = threading.local()


def _strip_thinking_tags(text):
    """
    Remove <think>...</think> pairs, and separately a possible lone "</think>" at the start (without an
    opening tag) - the DeepSeek documentation states that even in non-thinking mode an answer may start
    like that. Also useful for reasoning models in LM Studio.
    """
    if not text:
        return text
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"^\s*</think>\s*", "", text)
    return text.strip()


def _extract_json(text):
    """Plain JSON, or JSON inside ```json ... ```, or the text from the first '{' to the last '}'; else None."""
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
    """
    Shared parsing of an answer for all providers: the parsed JSON plus model_used and
    reasoning_before_verdict (whether the model wrote its reasoning before the verdict, as instructed),
    or a PARSE_ERROR result with the start of the raw answer.
    """
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
    """Value of a required environment variable; exits with instructions for .env if it is missing."""
    value = os.environ.get(var)
    if not value:
        print(f"[!] Error: {var} is missing (LLM_PROVIDER={LLM_PROVIDER}).")
        print(f"    Add it to the .env file at the project root: {var}=... (see .env.example)")
        if hint:
            print(f"    {hint}")
        sys.exit(1)
    return value


# ------------------------------------------------------------------ OpenAI-compatible (DeepSeek, LM Studio, OpenRouter)
def _openai_client(base_url, api_key):
    """The calling thread's OpenAI-compatible client (created on first use)."""
    from openai import OpenAI
    if not hasattr(_thread_local, "client"):
        _thread_local.client = OpenAI(base_url=base_url, api_key=api_key)
    return _thread_local.client


def _openai_compatible(prompt_text, *, label, base_url, api_key, model, extra, retries=MAX_RETRIES,
                       backoff_on_rate_limit=True):
    """
    One chat-completion call to an OpenAI-compatible endpoint, with retries: empty answers are retried
    after a short delay, errors after a delay that doubles for rate limits. Returns the parsed result or
    an ERROR result.
    """
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
                print(f"  [!] {label}: empty answer - retry {attempt+1}/{retries}")
                if attempt < retries - 1:
                    time.sleep(INITIAL_RETRY_DELAY)
                    continue
                return {"verdict": "ERROR", "error": f"{label}: empty answer", "model_used": model}

            return _finalize(content, label, model)

        except Exception as e:
            error_str = str(e)
            is_rate_limit = "429" in error_str or "rate" in error_str.lower()
            if attempt < retries - 1:
                delay = (INITIAL_RETRY_DELAY * (2 ** attempt)
                         if (is_rate_limit and backoff_on_rate_limit) else INITIAL_RETRY_DELAY)
                print(f"  [!] {label} retry {attempt+1}/{retries} (in {delay}s): {error_str[:150]}")
                time.sleep(delay)
            else:
                return {"verdict": "ERROR", "error": f"{label} request failed: {error_str[:200]}"}


# ------------------------------------------------------------------ Gemini (google-genai)
def _gemini(prompt_text, *, api_key, model, retries=MAX_RETRIES):
    """One Gemini call (JSON response type) with exponential backoff; returns the parsed result or ERROR."""
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
                return {"verdict": "ERROR", "error": "Gemini: the answer was blocked (safety filters)",
                        "model_used": model}
            return _finalize(response.text, "Gemini", model)
        except Exception as e:
            error_str = str(e)
            if attempt < retries - 1:
                delay = INITIAL_RETRY_DELAY * (2 ** attempt)
                print(f"  [!] Gemini retry {attempt+1}/{retries} (in {delay}s): {error_str[:150]}")
                time.sleep(delay)
            else:
                # An exhausted quota also ends here: ERROR -> the chain is retried, without a silent
                # model switch.
                return {"verdict": "ERROR", "error": f"Gemini request failed: {error_str[:200]}", "model_used": model}


# ------------------------------------------------------------------ provider selection
def get_provider():
    """Return (name, model, function prompt -> result, parallel calls) of the configured provider."""
    if LLM_PROVIDER not in PROVIDERS:
        sys.exit(f"[!] Unknown LLM_PROVIDER={LLM_PROVIDER} - options: {', '.join(PROVIDERS)}")
    workers = int(os.environ.get("LLM_MAX_WORKERS") or _DEFAULT_WORKERS[LLM_PROVIDER])

    if LLM_PROVIDER == "deepseek":
        # DeepSeek's thinking mode is ON by default -> explicitly disabled (cost/time without benefit for
        # this structured task, whose steps are defined by the prompt). temperature 0.1: consistent
        # classification, not creative variety.
        key = _need("DEEPSEEK_API_KEY", "Key from https://platform.deepseek.com - it needs a balance, "
                                        "otherwise 402 Insufficient Balance.")
        model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
        extra = {"response_format": {"type": "json_object"}, "extra_body": {"thinking": {"type": "disabled"}}}
        return "deepseek", model, lambda p: _openai_compatible(
            p, label="DeepSeek", base_url="https://api.deepseek.com", api_key=key, model=model, extra=extra), workers

    if LLM_PROVIDER == "gemini":
        key = _need("GEMINI_API_KEY", "Key from https://aistudio.google.com/apikey")
        model = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        return "gemini", model, lambda p: _gemini(p, api_key=key, model=model), workers

    if LLM_PROVIDER == "lmstudio":
        # LM Studio: start the server (Developer / Local Server, port 1234) with a model loaded.
        url = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
        model = os.environ.get("LM_STUDIO_MODEL", "local-model")
        # Reasoning models (e.g. Gemma 4, Qwen 3) otherwise spend ~2/3 of their output on hidden reasoning;
        # reasoning_effort="none" turns it off, as the thesis experiments do for DeepSeek.
        effort = os.environ.get("LM_STUDIO_REASONING", "none")
        extra = {"extra_body": {"reasoning_effort": effort}} if effort else {}
        return "lmstudio", model, lambda p: _openai_compatible(
            p, label="LM Studio", base_url=url, api_key="lm-studio", model=model, extra=extra,
            backoff_on_rate_limit=False), workers

    # openrouter: a specific model is required (no automatic router), so all results come from one model
    key = _need("OPENROUTER_API_KEY", "Key from https://openrouter.ai/keys")
    model = _need("OPENROUTER_MODEL", "A specific model, e.g. deepseek/deepseek-chat - not an automatic router, "
                                      "so that all results come from the same model.")
    extra = {"response_format": {"type": "json_object"}}
    return "openrouter", model, lambda p: _openai_compatible(
        p, label="OpenRouter", base_url="https://openrouter.ai/api/v1", api_key=key, model=model, extra=extra), workers

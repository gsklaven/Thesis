"""
Multi-Hop RAG Query System & LLM Prompt Generator (SSVC Ready).
"""
import json
import sys
import os
import numpy as np
from sentence_transformers import SentenceTransformer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "preparation"))
from utils import flatten_chain_to_text  # noqa: E402

BASE_DIR = "/home/sklavenitis/thesis/dataset"

INDEX_DIR = os.path.join(BASE_DIR, "indexes", "rag_index")
POLICY_INDEX_DIR = os.path.join(BASE_DIR, "indexes", "policy_index")

VECTORS_FILE = os.path.join(INDEX_DIR, "vectors.npy")
METADATA_FILE = os.path.join(INDEX_DIR, "metadata.json")
POLICY_VECTORS_FILE = os.path.join(POLICY_INDEX_DIR, "policy_vectors.npy")
POLICY_METADATA_FILE = os.path.join(POLICY_INDEX_DIR, "policy_metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"
MALWARE_TOP_K = 3
POLICY_TOP_K = 3
MALWARE_THRESHOLD = 0.55

# ΝΕΟ: prompt version tracking. Αύξησε αυτό ΚΑΘΕ ΦΟΡΑ που αλλάζεις ουσιαστικά
# το SSVC_COT_PROMPT παρακάτω (όχι για τυπογραφικά) - ώστε τα reports να
# κρατούν ΡΗΤΑ ποιο prompt τα παρήγαγε. Χωρίς αυτό, ένα before/after
# πείραμα σε νέο prompt θα μπέρδευε ασυνείδητα v1 και v2 reports μαζί σε
# ένα evaluation_summary.py run - κάνοντας αδύνατη τη σωστή σύγκριση.
PROMPT_VERSION = "v3"


SSVC_COT_PROMPT = """You are a Senior Cybersecurity Analyst specializing in software supply chain threats.
You must evaluate the following Python/npm package for malicious intent using the SSVC framework.

═══════════════════════════════════════════════════════
PACKAGE UNDER ANALYSIS: {package_name}
═══════════════════════════════════════════════════════

SECTION 1 — CODE BEHAVIOR (CodeQL Static Analysis Output):
{behavior_text}

SECTION 2 — SIMILAR KNOWN MALWARE (RAG Retrieval, top {malware_top_k} matches):
{malware_context}

SECTION 3 — RELEVANT SECURITY POLICIES (top {policy_top_k} matches):
{policy_context}

{extra_context}

═══════════════════════════════════════════════════════
CHAIN-OF-THOUGHT ANALYSIS — Follow these steps IN ORDER:
═══════════════════════════════════════════════════════

STEP 1 — CODE INTENT ANALYSIS:
Examine the code behavior in Section 1. What is the code actually doing?
Is this behavior consistent with the package's stated purpose, or is it
anomalous? Pay special attention to: setup.py hooks, __init__.py side-effects,
obfuscated strings, and network calls at import time.

STEP 2 — FALSE POSITIVE CHECK:
CRITICAL: Legitimate packages often use subprocess, exec(), socket, or
file I/O for standard build scripts, testing, or API features. If the
detected flow is clearly standard library functionality, well-documented
benign build tooling, or normal operations UNAMBIGUOUSLY consistent with
the package's stated purpose (e.g., an SSH library making SSH connections,
a cloud SDK reading cloud credentials) → mark as FALSE POSITIVE. However,
do NOT default to FALSE POSITIVE merely because the API usage pattern is
common or the package name sounds legitimate — a common API used for a
purpose UNRELATED to the package's stated function (e.g., unexpected
outbound network calls, credential access, or process execution with no
connection to any documented feature) remains a valid signal of malicious
intent, even if each individual API call looks unremarkable in isolation.

STEP 3 — MALWARE SIMILARITY ASSESSMENT:
Compare with the known malware samples in Section 2. How structurally
similar is this code to known-malicious behavior? Consider: Are the data
flows (source → sink) analogous? Is the control flow pattern (gating
conditions) similar? Or is the similarity superficial (both use sockets,
but for entirely different purposes)? IMPORTANT: a high similarity score
(above ~0.90) to a matched sample remains meaningful evidence even when
that sample's own attack-type tag is "unclassified" — many confirmed
malicious samples in this dataset lack a specific label for data-sourcing
reasons unrelated to severity. Do not discount a strong structural match
solely because the matched neighbor's tag is generic.

STEP 4 — POLICY VIOLATION ANALYSIS:
Check each policy in Section 3. Does this code violate any of these
security policies? If so, which specific policy and why?

STEP 5 — MITRE ATT&CK MAPPING:
If the behavior appears malicious, map it to the most relevant MITRE
ATT&CK technique(s). Consider: T1059 (Command Execution), T1071
(Application Layer Protocol), T1005 (Data from Local System),
T1041 (Exfiltration Over C2), T1027 (Obfuscated Files), etc.

STEP 6 — SSVC RISK ASSESSMENT:
Apply the SSVC decision framework:
- Exploitation: Is this automatable? (yes/no)
- Technical Impact: partial or total?
- Decision: TRACK (benign/FP) | TRACK* (suspicious, monitor) | ATTEND (likely malicious) | ACT (confirmed malicious)
When the evidence is suggestive but not fully conclusive (e.g., moderate-
to-high similarity with plausible but not certain malicious intent),
prefer SUSPICIOUS/TRACK* over BENIGN/TRACK — flagging an ambiguous case
for review is preferable to silently missing a genuine threat. Reserve
BENIGN/TRACK for cases where the false-positive explanation from STEP 2
is clear and well-supported by the code's stated purpose.

═══════════════════════════════════════════════════════
OUTPUT — Respond ONLY with a valid JSON object:
═══════════════════════════════════════════════════════

{{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": 0.0,
  "ssvc_decision": "TRACK | TRACK* | ATTEND | ACT",
  "reasoning": {{
    "code_intent": "Brief description of what the code does",
    "is_false_positive": true,
    "false_positive_reason": "Why this is/isn't a false positive"
  }},
  "malware_similarity": {{
    "most_similar_package": "package_name or null",
    "similarity_score": 0.0,
    "similarity_explanation": "Why the behavior matches/doesn't match"
  }},
  "policy_violations": [
    {{
      "policy_id": "e.g., CWE-94 or OWASP-CICD-SEC-3",
      "policy_name": "Name of violated policy",
      "violation_reason": "Why this code violates this policy"
    }}
  ],
  "mitre_mapping": [
    {{
      "technique_id": "e.g., T1059.006",
      "technique_name": "e.g., Command and Scripting Interpreter: Python",
      "relevance": "How this behavior maps to this technique"
    }}
  ],
  "summary": "One-paragraph human-readable summary for the security report"
}}"""


def cosine_search(query_vec, vectors, top_k=5):
    similarities = np.dot(vectors, query_vec)
    best_indices = np.argsort(similarities)[::-1][:top_k]
    return [(float(similarities[i]), i) for i in best_indices]


class RAGEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def _ensure_init(self):
        if self._initialized:
            return
        print(f"[*] Φόρτωση RAG Engine ({MODEL_NAME})...")
        self.model = SentenceTransformer(MODEL_NAME)

        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            self.malware_meta = json.load(f)
        self.malware_vectors = np.load(VECTORS_FILE)

        with open(POLICY_METADATA_FILE, "r", encoding="utf-8") as f:
            self.policy_meta = json.load(f)
        self.policy_vectors = np.load(POLICY_VECTORS_FILE)

        print(f"  [*] Malware index: {len(self.malware_meta)} vectors")
        print(f"  [*] Policy index: {len(self.policy_meta)} vectors")
        self._initialized = True

    def analyze_package(self, json_path, extra_context=""):
        self._ensure_init()

        if not os.path.exists(json_path):
            return []

        package_name = os.path.basename(json_path).replace(".json", "")

        with open(json_path, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)

        results = []

        for idx, chain in enumerate(pkg_data.get("behavior_chains", [])):
            text = flatten_chain_to_text(chain)
            query_vec = self.model.encode([text], normalize_embeddings=True)[0]

            m_matches = cosine_search(query_vec, self.malware_vectors, MALWARE_TOP_K)
            p_matches = cosine_search(query_vec, self.policy_vectors, POLICY_TOP_K)

            malware_hits = [{
                "package": self.malware_meta[i]["package"],
                "similarity": round(sim, 4),
                "attack_type_tags": self.malware_meta[i].get("attack_type_tags", []),
                "category": self.malware_meta[i].get("category"),
                "campaign_preview": self.malware_meta[i].get("campaign_signature_preview", ""),
            } for sim, i in m_matches]

            policy_hits = [{
                "source": self.policy_meta[i]["source"],
                "id": self.policy_meta[i]["id"],
                "name": self.policy_meta[i]["name"],
                "description": self.policy_meta[i].get("description", "")[:200],
                "similarity": round(sim, 4),
            } for sim, i in p_matches]

            best_sim = malware_hits[0]["similarity"] if malware_hits else 0.0

            malware_context = "\n".join([
                f"- [{h['similarity']:.2f}] Package: {h['package']} | "
                f"Tags: {', '.join(h['attack_type_tags'])} | "
                f"Category: {h['category']}"
                for h in malware_hits
            ]) or "No similar malware found in the database."

            policy_context = "\n".join([
                f"- [{h['similarity']:.2f}] {h['source']} [{h['id']}]: "
                f"{h['name']} — {h['description'][:100]}"
                for h in policy_hits
            ]) or "No relevant security policies matched."

            prompt = SSVC_COT_PROMPT.format(
                package_name=package_name,
                behavior_text=text,
                malware_top_k=MALWARE_TOP_K,
                malware_context=malware_context,
                policy_top_k=POLICY_TOP_K,
                policy_context=policy_context,
                extra_context=extra_context,
            )

            results.append({
                "chain_index": idx,
                "category": chain.get("category"),
                "flow_boundary": chain.get("flow_boundary", "Unknown"),
                "sensitive_api": chain.get("sensitive_api", ""),
                "location": chain.get("location", ""),
                "top_malware_similarity": best_sim,
                "malware_matches": malware_hits,
                "policy_matches": policy_hits,
                "pre_verdict": "MATCHES_KNOWN_MALWARE" if best_sim >= MALWARE_THRESHOLD else "NO_STRONG_MATCH",
                "behavior_text": text,
                "prompt_for_llm": prompt,
                "prompt_version": PROMPT_VERSION,
            })

        return results


def analyze_package(json_path):
    engine = RAGEngine()
    return engine.analyze_package(json_path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Χρήση: python3 query_rag.py /path/to/sliced_behavior_chain.json")
        sys.exit(1)

    results = analyze_package(sys.argv[1])
    for r in results:
        print(f"\n{'='*60}")
        print(f"=== Chain #{r['chain_index']} ({r['category']}) ===")
        print(f"[*] Similarity: {r['top_malware_similarity']:.3f} | "
              f"Verdict: {r['pre_verdict']}")
        print(f"[*] Flow boundary: {r['flow_boundary']}")
        if r['malware_matches']:
            print(f"[*] Top match: {r['malware_matches'][0]['package']} "
                  f"(tags: {r['malware_matches'][0]['attack_type_tags']})")
        print("\n--- SSVC CoT PROMPT ---")
        print(r['prompt_for_llm'][:500] + "...\n")
        print("-" * 60)
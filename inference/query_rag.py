"""
Multi-Hop RAG Query System & LLM Prompt Generator (SSVC Ready).

Redesign (Fixes I2, I3, I5, I8, M4):
  - RAGEngine singleton: φόρτωσε model/vectors/metadata ΜΙΑ φορά.
  - Structured output: similarity scores, matched packages, policy IDs.
  - Symmetric embedding: δεν περνάμε attack_type_tags στο query
    (ταιριάζει τώρα με το index, βλ. R2 fix στο build_rag_index).
  - Chain-of-Thought prompt template αντί για flat instructions.
  - Package name included in context για πληρέστερη ανάλυση.
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


def cosine_search(query_vec, vectors, top_k=5):
    similarities = np.dot(vectors, query_vec)
    best_indices = np.argsort(similarities)[::-1][:top_k]
    return [(float(similarities[i]), i) for i in best_indices]


# ========================================================================
# Chain-of-Thought SSVC Prompt Template
# Υλοποιεί τα βήματα 5 & 6 της αρχιτεκτονικής:
#   5. RAG retrieval → context injection
#   6. CoT prompting → structured JSON output
# ========================================================================
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
Legitimate packages often use subprocess, exec(), socket, or file I/O for 
standard build scripts, testing, or API features. 
HOWEVER (CRITICAL EXCEPTION): Do NOT automatically mark 1-chain or short 
flows as FALSE POSITIVE if they exhibit malicious patterns such as:
- Connecting to hardcoded/unverified IPs or external domains.
- Executing obfuscated code (e.g., base64, hex encoding).
- Downloading and executing secondary payloads silently during setup/import.
If these patterns exist, the intent is likely malicious despite being a short chain.

STEP 3 — MALWARE SIMILARITY ASSESSMENT:
Compare with the known malware samples in Section 2. How structurally
similar is this code to known-malicious behavior? Consider: Are the data
flows (source → sink) analogous? Is the control flow pattern (gating
conditions) similar? 
IMPORTANT: Malicious droppers often use a single, direct chain (e.g., straight 
to exec() or subprocess). If a 1-chain package closely matches a known malware 
signature from Section 2, weight the decision heavily towards MALICIOUS.

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


class RAGEngine:
    """
    M4 FIX: Singleton — φόρτωσε model/vectors/metadata ΜΙΑ φορά.
    Χωρίς αυτό, κάθε κλήση analyze_package() ξανα-φορτώνει:
    - SentenceTransformer (βαρύ initialization)
    - numpy vectors + JSON metadata (I/O)
    """
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
        """
        Αναλύει ένα behavior chain JSON και επιστρέφει structured results
        με similarity scores, matched packages, policy IDs, και CoT prompt.
        """
        self._ensure_init()

        if not os.path.exists(json_path):
            return []

        package_name = os.path.basename(json_path).replace(".json", "")

        with open(json_path, "r", encoding="utf-8") as f:
            pkg_data = json.load(f)

        results = []

        for idx, chain in enumerate(pkg_data.get("behavior_chains", [])):
            # I8 FIX: Symmetric embedding — ΔΕΝ περνάμε attack_type_tags
            # στο query, γιατί αυτά δεν υπάρχουν σε unknown πακέτα.
            text = flatten_chain_to_text(chain)
            query_vec = self.model.encode([text], normalize_embeddings=True)[0]

            m_matches = cosine_search(query_vec, self.malware_vectors, MALWARE_TOP_K)
            p_matches = cosine_search(query_vec, self.policy_vectors, POLICY_TOP_K)

            # I5 FIX: Structured match info — forward similarity scores + IDs
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

            # Build human-readable context strings for the prompt
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

            # I2+I3: CoT prompt with all expected elements
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
                # RAG retrieval results
                "top_malware_similarity": best_sim,
                "malware_matches": malware_hits,
                "policy_matches": policy_hits,
                "pre_verdict": "MATCHES_KNOWN_MALWARE" if best_sim >= MALWARE_THRESHOLD else "NO_STRONG_MATCH",
                # For LLM
                "behavior_text": text,
                "prompt_for_llm": prompt,
            })

        return results


# Backward compatibility: standalone usage
def analyze_package(json_path):
    """Wrapper για backward compatibility με llm_evaluator.py."""
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
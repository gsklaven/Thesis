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

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")

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
# ΣΗΜΕΙΩΣΗ: v3 έχει ΤΑΥΤΟΣΗΜΟ prompt κείμενο με το v2 (καμία αλλαγή στο
# SSVC_COT_PROMPT παρακάτω). Ο λόγος που υπάρχει ξεχωριστό version label:
# το v2 αξιολογήθηκε μόνο σε ένα stratified δείγμα 117 πακέτων (87 πρώην
# false negatives + 30 τυχαία ήδη-σωστά), ΟΧΙ στο πλήρες σύνολο 391+8. Το
# v3 τρέχει το ΙΔΙΟ prompt πάνω στο ΠΛΗΡΕΣ σύνολο, ώστε η σύγκριση με το
# v1 (που επίσης έτρεξε πλήρες) να είναι απευθείας συγκρίσιμη - ίδιος
# πληθυσμός και στις δύο πλευρές, χωρίς να χρειάζεται stratified-sample
# ανάλυση. Για το thesis: "v2" και "v3" αναφέρονται στο ΙΔΙΟ prompt σε
# διαφορετικό evaluation sample size, όχι σε διαφορετική prompt λογική.
# ΣΗΜΕΙΩΣΗ v6: πραγματική αλλαγή ΣΤΟ ΙΔΙΟ ΤΟ PROMPT ΚΕΙΜΕΝΟ (STEP 2) - όχι
# μόνο στο RAG index όπως το v5. Διόρθωση επιβεβαιωμένου precision
# regression: 9 γνωστά benign πακέτα (fabric, docker, kubernetes, pymongo,
# httpx, pyinstaller, pyyaml, python-dotenv, pytest) ταξινομήθηκαν λάθος ως
# MALICIOUS/SUSPICIOUS στο v5. Ρίζα του προβλήματος: το v4 αφαίρεσε την
# προηγούμενη προειδοποίηση για "διάσημα, καθιερωμένα πακέτα" από το STEP 2,
# αφήνοντας το LLM ευάλωτο σε γενικά, κοινά "σχήματα κώδικα" (base64+
# dynamic import, event-driven fetch) που ταιριάζουν με sim>0.9 σε ΟΠΟΙΟΔΗΠΟΤΕ
# πακέτο έχει παρόμοια επιφανειακή δομή, ανεξάρτητα από πραγματική πρόθεση.
# Το STEP 2 τώρα επαναφέρει ΚΑΙ ενισχύει αυτή την προστασία, στοχευμένα.
PROMPT_VERSION = "v8"


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
IMPORTANT — GENERIC CODE SHAPES ARE NOT BY THEMSELVES EVIDENCE: patterns
such as "base64 decode + dynamic __import__/exec" or "extract a value from
incoming data + make an outbound request" are extremely common in
legitimate code (plugin/lazy-loading systems, compressed asset or config
decoding, webhook/event handlers, feature flags) and appear near-identically
across thousands of unrelated packages. A high similarity score to Section 2
built ONLY on this kind of generic shape — especially when the matched
neighbor itself has no specific attack-type tag or analyst description
confirming what it actually does — is weak evidence on its own. Weigh it
against the package's real, well-established purpose: for a package that is
one of the most widely used, foundational tools in its ecosystem (e.g. a
major testing framework, container/orchestration client, or database
driver), a single structurally-generic match is NOT sufficient grounds for
MALICIOUS — look for something SPECIFIC to this package's actual behavior
(concrete evidence of what the decoded/fetched content is used for, an
install-time hook, credential harvesting, etc.) before concluding malicious
intent for such a package.

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

            # Πακέτο-επίπεδο γράφος εξαρτήσεων: διαθέσιμο στο JSON αλλά δεν
            # έφτανε ποτέ στο LLM prompt. Το προσθέτουμε ως συμπληρωματικό
            # context (μία φορά ανά chain, κρατάμε μικρό για να μην τρώει
            # tokens) ώστε το LLM να βλέπει τι τρίτου-μέρους βιβλιοθήκες
            # περικλείει το πακέτο - σημαντικό για supply-chain ανάλυση.
            dep_graph = pkg_data.get("package_dependency_graph", {})
            chain_extra = extra_context
            if dep_graph:
                dep_lines = [
                    f"  {pkg}: [{', '.join(deps[:5])}{'...' if len(deps) > 5 else ''}]"
                    for pkg, deps in list(dep_graph.items())[:10]
                ]
                dep_summary = (
                    "\n[PACKAGE DEPENDENCY GRAPH (vendored third-party libs)]:\n"
                    + "\n".join(dep_lines)
                    + (f"\n  ... ({len(dep_graph)} packages total)" if len(dep_graph) > 10 else "")
                    + "\n"
                )
                chain_extra = (extra_context + dep_summary) if extra_context else dep_summary

            # Heuristic scanner calibration note: when CodeQL found 0 chains and
            # the fallback regex scanner produced this chain, tell the LLM what
            # that means for confidence. The matched code snippet IS direct textual
            # evidence — it just lacks a full inter-procedural source→sink path.
            if chain.get("heuristic_source"):
                heuristic_note = (
                    "\n[STATIC ANALYSIS NOTE — HEURISTIC SCAN]: This behavior chain "
                    "was detected by a lightweight regex pattern scanner, NOT full "
                    "CodeQL taint tracking. CodeQL found zero behavior chains for "
                    "this package (common for obfuscated or install-hook malware). "
                    f"The specific pattern matched: {chain.get('heuristic_description', '')} "
                    "The matched code snippet in the 'Contributing data-flow nodes' "
                    "section is direct textual evidence — weigh it heavily. Do NOT "
                    "default to BENIGN solely because there is no full source→sink "
                    "path; this is expected for the obfuscation/install-hook class "
                    "of malware that evades static data-flow analysis.\n"
                )
                chain_extra = (chain_extra + heuristic_note) if chain_extra else heuristic_note

            m_matches = cosine_search(query_vec, self.malware_vectors, MALWARE_TOP_K)
            p_matches = cosine_search(query_vec, self.policy_vectors, POLICY_TOP_K)

            malware_hits = [{
                "package": self.malware_meta[i]["package"],
                "similarity": round(sim, 4),
                "attack_type_tags": self.malware_meta[i].get("attack_type_tags", []),
                "category": self.malware_meta[i].get("category"),
                "campaign_preview": self.malware_meta[i].get("campaign_signature_preview", ""),
                # ΝΕΟ: πραγματικό OSV description (όχι μόνο tags) - επικυρωμένο
                # εύρημα (p<0.000001 στο δικό μας recall-by-tag τεστ, ΚΑΙ το
                # ablation study του IntelGuard) ότι το πλούσιο, εξηγηματικό
                # κείμενο γύρω από ένα malware δείγμα βοηθάει σημαντικά το
                # LLM reasoning, πέρα από μόνο tags/category.
                "description": self.malware_meta[i].get("description", ""),
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
                + (f" | Analyst description: {h['description'][:250]}" if h.get("description") else "")
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
                extra_context=chain_extra,
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
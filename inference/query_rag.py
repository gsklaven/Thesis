"""
Multi-Hop RAG Query System & LLM Prompt Generator (SSVC Ready).
"""
import json
import re
import sys
import os
import numpy as np
from sentence_transformers import SentenceTransformer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "preparation"))
from utils import chain_to_llm_text, flatten_chain_to_text, is_pure_vendor_chain  # noqa: E402

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")

INDEX_DIR = os.path.join(BASE_DIR, "indexes", "rag_index")
POLICY_INDEX_DIR = os.path.join(BASE_DIR, "indexes", "policy_index")

VECTORS_FILE = os.path.join(INDEX_DIR, "vectors.npy")
METADATA_FILE = os.path.join(INDEX_DIR, "metadata.json")
POLICY_VECTORS_FILE = os.path.join(POLICY_INDEX_DIR, "policy_vectors.npy")
POLICY_METADATA_FILE = os.path.join(POLICY_INDEX_DIR, "policy_metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"
MALWARE_TOP_K = 5
POLICY_TOP_K = 4
# Δεύτερο στάδιο ανάκτησης policies: ερώτημα ΜΟΝΟ με το όνομα του sensitive API
# (το πλήρες κείμενο του chain σπάνια φέρνει τον κανόνα που αναφέρει το API).
# Τα αποτελέσματα ΕΝΩΝΟΝΤΑΙ με του πρώτου σταδίου (χωρίς διπλότυπα).
POLICY_API_TOP_K = 3
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
# v12: Ριζικά απλούστερο prompt. Αντί για 6 αντιφατικά steps, 3 σαφή
# ερωτήματα (Q1 συμπεριφορά, Q2 στάθμιση Τμήματος Β, Q3 δυαδικό verdict).
# Fixes: (a) LLM αθώωνε malicious squatted packages λόγω name recognition,
# (b) αντιφατικές εντολές → LLM διάλεγε BENIGN. Το verdict είναι BENIGN μόνο
# αν το Q1 δεν βρει ανεξήγητη ενέργεια (ανεξάρτητα από το similarity score),
# αλλιώς MALICIOUS· δεν υπάρχει πλέον κατάσταση SUSPICIOUS.
# 2026-09-24 (πριν τα runs του v12): ονόματα πεδίων που περιγράφουν ακριβώς τι
# είναι - is_false_positive -> behavior_explained (το LLM δεν ξέρει ground truth),
# policy_violations -> related_policies (ανακτημένες εγγραφές, όχι αποδεδειγμένες
# παραβιάσεις), και η λίστα εξαρτήσεων δεν λέγεται πια "vendored" (CODEQL_NO_VENDOR).
PROMPT_VERSION = "v12"

# Ablation: ίδιο prompt, αλλά αφαιρούνται τα ανακτημένα αποτελέσματα (το prompt
# ήδη λέει "No similar malware found" / "No relevant security policies matched").
# RAG_MODE: sum (προεπιλογή, δείγματα + policies) | samples (μόνο δείγματα malware)
#           | policy (μόνο policies) | llm (χωρίς ανάκτηση, μόνο LLM).
RAG_MODE = os.environ.get("RAG_MODE", "sum")
if RAG_MODE not in ("sum", "samples", "policy", "llm"):
    raise SystemExit(f"RAG_MODE άκυρο: {RAG_MODE}")
NO_MALWARE = RAG_MODE in ("policy", "llm")
NO_POLICY = RAG_MODE in ("samples", "llm")
# Φάκελος αποτελεσμάτων: results/v12_<RAG_MODE>[_<πάροχος αν όχι deepseek>][RESULTS_SUFFIX], ώστε
# αποτελέσματα άλλου LLM να μην αναμειγνύονται ποτέ με τα κύρια (deepseek).
_PROVIDER = os.environ.get("LLM_PROVIDER", "deepseek").strip().lower()
RESULTS_TAG = (f"{PROMPT_VERSION}_{RAG_MODE}" + ("" if _PROVIDER == "deepseek" else f"_{_PROVIDER}")
               + os.environ.get("RESULTS_SUFFIX", ""))


SSVC_COT_PROMPT = """You are a cybersecurity analyst evaluating a Python/npm package for malicious intent.

PACKAGE: {package_name}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION A — CODE BEHAVIOR (Static Analysis):
{behavior_text}

SECTION B — RAG SIMILARITY (top {malware_top_k} known-malicious matches):
{malware_context}

SECTION C — POLICY CONTEXT:
{policy_context}

{extra_context}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## HOW TO WEIGH THE EVIDENCE — READ FIRST

Section A (what the code actually does) and Section B (structural similarity
to known malware) answer DIFFERENT questions. Section A tells you what is
happening. Section B tells you that similar low-level code SHAPES appear in
confirmed malware — but shape alone does not tell you intent, because
legitimate code and malware both use eval(), file I/O, sockets, and dynamic
imports. A HIGH similarity score is NOT a default verdict to be overturned —
it is one piece of context you weigh alongside Section A.
THE DECIDING QUESTION IS ALWAYS: does Section A, on its own, show a SPECIFIC
action that is not explained by ordinary legitimate functionality — an
unexpected outbound call, credential access, install-time side effect, or
execution of dynamically-decoded content whose destination or purpose is not
documented anywhere in the visible code? If Section A shows nothing like
this, a high similarity score does not change that — you are looking at
generic code shape overlap, not a match to malicious INTENT. Package names
are not identity either way (RULE 1 below): do not assume "assertpy" or
"clearml" is safe just because you recognize the name, and do not assume it
is malicious just because a match looks alarming — in both directions, judge
Section A's actual behavior.

**RULE 1 — PACKAGE NAME ≠ PACKAGE IDENTITY:**
You are analyzing a file from PyPI/npm. A malicious package CAN have the exact
same name as a famous legitimate library (name squatting / dependency
confusion) — "assertpy", "clearml", "beaker", "crayons" etc. could be
malicious clones. Base your verdict ONLY on Section A, never on the name.

**RULE 2 — GENERIC CODE SHAPES ARE NOT INTENT, UNLESS A MATCH IS TAG-CONFIRMED:**
base64+exec, subprocess, socket, dynamic import, crypto/IV handling are
common in malware AND in legitimate code (compression, plugin loading,
encryption libraries, protocol handlers). A high similarity score built on
this kind of shape, WHEN THE MATCHED NEIGHBOR IS ITSELF UNCLASSIFIED OR
UNTAGGED, tells you the SHAPE recurs — not that this code shares that
neighbor's intent. BUT when a matched sample carries a SPECIFIC, non-generic
attack tag (credential-harvesting, data-exfiltration, backdoor, C2,
typosquatting, etc.) at meaningfully high similarity, that tag reflects a
human analyst's CONFIRMED classification of that exact pattern as malicious
— this is real evidence, and it is NOT cancelled out by the fact that the
underlying shape is also common elsewhere. "The shape is common" and "this
specific instance of the shape was confirmed malicious" are compatible facts,
not contradictory ones — do not use the former to dismiss the latter. Judge
by what the data flows TO: an outbound call to an undocumented destination,
a credential read with no connection to the package's stated purpose, or an
install-time side effect are real signals. A crypto library performing
crypto, a logger writing log files, or a serialization library using dynamic
imports for its own documented plugin system are not.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ANALYSIS

**Q1 — What does the code do, and is anything about it unexplained?**
Describe ONLY what Section A shows (not what the package name implies):
data sources, data destinations, install-time hooks, network calls,
credential access, obfuscation patterns.
Then answer directly: is there a SPECIFIC action here that is NOT fully
accounted for by ordinary, documented functionality? Name it precisely if
so (e.g., "writes to a path outside any documented config/cache location",
"makes an outbound call to a destination with no connection to the
package's stated purpose", "decodes and executes content whose purpose is
never referenced elsewhere in the visible code"). If every action has a
clear, specific, legitimate explanation, say so explicitly: "no
independently anomalous behavior — [state the specific legitimate
explanation, e.g. 'this is the package's own documented crypto IV handling'
or 'standard logging file-path setup']."

**Q2 — Does Section B change this assessment?**
State the top similarity score and the matched neighbor's tag.
- If Q1 found NO independent anomaly: Section B's score, however high, is
  evidence of generic shape overlap (RULE 2), not of intent. It does not
  override a clean Q1 finding. Say so explicitly rather than defaulting to
  suspicion because the number is high.
- If Q1 DID find a specific anomaly: does Section B corroborate it? Check
  EVERY match listed in Section B, not only the highest-ranked one — a
  SPECIFIC, non-generic attack tag (e.g., "credential-harvesting",
  "data-exfiltration", "backdoor", "C2", "typosquatting") on ANY match at
  meaningfully high similarity (≥ 0.85) IS corroboration, regardless of
  whether it happens to be ranked #1 or lower among the matches shown. A
  specific tag means a human analyst already confirmed that exact pattern
  in a different sample — this counts as corroboration EVEN WHEN the
  underlying code pattern (dynamic import, encoding, process execution) is
  itself common. RULE 2's caution about "generic shapes" applies to
  matches that are THEMSELVES unclassified/untagged — where you cannot
  tell whether the shape correlates with confirmed intent — not to matches
  that already carry a specific attack tag. Do not use RULE 2 to discount
  a specific tag just because the shape is common; that is what the tag
  is for. Only if EVERY match in Section B is unclassified/untagged does
  the similarity reduce to generic-shape overlap, in which case Q1's own
  finding stands on its own merits.

**Q3 — Final verdict.**
Choose: MALICIOUS | BENIGN. This is a BINARY decision — there is no
"monitor for now, not sure yet" middle option. Every case must resolve to
one or the other.
- BENIGN: Q1 found no independently anomalous behavior — every action is
  fully and specifically explained by ordinary, documented functionality.
  This holds REGARDLESS of the Section B similarity score — a clean,
  specifically-explained Q1 finding is not overridden by a high similarity
  number alone.
- MALICIOUS: everything else. Q1 found something not FULLY and
  SPECIFICALLY explained by ordinary legitimate functionality — this
  includes cases where Q1 itself is uncertain ("could be legitimate X, but
  could also be Y") as well as cases where Q1 is fully confident nothing
  legitimate accounts for it, and regardless of whether Section B
  corroborates with a specific tag or not. Do NOT hedge into a soft middle
  verdict: if you cannot fully and specifically explain the behavior via
  BENIGN's criteria above, the verdict is MALICIOUS. A specific attack tag
  in Section B (per Q2) or an unambiguous anomaly on its own both justify a
  HIGHER ssvc_decision (ATTEND/ACT rather than TRACK*, see below) but are
  not required to reach the MALICIOUS verdict itself once Q1 has identified
  something genuinely unexplained.
SSVC_DECISION GRANULARITY: use ssvc_decision to express your confidence
WITHIN the binary verdict, for downstream triage — it does not change the
verdict itself.
  - verdict BENIGN → ssvc_decision TRACK.
  - verdict MALICIOUS, but Q1's anomaly is genuinely tentative and Section B
    gives no specific-tag corroboration → ssvc_decision TRACK* (flag for
    human review, lower confidence).
  - verdict MALICIOUS, with either a specific-tag corroboration (Q2) or a
    clearly-identified anomaly → ssvc_decision ATTEND.
  - verdict MALICIOUS, with an unambiguous, confirmed malicious pattern
    (confirmed credential exfiltration, confirmed C2, confirmed execution
    of an undocumented decoded payload) → ssvc_decision ACT.
CONSISTENCY REQUIREMENT: behavior_explained in your JSON output must directly
reflect your Q1 finding and must agree with verdict: true only when verdict
is BENIGN (every action has a specific legitimate explanation), false
whenever verdict is MALICIOUS. Do not let these fields disagree with each
other or with Q1.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT — Respond ONLY with this JSON. Fill the fields IN THE ORDER SHOWN:
the reasoning fields (Q1, then Q2) come first and the verdict is derived
from them, so write the reasoning before you decide the verdict.

{{
  "reasoning": {{
    "code_intent": "Q1: What Section A code actually does",
    "q1_finding": "Q1: the specific anomaly, or the specific legitimate explanation for every action",
    "similarity_rule_applied": "Q2: How Section B was weighed given the Q1 finding",
    "behavior_explained": false
  }},
  "verdict": "MALICIOUS | BENIGN",
  "confidence": 0.0,
  "ssvc_decision": "TRACK | TRACK* | ATTEND | ACT",
  "malware_similarity": {{
    "most_similar_package": "package_name or null",
    "similarity_score": 0.0,
    "similarity_explanation": "Structural overlap description"
  }},
  "related_policies": [{{"policy_id": "...", "policy_name": "...", "relevance": "How this retrieved Section C entry relates to the behavior"}}],
  "mitre_mapping": [{{"technique_id": "...", "technique_name": "...", "relevance": "..."}}],
  "summary": "One-paragraph summary"
}}"""

_OSV_BOILERPLATE = re.compile(
    r"_-= Per source details\. Do not edit below this line\.=-_"   # διαχωριστικό του OSV
    r"|^#+\s*Source:.*$"                                             # "## Source: kam193 (hash)"
    r"|^\s*-{3,}\s*$", re.M)                                        # "---"


def clean_description(text):
    """
    Οι περιγραφές OSV ξεκινούν συχνά με boilerplate ("Malicious code in X (PyPI)", "---",
    "_-= Per source details... =-_", "## Source: <αναλυτής> (<hash>)") που έτρωγε το όριο των
    250 χαρακτήρων στο Τμήμα Β, πριν φτάσει η πραγματική περιγραφή. Αφαιρείται μόνο στο prompt.
    """
    t = _OSV_BOILERPLATE.sub(" ", text or "")
    t = re.sub(r"^\s*Malicious code in \S+ \((PyPI|npm)\)\s*", "", t.strip())
    return re.sub(r"\s+", " ", t).strip()


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
        api_cache = {}
        self.last_vendor_excluded = 0

        for idx, chain in enumerate(pkg_data.get("behavior_chains", [])):
            # Ίδιος κανόνας με το build_rag_index.py: κώδικας νόμιμων βιβλιοθηκών που
            # εγκαταστήσαμε εμείς στο vendor/ δεν αξιολογείται ως κώδικας του πακέτου.
            if is_pure_vendor_chain(chain):
                self.last_vendor_excluded += 1
                continue
            text = flatten_chain_to_text(chain)  # κείμενο embedding (≤200 λέξεις), ίδιο με το index
            query_vec = self.model.encode([text], normalize_embeddings=True)[0]
            llm_text = chain_to_llm_text(chain)  # πλήρες κείμενο για το Τμήμα Α του LLM

            # Εξαρτήσεις του πακέτου ως συμπληρωματικό context (μικρό, για να μην
            # τρώει tokens). Με CODEQL_NO_VENDOR=1 το package_dependency_graph είναι
            # {όνομα: []}: τα πακέτα τρίτων που κάνει import ο κώδικας, μόνο κατ' όνομα,
            # χωρίς υπο-εξαρτήσεις και χωρίς να έχει αναλυθεί ο κώδικάς τους.
            dep_names = sorted(pkg_data.get("package_dependency_graph") or {})
            chain_extra = extra_context
            if dep_names:
                dep_summary = (
                    "\n[THIRD-PARTY PACKAGES IMPORTED BY THE CODE (names only; their code was not analyzed)]: "
                    + ", ".join(dep_names[:15])
                    + (f" ... ({len(dep_names)} total)" if len(dep_names) > 15 else "")
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

            m_matches = [] if NO_MALWARE else cosine_search(query_vec, self.malware_vectors, MALWARE_TOP_K)
            p_matches = [] if NO_POLICY else cosine_search(query_vec, self.policy_vectors, POLICY_TOP_K)

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
                "description": clean_description(self.malware_meta[i].get("description", "")),
            } for sim, i in m_matches]

            policy_hits = [{
                "source": self.policy_meta[i]["source"],
                "id": self.policy_meta[i]["id"],
                "name": self.policy_meta[i]["name"],
                "description": self.policy_meta[i].get("description", "")[:200],
                "similarity": round(sim, 4),
                "matched_by": "chain",
            } for sim, i in p_matches]

            # Στάδιο 2: ανάκτηση policies με βάση ΜΟΝΟ το API του chain.
            api = (chain.get("sensitive_api") or "").removesuffix("(...)")
            if not NO_POLICY and chain.get("category") != "unanchored" and api and not api.startswith("ControlFlowNode for"):
                if api not in api_cache:
                    api_cache[api] = self.model.encode([f"Use of {api}"], normalize_embeddings=True)[0]
                seen_ids = {h["id"] for h in policy_hits}
                added = 0
                for sim, i in cosine_search(api_cache[api], self.policy_vectors, POLICY_TOP_K + POLICY_API_TOP_K):
                    if self.policy_meta[i]["id"] in seen_ids:
                        continue
                    policy_hits.append({
                        "source": self.policy_meta[i]["source"],
                        "id": self.policy_meta[i]["id"],
                        "name": self.policy_meta[i]["name"],
                        "description": self.policy_meta[i].get("description", "")[:200],
                        "similarity": round(sim, 4),
                        "matched_by": f"api:{api}",
                    })
                    seen_ids.add(self.policy_meta[i]["id"])
                    added += 1
                    if added >= POLICY_API_TOP_K:
                        break

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
                + (f" [matched on API {h['matched_by'][4:]}]" if h.get("matched_by", "").startswith("api:") else "")
                for h in policy_hits
            ]) or "No relevant security policies matched."

            prompt = SSVC_COT_PROMPT.format(
                package_name=package_name,
                behavior_text=llm_text,
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
                "behavior_text": llm_text,
                "embedding_text": text,
                "prompt_for_llm": prompt,
                "prompt_version": PROMPT_VERSION,
                "rag_mode": RAG_MODE,
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
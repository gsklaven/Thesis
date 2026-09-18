"""
Κοινές βοηθητικές συναρτήσεις για το pipeline προετοιμασίας δεδομένων.
Εισάγεται από prepare_dataset_diverse.py, attack_type_tagger.py και
build_final_dataset.py ώστε οι ορισμοί να είναι πάντα συνεπείς.
"""

import hashlib
import re
import os 

# Αφαιρεί hex hashes (>= 16 χαρακτήρες) που αλλάζουν ανά report μέλος
# μιας καμπάνιας, ώστε το boilerplate κείμενο να παραμείνει ίδιο.
_HASH_PATTERN = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
# Αφαιρεί γραμμές "## Source: RepoName (abc123ef)" - μοναδικό ανά report
_SOURCE_LINE_PATTERN = re.compile(
    r"##\s*Source:\s*\w+\s*\([0-9a-f]+\)", re.IGNORECASE
)
# ΝΕΟ FIX: αφαιρεί "Malicious code in {package_name} (PyPI)" - η ΠΡΩΤΗ
# γραμμή σε reports νεότερης μορφής (π.χ. EsqueleSquad/checkmarx). Χωρίς
# αυτό, το ΜΟΝΑΔΙΚΟ όνομα πακέτου έμενε στο κείμενο πριν τον υπολογισμό
# του SHA-256, κάνοντας ΚΑΘΕ signature μοναδικό ακόμα κι όταν το
# υπόλοιπο, πραγματικό campaign κείμενο ήταν πανομοιότυπο - 5.310
# EsqueleSquad πακέτα εμφανίζονταν λανθασμένα σαν ~5.310 ξεχωριστές
# καμπάνιες αντί για 1.
_MALICIOUS_CODE_LINE_PATTERN = re.compile(
    r"malicious code in \S+\s*\([^)]*\)", re.IGNORECASE
)
# Ορίζουμε κεντρικά όλους τους πιθανούς δίσκους
CANDIDATE_SOURCES_DIRS = [
    "/media/sklavenitis/C09F-7FCB",
    "/media/sklavenitis/123 GB Volume",
    "/media/sklavenitis/Giorgos",
    os.path.join(os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "dataset", "sources"),
]

def campaign_signature(description):
    """
    Επιστρέφει την κανονικοποιημένη υπογραφή καμπάνιας για ένα OSV description.

    Αφαιρεί per-report hashes και IDs ώστε όλα τα μέλη της ίδιας καμπάνιας
    (που μοιράζονται boilerplate κείμενο αλλά διαφέρουν στο hash) να πέφτουν
    στο ίδιο signature bucket.

    H3 FIX: Χρήση SHA-256 hash αντί truncation στους 200 χαρακτήρες.
    Η truncation μπορούσε να δημιουργήσει false collisions αν δύο διαφορετικές
    καμπάνιες μοιράζονταν τα πρώτα 200 chars αλλά διέφεραν στη συνέχεια.

    Επιστρέφει None αν το description είναι κενό ή πολύ σύντομο για να είναι
    αξιόπιστο campaign ID (< 20 χαρακτήρες μετά τον καθαρισμό).
    """
    if not description:
        return None
    text = _SOURCE_LINE_PATTERN.sub("", description)
    text = _MALICIOUS_CODE_LINE_PATTERN.sub("", text)
    text = _HASH_PATTERN.sub("", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    if len(text) <= 20:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def flatten_chain_to_text(chain, attack_type_tags=None):
    """
    Μετατρέπει ένα behavior_chain dict σε περιγραφικό κείμενο για embedding.

    ΚΡΙΣΙΜΟ: αυτή είναι η ΜΟΝΑΔΙΚΗ υλοποίηση - χρησιμοποιείται ΚΑΙ από το
    build_rag_index.py (όταν χτίζεται το index) ΚΑΙ από το query_rag.py
    (όταν γίνεται αναζήτηση). Αν οι δύο πλευρές χρησιμοποιούν διαφορετικό
    επίπεδο λεπτομέρειας κειμένου, το cosine similarity είναι λιγότερο
    ακριβές - συγκρίνεις "λεπτομερές" vector με "αραιό" vector.

    Αποφεύγουμε επίτηδες package name/file paths/line numbers - θέλουμε το
    embedding να συλλάβει τη ΣΥΜΠΕΡΙΦΟΡΑ, όχι μοναδικά αναγνωριστικά.
    """
    parts = []

    category = chain.get("category", "unknown")
    parts.append(f"Malware behavior category: {category}.")

    api = chain.get("sensitive_api", "")
    if api:
        parts.append(f"Sensitive API involved: {api}.")

    boundary = chain.get("flow_boundary", "Unknown")
    parts.append(f"Flow boundary: {boundary}.")

    for flow in chain.get("confirmed_source_flows", []):
        src_node = flow.get("source", {}).get("node", "")
        sink_node = flow.get("sink_node", "")
        parts.append(f"Data flows from a {src_node} source into a {sink_node} sink.")

    for cond in chain.get("control_conditions", []):
        parts.append(
            f"Execution is gated by a condition ({cond.get('condition','')}) "
            f"which must evaluate to {cond.get('must_be','')}."
        )

    slice_texts = [n.get("text", "") for n in chain.get("data_flow_slice", [])]
    if slice_texts:
        parts.append("Contributing data-flow nodes: " + "; ".join(slice_texts[:10]) + ".")

    edges = chain.get("relevant_call_graph", [])
    external_callees = sorted({e["callee"] for e in edges if e.get("edge_type") == "external"})
    if external_callees:
        parts.append("Calls external/library functions: " + ", ".join(external_callees[:10]) + ".")

    if attack_type_tags:
        parts.append("Known attack-type classification: " + ", ".join(attack_type_tags) + ".")

    # R2: Token truncation guard — το all-MiniLM-L6-v2 δέχεται max 256
    # word pieces. Κείμενο πάνω από ~200 λέξεις αγνοείται σιωπηλά.
    final_text = " ".join(parts)
    words = final_text.split()
    if len(words) > 200:
        final_text = " ".join(words[:200])
    return final_text

def find_target_dir(target_name):
    """
    Ψάχνει για έναν συγκεκριμένο υποφάκελο (π.χ. 'pypi_malregistry')
    σε όλους τους πιθανούς δίσκους. Επιστρέφει το πλήρες path αν βρεθεί,
    αλλιώς επιστρέφει None.
    """
    for base in CANDIDATE_SOURCES_DIRS:
        candidate_path = os.path.join(base, target_name)
        if os.path.exists(candidate_path):
            return candidate_path
            
    print(f"  [!] Προειδοποίηση: Ο φάκελος '{target_name}' δεν βρέθηκε σε κανέναν δίσκο.")
    return None
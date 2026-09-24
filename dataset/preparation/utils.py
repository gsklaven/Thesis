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
_ROOT_DIR = os.environ.get("THESIS_BASE_DIR",
                           os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))


def load_env_file(path=os.path.join(_ROOT_DIR, ".env")):
    """
    Φορτώνει το .env της ρίζας του έργου (KEY=VALUE, γραμμές # σχόλια) στο os.environ: θέση πηγών,
    κλειδιά API κ.λπ. (υπόδειγμα: .env.example). ΔΕΝ αντικαθιστά μεταβλητές που έχουν ήδη οριστεί
    στο τερματικό (αυτές υπερισχύουν) ούτε γράφει κενές τιμές. Χωρίς εξωτερική βιβλιοθήκη.
    Καλείται αυτόματα όταν φορτώνεται το utils (το εισάγουν όλα τα scripts, και οι evaluators
    μέσω του query_rag), οπότε το .env ισχύει είτε τρέχει το run_pipeline.sh είτε ένα script μόνο του.
    """
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = (x.strip() for x in line.split("=", 1))
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()   # σχόλιο στο τέλος της γραμμής
            if key and value and key not in os.environ:
                os.environ[key] = value


load_env_file()

# Θέση των ακατέργαστων πηγών (κλώνοι pypi_malregistry, MalwareBench pypi, OSV malicious-packages,
# Datadog, maloss): THESIS_SOURCES_DIR (ή THESIS_USB_MOUNT), προεπιλογή ο εξωτερικός δίσκος.
SOURCES_DIR = (os.environ.get("THESIS_SOURCES_DIR") or os.environ.get("THESIS_USB_MOUNT")
               or "/Volumes/GIORGOS_128")
# Όλοι οι πιθανοί δίσκοι (οι /media/... είναι του αρχικού Linux μηχανήματος)
CANDIDATE_SOURCES_DIRS = [
    SOURCES_DIR,
    "/media/sklavenitis/C09F-7FCB",
    "/media/sklavenitis/123 GB Volume",
    "/media/sklavenitis/Giorgos",
    os.path.join(os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "dataset", "sources"),
]

# Οι φάκελοι-ρίζες των πηγών μέσα στο SOURCES_DIR (κλώνοι/αποσυμπιέσεις).
SOURCE_ROOTS = ("pypi_malregistry", "pypi", "malicious-software-packages-dataset", "malware_samples",
                "malware_samples_datadog", "maloss-samples", "malicious-packages", "npm")


def resolve_source_path(path):
    """
    Διαδρομή πηγαίου κώδικα όπως αποθηκεύτηκε στο malware_dataset*.json (από ΟΠΟΙΟΔΗΠΟΤΕ
    μηχάνημα, π.χ. /media/sklavenitis/C09F-7FCB/pypi_malregistry/x/1.0) -> η αντίστοιχη
    διαδρομή κάτω από το SOURCES_DIR αυτού του μηχανήματος. Ο χρήστης δίνει ΜΟΝΟ τη θέση
    των πηγών (THESIS_SOURCES_DIR)· όλα τα scripts λύνουν τις διαδρομές μέσω αυτής.
    """
    if not path or os.path.exists(path):
        return path
    parts = path.replace("\\", "/").split("/")
    for i, part in enumerate(parts):
        if part in SOURCE_ROOTS:
            return os.path.join(SOURCES_DIR, *parts[i:])
    return path


def source_name(path):
    """Η πηγή (φάκελος-ρίζα) ενός δείγματος, π.χ. 'pypi_malregistry' - για στατιστικά ανά πηγή."""
    parts = (path or "").replace("\\", "/").split("/")
    return next((p for p in parts if p in SOURCE_ROOTS), "unknown")


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


def is_pure_vendor_chain(chain):
    """
    True αν το chain ανήκει ΕΞ ΟΛΟΚΛΗΡΟΥ σε vendored βιβλιοθήκη: το anchor του είναι μέσα
    στο vendor/ (κώδικας που εγκαταστήσαμε ΕΜΕΙΣ από το PyPI με pip, όχι κώδικας του
    πακέτου) ΚΑΙ καμία επιβεβαιωμένη ροή δεν ξεκινά από κώδικα του πακέτου. Τέτοια chains
    είναι ίδια για κάθε πακέτο που κάνει import τη βιβλιοθήκη, άρα δεν λένε τίποτα για την
    πρόθεσή του. Chains με anchor στο vendor/ αλλά ροή από την εφαρμογή (App-to-Vendor)
    ΚΡΑΤΙΟΥΝΤΑΙ: είναι τα δεδομένα του πακέτου που φτάνουν σε sink μιας βιβλιοθήκης.
    Χρησιμοποιείται ΚΑΙ στο build_rag_index.py ΚΑΙ στο query_rag.py (συμμετρία).
    """
    norm = lambda p: (p or "").replace("\\", "/")
    if not norm(chain.get("location")).startswith("vendor/"):
        return False
    return all(norm(f.get("source", {}).get("file")).startswith("vendor/")
               for f in chain.get("confirmed_source_flows", []))


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
    # R2: Token truncation guard — το all-MiniLM-L6-v2 δέχεται max 256
    # word pieces. Κείμενο πάνω από ~200 λέξεις αγνοείται σιωπηλά.
    return _serialize_chain(chain, attack_type_tags, max_words=200, max_slice=10, max_callees=10)


def chain_to_llm_text(chain):
    """
    Το κείμενο του Τμήματος Α στο LLM prompt. ΔΙΑΦΟΡΕΤΙΚΟ από το κείμενο του embedding:
    το όριο των 200 λέξεων υπάρχει μόνο για το μοντέλο ενσωμάτωσης (~256 tokens) - το
    LLM δεν έχει τέτοιο περιορισμό, οπότε βλέπει ΟΛΟΥΣ τους κόμβους, ροές, συνθήκες και
    κλήσεις (χωρίς διπλότυπα), με μόνο ένα συνολικό όριο ασφαλείας (LLM_MAX_WORDS). Ό,τι
    παραλείπεται σημειώνεται ρητά. Πριν (2026-09-23) το LLM έβλεπε το κείμενο του
    embedding: ~24% των chains κόβονταν στις 200 λέξεις.
    """
    return _serialize_chain(chain, None, max_words=LLM_MAX_WORDS, max_slice=None, max_callees=None,
                            dedup=True, mark_omitted=True)


# Μόνο δίχτυ ασφαλείας για ακραία chains (π.χ. 1.230 κόμβοι ροής) - όλοι οι κόμβοι, ροές,
# συνθήκες και κλήσεις δίνονται στο LLM (χωρίς διπλότυπα) μέχρι αυτό το συνολικό όριο.
LLM_MAX_WORDS = 4000
_NOISE_CALLEES = {"<complex_expr>"}  # placeholder του call_graph_py.ql για μη-ονομαστικές κλήσεις

# Αρχικά τμήματα path που προέρχονται από τον τρόπο αποθήκευσης/αποσυμπίεσης και όχι από
# το ίδιο το πακέτο: φάκελοι έκδοσης (2.13.36/), ρίζα sdist (name-1.2.3/), hashes,
# φάκελοι αποσυμπίεσης (.x). Διαφέρουν συστηματικά ανάμεσα σε malware και benign, οπότε
# αφαιρούνται για να μη λειτουργήσουν ως shortcut.
_ARTIFACT_DIR = re.compile(r"(\d+(\.\d+)+.*|.+-\d+(\.\d+)*[\w.+-]*|[0-9a-f]{16,}|.+\.x"
                           r"|tar-gz|tar\.gz|zip|whl|.+-whl|.+-tar-gz|tmp\w*)")


def display_path(location):
    """'2.13.36/pkg-2.13.36/pkg/setup.py:12' -> 'pkg/setup.py' (θέση ΜΕΣΑ στο πακέτο)."""
    parts = (location or "").rsplit(":", 1)[0].replace("\\", "/").split("/")
    while len(parts) > 1 and _ARTIFACT_DIR.fullmatch(parts[0]):
        parts = parts[1:]
    return "/".join(parts)


def _serialize_chain(chain, attack_type_tags, max_words, max_slice, max_callees,
                     max_flows=None, max_conditions=None, dedup=False, mark_omitted=False):
    def capped(items, cap, what):
        if mark_omitted:  # κείμενο LLM: κενή συμβολοσειρά/κόμβος -> ρητό "" αντί για κενό
            items = [x if x.strip() else '""' for x in items]
        if dedup:
            items = list(dict.fromkeys(items))
        if cap is None or len(items) <= cap:
            return items
        return items[:cap] + ([f"(+{len(items) - cap} more {what})"] if mark_omitted else [])

    parts = []

    category = chain.get("category", "unknown")
    parts.append(f"Malware behavior category: {category}.")

    api = chain.get("sensitive_api", "")
    if api:
        parts.append(f"Sensitive API involved: {api}.")

    # Μόνο στο κείμενο του LLM (όχι στο embedding): σε ποιο αρχείο είναι η κλήση - π.χ.
    # setup.py (τρέχει στην εγκατάσταση) ή __init__.py (τρέχει στο import).
    if mark_omitted and chain.get("location"):
        parts.append(f"Location: {display_path(chain['location'])}.")

    boundary = chain.get("flow_boundary", "Unknown")
    parts.append(f"Flow boundary: {boundary}.")

    q = (lambda x: x if (x or "").strip() else '""') if mark_omitted else (lambda x: x)
    flows = [f"Data flows from a {q(f.get('source', {}).get('node', ''))} source into a {q(f.get('sink_node', ''))} sink."
             for f in chain.get("confirmed_source_flows", [])]
    parts.extend(capped(flows, max_flows, "data flows"))

    conds = [f"Execution is gated by a condition ({c.get('condition', '')}) which must evaluate to {c.get('must_be', '')}."
             for c in chain.get("control_conditions", [])]
    parts.extend(capped(conds, max_conditions, "gating conditions"))

    slice_texts = [n.get("text", "") for n in chain.get("data_flow_slice", [])]
    if slice_texts:
        parts.append("Contributing data-flow nodes: " + "; ".join(capped(slice_texts, max_slice, "nodes")) + ".")

    edges = chain.get("relevant_call_graph", [])
    external_callees = sorted({e["callee"] for e in edges if e.get("edge_type") == "external"} - _NOISE_CALLEES)
    if external_callees:
        parts.append("Calls external/library functions: " + ", ".join(capped(external_callees, max_callees, "functions")) + ".")

    if attack_type_tags:
        parts.append("Known attack-type classification: " + ", ".join(attack_type_tags) + ".")

    final_text = " ".join(parts)
    words = final_text.split()
    if len(words) > max_words:
        final_text = " ".join(words[:max_words])
        if mark_omitted:
            final_text += f" [... truncated: {len(words) - max_words} more words]"
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
"""
Χτίζει το RAG index ΜΟΝΟ από το rag_train/ (ΠΟΤΕ από το rag_test/).

I8 FIX (πλήρες, και στις 2 πλευρές): το query_rag.py δεν περνάει
attack_type_tags στο flatten_chain_to_text() γιατί είναι άγνωστα για ένα νέο
πακέτο - για ΠΡΑΓΜΑΤΙΚΗ συμμετρία, ούτε εδώ (index-building) πρέπει να τα
περνάμε στο ΙΔΙΟ ΚΕΙΜΕΝΟ ΤΟΥ EMBEDDING. Τα tags παραμένουν διαθέσιμα στο
metadata.json για εμφάνιση/φιλτράρισμα - απλά δεν μπαίνουν πια ΜΕΣΑ στο
vector, ώστε train και query embeddings να παράγονται από επακριβώς το ίδιο
είδος κειμένου. ΙΔΙΟ σκεπτικό ισχύει για το description παρακάτω: μπαίνει
ΜΟΝΟ στο metadata (για εμφάνιση στο LLM prompt ως πλαίσιο για τους
ανακτημένους ΓΕΙΤΟΝΕΣ), ΠΟΤΕ μέσα στο ίδιο το embedding text - ένα νέο,
υπό εξέταση πακέτο δεν έχει description (δεν είναι ακόμα γνωστό αν είναι
malware), οπότε η συμμετρία train/query παραμένει ανέπαφη.
"""

import json
import os

import numpy as np
from sentence_transformers import SentenceTransformer
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import flatten_chain_to_text, is_pure_vendor_chain  # noqa: E402

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
TRAIN_DIR = os.path.join(BASE_DIR, "rag_train")
ATTACK_TAGS_JSON = os.path.join(BASE_DIR, "attack_type_tags.json")

# ΝΕΟ: πηγή για το OSV description ανά πακέτο (ίδιο fallback pattern με
# αλλού στο project - deduped αν υπάρχει, αλλιώς matched).
_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

INDEX_DIR = os.path.join(BASE_DIR, "indexes", "rag_index")
VECTORS_FILE = os.path.join(INDEX_DIR, "vectors.npy")
METADATA_FILE = os.path.join(INDEX_DIR, "metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"


def load_descriptions():
    """
    Χτίζει lookup package_name -> description από το πηγαίο dataset json.
    Defensive: αν κάτι λείπει/είναι διαφορετικού σχήματος, απλά επιστρέφει
    άδειο string για εκείνο το πακέτο - ΠΟΤΕ δεν σταματάει το index build.
    """
    if not os.path.exists(DATASET_JSON):
        print(f"  [!] Δεν βρέθηκε {DATASET_JSON} - όλα τα descriptions θα είναι κενά.")
        return {}
    try:
        with open(DATASET_JSON, "r", encoding="utf-8") as f:
            dataset = json.load(f)
    except Exception as e:
        print(f"  [!] Αδυναμία φόρτωσης {DATASET_JSON}: {e}")
        return {}

    by_pkg = {}
    for item in dataset:
        name = item.get("package_name", "")
        desc = (item.get("description") or "").strip()
        if name and desc:
            by_pkg[name] = desc
    return by_pkg


def main():
    os.makedirs(INDEX_DIR, exist_ok=True)

    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    descriptions = load_descriptions()
    print(f"[*] {len(descriptions)} πακέτα με πραγματικό OSV description βρέθηκαν "
          f"(από {os.path.basename(DATASET_JSON)}).")

    print(f"[*] Φόρτωση μοντέλου embeddings: {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    texts = []
    metadata = []
    vendor_skipped = 0

    for fname in sorted(os.listdir(TRAIN_DIR)):
        if not fname.endswith(".json"):
            continue
        pkg_name = fname[:-5]
        with open(os.path.join(TRAIN_DIR, fname), "r", encoding="utf-8") as f:
            data = json.load(f)

        tag_info = attack_tags.get(pkg_name, {})
        pkg_description = descriptions.get(pkg_name, "")

        for idx, chain in enumerate(data.get("behavior_chains", [])):
            # Κώδικας νόμιμων βιβλιοθηκών (vendor/) ΔΕΝ είναι παράδειγμα malware - βλ. utils.
            if is_pure_vendor_chain(chain):
                vendor_skipped += 1
                continue
            # I8 FIX: ΧΩΡΙΣ attack_type_tags στο embedding text - συμμετρικό
            # με το query_rag.py, που ΔΕΝ μπορεί να τα ξέρει για νέο πακέτο.
            text = flatten_chain_to_text(chain)
            texts.append(text)
            metadata.append({
                "package": pkg_name,
                "chain_index": idx,
                "category": chain.get("category"),
                "language": chain.get("language"),
                # Τα tags ΠΑΡΑΜΕΝΟΥΝ εδώ - χρήσιμα για εμφάνιση/φιλτράρισμα
                # αποτελεσμάτων, απλά όχι πια ΜΕΣΑ στο ίδιο το vector.
                "attack_type_tags": tag_info.get("attack_type_tags", []),
                "campaign_signature_preview": (tag_info.get("campaign_signature") or "")[:100],
                "location": chain.get("location"),
                # ΝΕΟ: πραγματικό OSV description (κενό string αν δεν
                # υπάρχει - bulk-source πακέτα θα παραμείνουν κενά, όπως
                # πριν, απλά τώρα τα OSV-sourced ΘΑ έχουν πραγματικό κείμενο).
                "description": pkg_description,
                "text": text,
            })

    print(f"[*] {len(texts)} behavior-chain κομμάτια (chunks) προς embedding "
          f"({vendor_skipped} καθαρά vendor chains εξαιρέθηκαν).")

    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    np.save(VECTORS_FILE, embeddings)

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Index χτίστηκε: {len(texts)} vectors -> {VECTORS_FILE}")
    print(f"[+] Metadata -> {METADATA_FILE}")


if __name__ == "__main__":
    main()
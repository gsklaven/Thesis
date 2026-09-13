"""
Χτίζει το RAG index ΜΟΝΟ από το rag_train/ (ΠΟΤΕ από το rag_test/).

I8 FIX (πλήρες, και στις 2 πλευρές): το query_rag.py δεν περνάει
attack_type_tags στο flatten_chain_to_text() γιατί είναι άγνωστα για ένα νέο
πακέτο - για ΠΡΑΓΜΑΤΙΚΗ συμμετρία, ούτε εδώ (index-building) πρέπει να τα
περνάμε στο ΙΔΙΟ ΚΕΙΜΕΝΟ ΤΟΥ EMBEDDING. Τα tags παραμένουν διαθέσιμα στο
metadata.json για εμφάνιση/φιλτράρισμα - απλά δεν μπαίνουν πια ΜΕΣΑ στο
vector, ώστε train και query embeddings να παράγονται από επακριβώς το ίδιο
είδος κειμένου.
"""

import json
import os

import numpy as np
from sentence_transformers import SentenceTransformer
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import flatten_chain_to_text  # noqa: E402

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
TRAIN_DIR = os.path.join(BASE_DIR, "rag_train")
ATTACK_TAGS_JSON = os.path.join(BASE_DIR, "attack_type_tags.json")

INDEX_DIR = os.path.join(BASE_DIR, "indexes", "rag_index")
VECTORS_FILE = os.path.join(INDEX_DIR, "vectors.npy")
METADATA_FILE = os.path.join(INDEX_DIR, "metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"


def main():
    os.makedirs(INDEX_DIR, exist_ok=True)

    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    print(f"[*] Φόρτωση μοντέλου embeddings: {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    texts = []
    metadata = []

    for fname in sorted(os.listdir(TRAIN_DIR)):
        if not fname.endswith(".json"):
            continue
        pkg_name = fname[:-5]
        with open(os.path.join(TRAIN_DIR, fname), "r", encoding="utf-8") as f:
            data = json.load(f)

        tag_info = attack_tags.get(pkg_name, {})

        for idx, chain in enumerate(data.get("behavior_chains", [])):
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
                "text": text,
            })

    print(f"[*] {len(texts)} behavior-chain κομμάτια (chunks) προς embedding.")

    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    np.save(VECTORS_FILE, embeddings)

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Index χτίστηκε: {len(texts)} vectors -> {VECTORS_FILE}")
    print(f"[+] Metadata -> {METADATA_FILE}")


if __name__ == "__main__":
    main()

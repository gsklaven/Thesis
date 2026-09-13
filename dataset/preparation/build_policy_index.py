import json
import os
import numpy as np
from sentence_transformers import SentenceTransformer

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/home/sklavenitis/thesis")
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
POLICY_JSON = os.path.join(BASE_DIR, "policy_rules.json")

# Πατη εξόδου συγχρονισμένη με το query_rag.py (dataset/indexes/policy_index/)
POLICY_INDEX_DIR = os.path.join(BASE_DIR, "indexes", "policy_index")
VECTORS_FILE = os.path.join(POLICY_INDEX_DIR, "policy_vectors.npy")
METADATA_FILE = os.path.join(POLICY_INDEX_DIR, "policy_metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"


def build_policy_index():
    if not os.path.exists(POLICY_JSON):
        raise FileNotFoundError(
            f"Δεν βρέθηκε {POLICY_JSON} - τρέξε πρώτα build_policy_dataset.py"
        )

    if not os.path.exists(POLICY_INDEX_DIR):
        os.makedirs(POLICY_INDEX_DIR)

    print(f"[*] Διάβασμα των κανόνων από το {POLICY_JSON}...")
    with open(POLICY_JSON, "r", encoding="utf-8") as f:
        policies = json.load(f)

    print(f"[*] Φόρτωση του μοντέλου {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    texts = []
    metadata = []

    for p in policies:
        texts.append(p["text_for_embedding"])
        metadata.append({
            "source": p.get("source"),
            "id": p.get("id"),
            "name": p.get("name"),
            "description": p.get("description"),
            "tactics": p.get("tactics", []),
        })

    print(f"[*] Δημιουργία embeddings για {len(texts)} κανόνες/πολιτικές...")
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)

    print("[*] Αποθήκευση του Policy Index (Vectors & Metadata)...")
    np.save(VECTORS_FILE, embeddings)
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Επιτυχία! Το Policy Index δημιουργήθηκε στο: {POLICY_INDEX_DIR}")


if __name__ == "__main__":
    build_policy_index()

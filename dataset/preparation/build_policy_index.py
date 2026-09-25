"""
Build the vector index of the security knowledge base (policy store of the Hybrid RAG).

Reads dataset/policy_rules.json (written by build_policy_dataset.py), embeds the text of every
entry with all-MiniLM-L6-v2 (normalised vectors, so a dot product is the cosine similarity) and
writes, in the folder that query_rag.py reads (dataset/indexes/policy_index/):
  policy_vectors.npy     one row per entry
  policy_metadata.json   source, id, name, description and tactics of each entry, same order
"""
import json
import os
import numpy as np
from sentence_transformers import SentenceTransformer

_THESIS_ROOT = os.environ.get(
    "THESIS_BASE_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)
BASE_DIR = os.path.join(_THESIS_ROOT, "dataset")
POLICY_JSON = os.path.join(BASE_DIR, "policy_rules.json")

# Output paths, kept in sync with query_rag.py (dataset/indexes/policy_index/)
POLICY_INDEX_DIR = os.path.join(BASE_DIR, "indexes", "policy_index")
VECTORS_FILE = os.path.join(POLICY_INDEX_DIR, "policy_vectors.npy")
METADATA_FILE = os.path.join(POLICY_INDEX_DIR, "policy_metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"


def build_policy_index():
    """Embed every knowledge-base entry and save vectors + metadata (row i of both = entry i)."""
    if not os.path.exists(POLICY_JSON):
        raise FileNotFoundError(
            f"{POLICY_JSON} not found - run build_policy_dataset.py first"
        )

    if not os.path.exists(POLICY_INDEX_DIR):
        os.makedirs(POLICY_INDEX_DIR)

    print(f"[*] Reading the rules from {POLICY_JSON}...")
    with open(POLICY_JSON, "r", encoding="utf-8") as f:
        policies = json.load(f)

    print(f"[*] Loading model {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    texts = []
    metadata = []

    for p in policies:
        # text_for_embedding is prepared by build_policy_dataset.py ("<name>. <description>")
        texts.append(p["text_for_embedding"])
        metadata.append({
            "source": p.get("source"),
            "id": p.get("id"),
            "name": p.get("name"),
            "description": p.get("description"),
            "tactics": p.get("tactics", []),
        })

    print(f"[*] Creating embeddings for {len(texts)} rules/policies...")
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)

    print("[*] Saving the policy index (vectors & metadata)...")
    np.save(VECTORS_FILE, embeddings)
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)

    print(f"\n[✓] Done! The policy index was created in: {POLICY_INDEX_DIR}")


if __name__ == "__main__":
    build_policy_index()

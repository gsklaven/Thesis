"""
Build the malware-examples index of the Hybrid RAG, ONLY from rag_train/ (NEVER from rag_test/).

For every Behavior Chain of every training package (except pure-vendor chains) the compact text
(utils.flatten_chain_to_text) is embedded with all-MiniLM-L6-v2, and one metadata row is stored
next to each vector: package, category, attack-type tags, OSV description, location, text.

Index/query symmetry: query_rag.py cannot know the attack-type tags or the description of a new
package, so they are NOT part of the embedded text here either - train and query vectors are made
from exactly the same kind of text. Tags and description stay in the metadata, where they are shown
to the LLM as context about the retrieved NEIGHBOURS (Section B of the prompt).

Output: dataset/indexes/rag_index/vectors.npy + metadata.json (row i of both = the same chain).
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

# Source of the OSV description of each package: the de-duplicated dataset if it exists,
# otherwise the matched one (same fallback as elsewhere in the project).
_DEDUPED_JSON = os.path.join(BASE_DIR, "malware_dataset_deduped.json")
_MATCHED_JSON = os.path.join(BASE_DIR, "malware_dataset_matched.json")
DATASET_JSON = _DEDUPED_JSON if os.path.exists(_DEDUPED_JSON) else _MATCHED_JSON

INDEX_DIR = os.path.join(BASE_DIR, "indexes", "rag_index")
VECTORS_FILE = os.path.join(INDEX_DIR, "vectors.npy")
METADATA_FILE = os.path.join(INDEX_DIR, "metadata.json")

MODEL_NAME = "all-MiniLM-L6-v2"


def load_descriptions():
    """
    Lookup package_name -> OSV description from the dataset JSON. Defensive: if the file is missing
    or has another shape, packages simply get an empty description - the index build never stops.
    """
    if not os.path.exists(DATASET_JSON):
        print(f"  [!] {DATASET_JSON} not found - all descriptions will be empty.")
        return {}
    try:
        with open(DATASET_JSON, "r", encoding="utf-8") as f:
            dataset = json.load(f)
    except Exception as e:
        print(f"  [!] Could not load {DATASET_JSON}: {e}")
        return {}

    by_pkg = {}
    for item in dataset:
        name = item.get("package_name", "")
        desc = (item.get("description") or "").strip()
        if name and desc:
            by_pkg[name] = desc
    return by_pkg


def main():
    """Embed every training chain and write vectors.npy + metadata.json."""
    os.makedirs(INDEX_DIR, exist_ok=True)

    with open(ATTACK_TAGS_JSON, "r", encoding="utf-8") as f:
        attack_tags = json.load(f)

    descriptions = load_descriptions()
    print(f"[*] {len(descriptions)} packages with a real OSV description found "
          f"(from {os.path.basename(DATASET_JSON)}).")

    print(f"[*] Loading embedding model: {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    texts = []
    metadata = []
    vendor_skipped = 0

    # sorted file order -> deterministic row order of the index
    for fname in sorted(os.listdir(TRAIN_DIR)):
        if not fname.endswith(".json"):
            continue
        pkg_name = fname[:-5]
        with open(os.path.join(TRAIN_DIR, fname), "r", encoding="utf-8") as f:
            data = json.load(f)

        tag_info = attack_tags.get(pkg_name, {})
        pkg_description = descriptions.get(pkg_name, "")

        for idx, chain in enumerate(data.get("behavior_chains", [])):
            # code of legitimate libraries (vendor/) is NOT a malware example - see utils
            if is_pure_vendor_chain(chain):
                vendor_skipped += 1
                continue
            # no attack_type_tags in the embedded text: symmetric with query_rag.py,
            # which cannot know them for a new package
            text = flatten_chain_to_text(chain)
            texts.append(text)
            metadata.append({
                "package": pkg_name,
                "chain_index": idx,
                "category": chain.get("category"),
                "language": chain.get("language"),
                # tags are kept here, for display in the prompt - just not inside the vector
                "attack_type_tags": tag_info.get("attack_type_tags", []),
                "campaign_signature_preview": (tag_info.get("campaign_signature") or "")[:100],
                "location": chain.get("location"),
                # real OSV description (empty string when the package has none)
                "description": pkg_description,
                "text": text,
            })

    print(f"[*] {len(texts)} behavior-chain chunks to embed "
          f"({vendor_skipped} pure vendor chains excluded).")

    # normalised vectors: a dot product is the cosine similarity (used by query_rag.py)
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    np.save(VECTORS_FILE, embeddings)

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Index built: {len(texts)} vectors -> {VECTORS_FILE}")
    print(f"[+] Metadata -> {METADATA_FILE}")


if __name__ == "__main__":
    main()

"""
chain_fingerprint.py — Stable fingerprinting for behavior chains.

Χρησιμοποιείται για να παρακολουθούμε ποια chains έχουν ήδη αναλυθεί,
ώστε να μην ξαναστέλνουμε το ίδιο chain στο LLM σε επόμενα commits.

Fingerprint ορισμός:
  - Εξαρτάται από: category, sensitive_api, flow_boundary,
    και τα normalized texts των data_flow_slice nodes
  - ΔΕΝ εξαρτάται από: line numbers, whitespace, variable names
  - Έτσι: ένα αρχείο που αλλάζει μόνο variable names ή μετακινείται
    σε άλλη γραμμή δίνει ΤΟ ΙΔΙΟ fingerprint → skip (δεν ξαναναλύεται)
"""
import hashlib
import re


def _normalize(text: str) -> str:
    """Strip whitespace και κάνε lowercase για fingerprint stability."""
    if not text:
        return ""
    # Collapse all whitespace to single space
    text = re.sub(r"\s+", " ", text.strip())
    return text.lower()


def chain_fingerprint(chain: dict) -> str:
    """
    Επιστρέφει ένα 16-χαρακτηρο hex fingerprint για ένα behavior chain.

    Stable across: line number changes, whitespace changes, variable renames.
    NOT stable across: changes to API calls, data flow nodes, category.
    """
    parts = [
        chain.get("category", ""),
        chain.get("sensitive_api", ""),
        chain.get("flow_boundary", ""),
    ]

    # Include data flow nodes (normalized text)
    for node in chain.get("data_flow_slice", []):
        parts.append(_normalize(node.get("text", "")))

    # Include control conditions
    for cond in chain.get("control_conditions", []):
        parts.append(_normalize(cond.get("condition", "") if isinstance(cond, dict)
                                else str(cond)))

    # Include confirmed source flows
    for src in chain.get("confirmed_source_flows", []):
        if isinstance(src, dict):
            parts.append(_normalize(src.get("text", "") or src.get("source", "")))

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def chain_touched_files(chain: dict) -> set:
    """
    Επιστρέφει το σύνολο των αρχείων που αφορά ένα chain.
    Χρησιμοποιείται για να φιλτράρουμε ποια chains σχετίζονται
    με τα changed files ενός commit.
    """
    files = set()

    # Primary location
    loc = chain.get("location", "")
    if loc and ":" in loc:
        files.add(loc.split(":")[0].strip())
    elif loc:
        files.add(loc.strip())

    # Data flow slice files
    for node in chain.get("data_flow_slice", []):
        f = node.get("file", "")
        if f:
            files.add(f.strip())

    # Control condition files
    for cond in chain.get("control_conditions", []):
        if isinstance(cond, dict):
            f = cond.get("file", "")
            if f:
                files.add(f.strip())

    # Confirmed source flows
    for src in chain.get("confirmed_source_flows", []):
        if isinstance(src, dict):
            f = src.get("file", "")
            if f:
                files.add(f.strip())

    # Remove empty strings
    files.discard("")
    return files


def fingerprint_all(chains: list) -> dict:
    """
    Επιστρέφει dict: fingerprint → chain_index
    για γρήγορη αναζήτηση αν ένα chain έχει ήδη αναλυθεί.
    """
    return {chain_fingerprint(c): i for i, c in enumerate(chains)}

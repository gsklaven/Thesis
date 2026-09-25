"""
chain_fingerprint.py - Stable fingerprinting for behavior chains.

Used by the incremental scanner to track which chains have already been analysed, so the same chain is
not sent to the LLM again on later commits.

Fingerprint definition:
  - Depends on: category, sensitive_api, flow_boundary, and the normalised texts of the data-flow slice
    nodes, the gating conditions and the confirmed source flows
  - Does NOT depend on: line numbers or whitespace
  - So a file that only moves code to other lines gives THE SAME fingerprint -> skipped (not re-analysed)
"""
import hashlib
import re


def _normalize(text: str) -> str:
    """Collapse whitespace and lower-case the text, for fingerprint stability."""
    if not text:
        return ""
    # Collapse all whitespace to single space
    text = re.sub(r"\s+", " ", text.strip())
    return text.lower()


def chain_fingerprint(chain: dict) -> str:
    """
    Return a 16-character hex fingerprint of a behavior chain.

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
    Return the set of files a chain touches (anchor, slice nodes, conditions, source flows).
    Used to select the chains related to the files changed by a commit.
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
    Return a dict fingerprint -> chain_index, for a quick lookup of whether a chain has already
    been analysed.
    """
    return {chain_fingerprint(c): i for i, c in enumerate(chains)}

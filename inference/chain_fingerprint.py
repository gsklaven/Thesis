"""
chain_fingerprint.py - Stable fingerprinting for behavior chains.

Used by the incremental scanner to recognise chains that have already been evaluated, so the same
chain is not sent to the LLM again on later commits.

Fingerprint definition - a chain keeps its fingerprint as long as its BEHAVIOUR is unchanged:
  - Depends on: category, sensitive API, flow boundary, the file the call is in (not the line), and the
    normalised texts of the data-flow slice nodes, the gating conditions and the confirmed source ->
    sink flows (as sorted sets, so that their order does not matter).
  - Does NOT depend on: line numbers, whitespace, the order of nodes.
  So code that only moves to other lines or is re-formatted gives THE SAME fingerprint -> not
  re-evaluated; any change of the code that feeds the call (including renamed variables, which appear
  in the node texts) gives a new fingerprint -> evaluated again.
"""
import hashlib
import re


def _normalize(text) -> str:
    """Collapse whitespace and lower-case the text, for fingerprint stability (non-strings -> "")."""
    if not isinstance(text, str) or not text:
        return ""
    # collapse all whitespace to a single space
    text = re.sub(r"\s+", " ", text.strip())
    return text.lower()


def _file_of(location) -> str:
    """'pkg/mod.py:42' -> 'pkg/mod.py' (the file of a location, without the line number)."""
    return (location or "").rsplit(":", 1)[0].replace("\\", "/").strip()


def chain_fingerprint(chain: dict) -> str:
    """
    Return a 16-character hex fingerprint of a behavior chain (see the module docstring).

    Stable across: line-number changes, whitespace changes, re-ordering of nodes.
    NOT stable across: changes to API calls, data-flow nodes, conditions, flows, category or file.
    """
    parts = [
        chain.get("category", ""),
        chain.get("sensitive_api", ""),
        chain.get("flow_boundary", ""),
        _file_of(chain.get("location")),
    ]

    # data-flow slice nodes (normalised text, as a sorted set)
    parts.append("|".join(sorted({_normalize(n.get("text")) for n in chain.get("data_flow_slice", [])})))

    # gating conditions (condition + required value)
    conds = set()
    for cond in chain.get("control_conditions", []):
        if isinstance(cond, dict):
            conds.add(f"{_normalize(cond.get('condition'))}={_normalize(cond.get('must_be'))}")
        else:
            conds.add(_normalize(str(cond)))
    parts.append("|".join(sorted(conds)))

    # confirmed flows: source node text -> sink node text
    flows = set()
    for flow in chain.get("confirmed_source_flows", []):
        if isinstance(flow, dict):
            source = flow.get("source") if isinstance(flow.get("source"), dict) else {}
            flows.add(f"{_normalize(source.get('node'))}->{_normalize(flow.get('sink_node'))}")
    parts.append("|".join(sorted(flows)))

    raw = "#".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def chain_touched_files(chain: dict) -> set:
    """
    Return the set of files a chain touches (anchor, slice nodes, conditions, flow sources).
    Used to report which changed files of a commit a chain is related to.
    """
    files = {_file_of(chain.get("location"))}

    for node in chain.get("data_flow_slice", []):
        files.add(_file_of(node.get("file")))

    for cond in chain.get("control_conditions", []):
        if isinstance(cond, dict):
            files.add(_file_of(cond.get("file")))

    # the source of a flow is a dict {file, line, node}
    for flow in chain.get("confirmed_source_flows", []):
        if isinstance(flow, dict) and isinstance(flow.get("source"), dict):
            files.add(_file_of(flow["source"].get("file")))

    files.discard("")
    return files


def fingerprint_all(chains: list) -> dict:
    """
    Return a dict fingerprint -> index of the first chain with that fingerprint, for a quick lookup of
    whether a chain has already been evaluated.
    """
    out = {}
    for i, c in enumerate(chains):
        out.setdefault(chain_fingerprint(c), i)
    return out

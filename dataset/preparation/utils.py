"""
Shared helpers for the data-preparation pipeline and the inference stage.

Everything that must be defined identically in more than one place lives here, so that the
definitions can never drift apart:
  - loading of the project's .env file (sources location, API keys),
  - resolution of sample paths under THESIS_SOURCES_DIR, on any machine,
  - the campaign signature of an OSV report,
  - the "pure vendor chain" test used both when building the index and when querying it,
  - the two text serialisations of a Behavior Chain (compact one for embeddings, full one for the LLM),
  - the normalised in-package display path of a file.

Imported by almost every script of dataset/preparation/ and, through query_rag.py, by the evaluator.
"""

import hashlib
import re
import os

# Hex hashes (>= 16 characters) differ between the reports of the members of one campaign;
# removing them leaves the campaign's shared boilerplate text.
_HASH_PATTERN = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
# "## Source: RepoName (abc123ef)" lines are unique per report, so they are removed as well.
_SOURCE_LINE_PATTERN = re.compile(
    r"##\s*Source:\s*\w+\s*\([0-9a-f]+\)", re.IGNORECASE
)
# "Malicious code in {package_name} (PyPI)" is the first line of newer-style reports. It contains
# the (unique) package name, so without removing it every member of a campaign would get its own
# signature even when the rest of the report text is identical.
_MALICIOUS_CODE_LINE_PATTERN = re.compile(
    r"malicious code in \S+\s*\([^)]*\)", re.IGNORECASE
)
# Project root: THESIS_BASE_DIR if set, otherwise two levels above this file.
_ROOT_DIR = os.environ.get("THESIS_BASE_DIR",
                           os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))


def load_env_file(path=os.path.join(_ROOT_DIR, ".env")):
    """
    Load the project's .env file (KEY=VALUE lines, # comments) into os.environ: the location of the
    sources, API keys, the LLM provider, etc. (template: .env.example). No external library is used.

    Variables that are already set in the shell are NOT overwritten (the shell wins), and empty values
    are ignored. The function runs automatically when utils is imported (every script imports it, the
    evaluators through query_rag), so the .env applies both under run_pipeline.sh and when a script is
    run on its own.
    """
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # accept shell-style "export KEY=VALUE" lines too
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = (x.strip() for x in line.split("=", 1))
            # a quoted value is taken literally (it may contain " #")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()   # comment at the end of the line
            if key and value and key not in os.environ:
                os.environ[key] = value


load_env_file()

# Location of the raw sources (clones of pypi_malregistry, MalwareBench pypi, OSV malicious-packages,
# Datadog, maloss): THESIS_SOURCES_DIR (or the older THESIS_USB_MOUNT), default the external disk.
SOURCES_DIR = (os.environ.get("THESIS_SOURCES_DIR") or os.environ.get("THESIS_USB_MOUNT")
               or "/Volumes/GIORGOS_128")
# Every place the sources may be found, in order (the /media/... entries are the mount points of
# the original Linux machine, kept so that older datasets keep resolving).
CANDIDATE_SOURCES_DIRS = [
    SOURCES_DIR,
    "/media/sklavenitis/C09F-7FCB",
    "/media/sklavenitis/123 GB Volume",
    "/media/sklavenitis/Giorgos",
    os.path.join(os.environ.get("THESIS_BASE_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "dataset", "sources"),
]

# Top-level folders of the sources inside SOURCES_DIR (clones / extracted archives).
SOURCE_ROOTS = ("pypi_malregistry", "pypi", "malicious-software-packages-dataset", "malware_samples",
                "malware_samples_datadog", "maloss-samples", "malicious-packages", "npm")


def resolve_source_path(path):
    """
    Map a source-code path as stored in malware_dataset*.json (written on ANY machine, e.g.
    /media/sklavenitis/C09F-7FCB/pypi_malregistry/x/1.0) to the same sample under SOURCES_DIR of
    this machine. The user only provides the location of the sources (THESIS_SOURCES_DIR); every
    script resolves sample paths through this function.
    """
    if not path or os.path.exists(path):
        return path
    parts = path.replace("\\", "/").split("/")
    # keep everything from the first known source folder onwards, re-rooted under SOURCES_DIR
    for i, part in enumerate(parts):
        if part in SOURCE_ROOTS:
            return os.path.join(SOURCES_DIR, *parts[i:])
    return path


def source_name(path):
    """Source (top-level folder) of a sample, e.g. 'pypi_malregistry' - for per-source statistics."""
    parts = (path or "").replace("\\", "/").split("/")
    return next((p for p in parts if p in SOURCE_ROOTS), "unknown")


def campaign_signature(description):
    """
    Normalised campaign signature of an OSV report description.

    Per-report hashes, source lines and the "Malicious code in X" line are removed, so that all the
    members of one campaign (identical boilerplate text, different hashes/names) get the same
    signature. The signature is a SHA-256 of the whole normalised text (not a prefix), so two
    campaigns that only share their first sentences are not merged.

    Returns None when the description is empty or too short (<= 20 characters after cleaning) to
    identify a campaign reliably.
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
    True if the chain belongs ENTIRELY to vendored library code: its anchor is inside vendor/
    (third-party code installed from PyPI during analysis, not code of the package itself) AND no
    confirmed flow starts in the package's own code. Such chains are the same for every package that
    imports the library, so they say nothing about the package's intent.

    Chains anchored in vendor/ but fed by the application (App-to-Vendor) are KEPT: they are the
    package's own data reaching a library sink. Used by build_rag_index.py AND query_rag.py, so the
    index and the queries are filtered the same way.
    """
    norm = lambda p: (p or "").replace("\\", "/")
    if not norm(chain.get("location")).startswith("vendor/"):
        return False
    return all(norm(f.get("source", {}).get("file")).startswith("vendor/")
               for f in chain.get("confirmed_source_flows", []))


def flatten_chain_to_text(chain, attack_type_tags=None):
    """
    Compact Behavior Chain Representation: the text that is embedded for similarity search.

    This is the ONLY implementation, used both by build_rag_index.py (index side) and by
    query_rag.py (query side): if the two sides used different levels of detail, cosine similarity
    would compare a "detailed" vector with a "sparse" one.

    Package names, file paths and line numbers are deliberately left out: the embedding should
    capture the BEHAVIOUR, not identifiers of a particular package.
    """
    # all-MiniLM-L6-v2 accepts at most 256 word pieces and silently ignores the rest, so the text
    # is kept to ~200 words (first 10 slice nodes and 10 callees).
    return _serialize_chain(chain, attack_type_tags, max_words=200, max_slice=10, max_callees=10)


def chain_to_llm_text(chain):
    """
    Full Behavior Chain Representation: the text of Section A of the LLM prompt.

    Unlike the embedding text, it is not limited to 200 words (that limit exists only because of the
    embedding model): the LLM sees ALL nodes, flows, conditions and callees (without duplicates),
    with a single overall safety cap (LLM_MAX_WORDS). Anything that is left out is stated explicitly.
    """
    return _serialize_chain(chain, None, max_words=LLM_MAX_WORDS, max_slice=None, max_callees=None,
                            dedup=True, mark_omitted=True)


# Only a safety net for extreme chains (e.g. 1,230 data-flow nodes): all nodes, flows, conditions and
# callees are given to the LLM (without duplicates) up to this overall limit.
LLM_MAX_WORDS = 4000
_NOISE_CALLEES = {"<complex_expr>"}  # placeholder of call_graph_py.ql for calls without a simple name

# Leading path components that come from how samples were stored/extracted and not from the package
# itself: version folders (2.13.36/), sdist root (name-1.2.3/), hashes, extraction folders (.x).
# They differ systematically between malware and benign samples, so they are removed to prevent
# them from acting as a shortcut.
_ARTIFACT_DIR = re.compile(r"(\d+(\.\d+)+.*|.+-\d+(\.\d+)*[\w.+-]*|[0-9a-f]{16,}|.+\.x"
                           r"|tar-gz|tar\.gz|zip|whl|.+-whl|.+-tar-gz|tmp\w*)")


def display_path(location):
    """'2.13.36/pkg-2.13.36/pkg/setup.py:12' -> 'pkg/setup.py' (the position INSIDE the package)."""
    parts = (location or "").rsplit(":", 1)[0].replace("\\", "/").split("/")
    # drop storage/extraction folders from the front, but always keep the file name
    while len(parts) > 1 and _ARTIFACT_DIR.fullmatch(parts[0]):
        parts = parts[1:]
    return "/".join(parts)


def _serialize_chain(chain, attack_type_tags, max_words, max_slice, max_callees,
                     max_flows=None, max_conditions=None, dedup=False, mark_omitted=False):
    """
    Deterministic text serialisation of one Behavior Chain, shared by both representations.

    The parts appear in a fixed order: category, sensitive API, (LLM only) location, flow boundary,
    confirmed source->sink flows, gating conditions, data-flow slice nodes, external callees and
    (index only) attack-type tags. Each list can be capped; with mark_omitted=True (LLM text) the
    number of omitted items and any final truncation are stated in the text.
    """
    def capped(items, cap, what):
        """Optionally de-duplicate a list and cut it at `cap`, noting how many items were omitted."""
        if mark_omitted:  # LLM text: an empty string/node becomes an explicit "" instead of nothing
            items = [x if x.strip() else '""' for x in items]
        if dedup:
            items = list(dict.fromkeys(items))  # keeps the original order
        if cap is None or len(items) <= cap:
            return items
        return items[:cap] + ([f"(+{len(items) - cap} more {what})"] if mark_omitted else [])

    parts = []

    category = chain.get("category", "unknown")
    parts.append(f"Malware behavior category: {category}.")

    api = chain.get("sensitive_api", "")
    if api:
        parts.append(f"Sensitive API involved: {api}.")

    # LLM text only (not the embedding): the file of the call, e.g. setup.py (runs at install time)
    # or __init__.py (runs on import).
    if mark_omitted and chain.get("location"):
        parts.append(f"Location: {display_path(chain['location'])}.")

    boundary = chain.get("flow_boundary", "Unknown")
    parts.append(f"Flow boundary: {boundary}.")

    # q() makes empty node texts visible as "" in the LLM text (identity for the embedding text)
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

    # external (library) callees of the relevant call-graph part, sorted for determinism
    edges = chain.get("relevant_call_graph", [])
    external_callees = sorted({e["callee"] for e in edges if e.get("edge_type") == "external"} - _NOISE_CALLEES)
    if external_callees:
        parts.append("Calls external/library functions: " + ", ".join(capped(external_callees, max_callees, "functions")) + ".")

    if attack_type_tags:
        parts.append("Known attack-type classification: " + ", ".join(attack_type_tags) + ".")

    # final word limit (embedding model input size, or the LLM safety cap)
    final_text = " ".join(parts)
    words = final_text.split()
    if len(words) > max_words:
        final_text = " ".join(words[:max_words])
        if mark_omitted:
            final_text += f" [... truncated: {len(words) - max_words} more words]"
    return final_text

def find_target_dir(target_name):
    """
    Look for a source folder (e.g. 'pypi_malregistry') in every candidate sources location
    (CANDIDATE_SOURCES_DIRS). Returns its full path, or None if it is not found anywhere.
    """
    for base in CANDIDATE_SOURCES_DIRS:
        candidate_path = os.path.join(base, target_name)
        if os.path.exists(candidate_path):
            return candidate_path

    print(f"  [!] Warning: folder '{target_name}' was not found in any sources location.")
    return None

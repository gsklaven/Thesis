# Behavioral RAG for Malicious Package Detection

A system that detects malicious Python (PyPI) packages in three stages:

1. **Static analysis (CodeQL)**: for every sensitive call (network, command execution, files,
   encoding) a *Behavior Chain* is extracted: the data flows into the call, the gating conditions
   and the library calls around it.
2. **Hybrid RAG**: every Behavior Chain is compared (all-MiniLM-L6-v2, cosine similarity) with
   (a) Behavior Chains of known malicious packages and (b) a security knowledge base
   (MITRE ATT&CK, CAPEC, CWE, Semgrep, Bandit, GuardDog, SLSA, OWASP).
3. **LLM (DeepSeek)**: a structured prompt with three questions → a `MALICIOUS`/`BENIGN` verdict per
   Behavior Chain → aggregated into a package verdict (one `MALICIOUS` chain is enough).

## Layout

```
dataset/
  preparation/               all preparation scripts (see the flow below)
    policy_sources/          local sources of the knowledge base (Semgrep, Bandit, GuardDog, OWASP, SLSA ...)
  malware_dataset*.json      list of malware samples and the location of their code
  analyzed_chains/           Behavior Chains of all malware (one JSON per package)
  benign_test_set/           Behavior Chains of the benign test packages (sdists from PyPI)
  final_diverse_subset/      selected samples (one per distinct code) + _meta/_packages.json
  rag_train/  rag_test/      family-level split (no shared campaign or code)
  indexes/rag_index/         vectors of the rag_train Behavior Chains
  indexes/policy_index/      vectors of the security knowledge base
  obfuscated/                obfuscated copies (levels A, B) of 100+100 evaluation packages (obfuscated_set.json)
  payload_scan.json, excluded_*.json, attack_type_tags.json, policy_rules.json, audit_leakage.json,
  audit_code_overlap.json    code overlap of the evaluation malware without Behavior Chains with the index
  added_test_samples.json    samples added to the evaluation set only (index and split unchanged)
inference/
  codeql_pipeline/           analysis.py, build_behavior_chain.py, python_queries/, js_queries/
  query_rag.py               retrieval + prompt construction (RAG_MODE for the ablations)
  llm_evaluator.py           evaluation of one package (shared logic for every LLM)
  llm_providers.py           LLM call: deepseek | gemini | lmstudio | openrouter (LLM_PROVIDER in .env)
results/
  <version>/report_*.json    report per package (v14_<mode>/ = final results of the thesis)
  test_set_summaries/        test_set_summary_<version>_<test set>.json
  evaluation_summaries/      evaluation_summary_<version>.json
  analysis/                  metrics, confusion matrices, strata, ablations, LaTeX of the thesis
  check_test_set.py, evaluation_summary.py, results_analysis.py, thesis_tables.py, progress.py, run_local_subset.sh,
  retrieval_sensitivity.py
expected_labels.json         evaluation labels (malicious for rag_test, benign for benign_test_set)
run_pipeline.sh              automated execution of all stages (guide: PIPELINE.md)
requirements.txt             versions of the Python packages
.env.example                 template of the local settings (sources location, LLM key) -> .env
old/                         everything the pipeline no longer uses (not in git)
```

## Quick start

```bash
./run_pipeline.sh setup      # sources location -> .env, venv, CodeQL packs
./run_pipeline.sh check
./run_pipeline.sh status     # what has been done and what is missing
./run_pipeline.sh all        # or single stages: sources, collect, analyze, benign, rag, evaluate
```

Detailed scenarios (new machine, reproduction from the GitHub Release without re-running CodeQL,
update with new packages, publishing the Behavior Chains): **[PIPELINE.md](PIPELINE.md)**. The sections
below describe what each stage does and which script it calls.

## Prerequisites

- Python 3.14 and a `venv/` with the packages of `requirements.txt` (`./run_pipeline.sh setup` installs them).
- CodeQL CLI 2.27.0 in the `PATH` and the query packs (`codeql pack install`, also done by `setup`).
- The clones of the malware sources in one folder or disk, declared as `THESIS_SOURCES_DIR` in `.env`
  (`./run_pipeline.sh sources` downloads them). The stored sample paths are mapped automatically to
  this folder (`utils.resolve_source_path`).
- `DEEPSEEK_API_KEY` for the LLM stage.

## Execution flow

This is what `run_pipeline.sh` does, stage by stage. Commands run from the project root, with the
`venv` active. Every script reads the sources location and the keys from `.env` (`utils.load_env_file`).

### 1. Collection of malware samples

```bash
python3 dataset/preparation/prepare_dataset_diverse.py   # OSV malicious-packages -> dataset/malware_dataset.json
python3 dataset/preparation/collect_all_samples.py       # + Datadog, MalwareBench, pypi_malregistry, maloss -> malware_dataset_all_sources.json
python3 dataset/preparation/extract_samples.py           # matching with the code on disk -> malware_dataset_matched.json
python3 dataset/preparation/malwarebench_false_positives.py  # legitimate MalwareBench packages (threat_type=false_positive)
```

### 2. Static analysis (Behavior Chains)

Without installing dependencies (`CODEQL_NO_VENDOR=1`). Packages that already have a result are
skipped, so an interrupted run resumes where it stopped.

```bash
# malware -> dataset/analyzed_chains/ (list: {"targets": [package names]})
python3 -c "import json; json.dump({'targets': [i['package_name'] for i in json.load(open('dataset/malware_dataset_matched.json')) if i.get('package_name')]}, open('/tmp/targets.json', 'w'))"
CODEQL_NO_VENDOR=1 CODEQL_QUERY_TIMEOUT=600 CODEQL_DB_TIMEOUT=900 BATCH_ANALYSIS_TIMEOUT=1200 \
  python3 dataset/preparation/rerun_chains.py --packages-file /tmp/targets.json --key targets
#   in parallel: N processes with --shard i/N, --pipeline-dir <private copy of inference/codeql_pipeline>
#   and BATCH_STAGING_DIR=<private folder> per process

# benign packages: sdists from the PyPI JSON API (no pip) -> dataset/benign_test_set/
python3 dataset/preparation/select_extra_benign.py       # selection (benign_extra_selection.json)
CODEQL_NO_VENDOR=1 python3 dataset/preparation/fetch_benign_test_set.py

# scan for malicious code, independent of CodeQL -> dataset/payload_scan.json
python3 dataset/preparation/payload_scan.py
```

### 3. Security knowledge base

```bash
python3 dataset/preparation/harvest_policy_sources.py   # GuardDog, Bandit, Semgrep, registry policies -> policy_sources/*.json
python3 dataset/preparation/build_policy_dataset.py     # + MITRE ATT&CK, CWE, CAPEC -> dataset/policy_rules.json
python3 dataset/preparation/build_policy_index.py       # -> dataset/indexes/policy_index/
# or all three: ./run_pipeline.sh policy
```

### 4. RAG: selection, split, index

```bash
python3 dataset/preparation/rebuild_rag.py            # --dry-run to preview, --from-step N to resume
python3 dataset/preparation/audit_leakage.py --out dataset/audit_leakage.json
python3 dataset/preparation/audit_code_overlap.py      # -> dataset/audit_code_overlap.json
```

`rebuild_rag.py` runs, in order:

| Step | Script | What it does |
|---|---|---|
| 1 | `backfill_osv_descriptions.py` | fills in the OSV descriptions |
| 2 | `attack_type_tagger.py` | attack-type tags and campaign signatures |
| 3 | `build_final_dataset.py` | excludes false positives/no_payload, keeps one package per distinct code (≤5 per campaign), static misses at the population rate |
| 4 | `split_train_test.py` | 80/20 by family (campaign or identical code), seed 42 |
| 5 | `build_rag_index.py` | vectors of the rag_train Behavior Chains |
| — | (built in) | update of `expected_labels.json` and sanity check |

`audit_leakage.py` checks: no train/test overlap, no shared code, no prompt with information about the
package itself, similarity strata (known variant / close / novel) and shortcuts. `audit_code_overlap.py`
covers the evaluation malware without Behavior Chains (no payload signature): it hashes each code file
independently of whitespace and looks it up among the code files of every rag_train package.

### 5. LLM evaluation (4 ablations)

```bash
# DEEPSEEK_API_KEY in .env
RESULTS_PREFIX=v14 PARALLEL_MODES=1 ./run_pipeline.sh evaluate   # sum samples policy llm -> results/v14_<mode>/
# one configuration and one set by hand:
RESULTS_TAG=v14_sum RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test
python3 results/results_analysis.py v14_sum v14_samples v14_policy v14_llm   # -> results/analysis/
python3 results/thesis_tables.py          # LaTeX tables and figures of the thesis -> results/analysis/latex/
```

- Reports per package: `results/v14_<mode>/report_<package>.json`, summaries in `results/test_set_summaries/`
  and `results/evaluation_summaries/`.
- `check_test_set.py` automatically re-runs whatever is `EVALUATION_FAILED`/`INCOMPLETE`/`UNKNOWN`
  and skips packages that already have a final verdict.
- `RESULTS_SUFFIX=_smoke` for test runs that are never mixed with the real results.

## Environment variables

| Variable | Use |
|---|---|
| `CODEQL_NO_VENDOR=1` | dependencies are recorded by name and not installed |
| `CODEQL_QUERY_TIMEOUT`, `CODEQL_DB_TIMEOUT`, `BATCH_ANALYSIS_TIMEOUT`, `BENIGN_ANALYSIS_TIMEOUT` | time limits (seconds) |
| `BATCH_STAGING_DIR` | temporary analysis folder (one per parallel process) |
| `THESIS_SOURCES_DIR` | folder with the clones of the sources (in `.env`) |
| `THESIS_OSV_DIR`, `THESIS_BASE_DIR` | optional: another location for OSV / the project root |
| `RAG_MODE` | `sum` \| `samples` \| `policy` \| `llm` |
| `RESULTS_SUFFIX` | suffix of the results folder (e.g. `_smoke`) |
| `LLM_PROVIDER` | `deepseek` (default) \| `gemini` \| `lmstudio` \| `openrouter` - the same evaluator for all |
| `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL` | LLM access (default `deepseek-flash`); likewise `GEMINI_*`, `LM_STUDIO_*`, `OPENROUTER_*` |

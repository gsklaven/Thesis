# Execution guide: `run_pipeline.sh`

`run_pipeline.sh` runs the whole pipeline in stages. **Every stage resumes where it stopped**: anything
that already has a result is skipped, so an interruption (power, disconnected disk, Ctrl+C) loses no
work. Just run the same command again.

The only things you provide are **where the sources are** (the disk or folder with the clones of the
malware datasets) and, for the evaluation, **the LLM key**. They are written once in `.env` (never
committed to git).

## 0. What is in git and what is in the GitHub Release

| In git (clone of the repository) | In the GitHub Release (`./run_pipeline.sh pack`) |
|---|---|
| all the code, `run_pipeline.sh`, guides, `requirements.txt` | `dataset/analyzed_chains/` - Behavior Chains of all malware (~10 GB) |
| the small JSON files of `dataset/`: sample lists (`malware_dataset*.json`), labels, `payload_scan`, exclusions, selection (`final_diverse_subset_*.json`), `policy_rules.json` | `dataset/benign_test_set/` - Behavior Chains of the benign packages |
| `dataset/preparation/policy_sources/` (without the Semgrep rules) | `dataset/rag_train/`, `dataset/rag_test/`, `dataset/indexes/` (with the vectors) |
| `expected_labels.json`, result summaries (`results/*_summaries/`, `results/analysis/`) | LLM reports per package (`results/v12_*/`) + again the JSON files of `dataset/` and `expected_labels.json` |

The clone is small. The large data is downloaded once from the Release (scenario A).

## 1. Installation on a new machine

Requirements: Python 3.14, git (+ `git-lfs` for the MalwareBench source) and the
[CodeQL CLI 2.27.0](https://github.com/github/codeql-action/releases) in the `PATH` (macOS: `brew install codeql`).

```bash
git clone <this repository> Thesis && cd Thesis
./run_pipeline.sh setup    # asks for the sources location -> .env, creates the venv, installs the CodeQL packs
./run_pipeline.sh check    # confirms venv, CodeQL, sources, key
```

Settings live in `.env` (template: `.env.example`). It is read **both** by `run_pipeline.sh` **and** by
every Python script on its own (through `dataset/preparation/utils.py`), so e.g.
`python3 results/check_test_set.py dataset/rag_test` finds the key without `export`. Anything set in the
shell overrides `.env`. Values with spaces go in quotes.

| Variable | What it is |
|---|---|
| `THESIS_SOURCES_DIR` | folder with the clones of the sources (e.g. `/Volumes/USB`). Needed for `sources`, `collect`, `analyze`, `rag` |
| `LLM_PROVIDER` | which LLM `evaluate` uses: `deepseek` (default), `gemini`, `lmstudio`, `openrouter` (see scenario E) |
| `DEEPSEEK_API_KEY` | only for `evaluate` with `deepseek` (likewise `GEMINI_API_KEY`, `OPENROUTER_API_KEY`) |
| `WORKERS` | parallel CodeQL analyses (default 4; ~4 GB RAM each) |

The sample paths in `dataset/malware_dataset_matched.json` were recorded on another machine. All scripts
map them automatically to `THESIS_SOURCES_DIR` (`utils.resolve_source_path`), so **no change to code or
data is needed**.

### Sources

```bash
./run_pipeline.sh sources  # clone the missing ones into THESIS_SOURCES_DIR, git pull the existing ones
```

| Folder | Repository | Note |
|---|---|---|
| `malicious-packages/` | github.com/ossf/malicious-packages | OSV reports (descriptions, campaigns) |
| `pypi_malregistry/` | github.com/lxyeternal/pypi_malregistry | main source of PyPI samples |
| `pypi/` | github.com/MalwareBench/pypi | git-lfs; only `threat_type = malware` - the `false_positive` ones are legitimate packages and are excluded |
| `malicious-software-packages-dataset/` | github.com/DataDog/malicious-software-packages-dataset | encrypted zips (password `infected`), extracted by `collect` into `malware_samples/` |
| `maloss-samples/` | github.com/osssanitizer/maloss-samples | access may have to be requested from its authors |

> The sources contain **real malicious code**. The pipeline never executes it (static analysis only,
> no `pip install`). Do not open/run the samples outside the pipeline and never upload them anywhere.

## 2. Scenarios

### A. Reproducing the results without re-running CodeQL (the fastest)

The Behavior Chains, the train/test sets and the indexes are published as a GitHub Release (see D).
The malware sources are not needed.

```bash
# download behavior_chains.tar.gz.part-* and SHA256SUMS from the Release page into dist/
# (or: gh release download <tag> -p 'behavior_chains*' -p SHA256SUMS -D dist)
./run_pipeline.sh unpack          # checksum check + restore into dataset/ and results/
./run_pipeline.sh evaluate        # MODES="sum samples policy llm" (default)
```

### B. Resuming / updating with new packages

```bash
./run_pipeline.sh unpack          # (when starting from the Release) the already analysed samples, so CodeQL does not run again
./run_pipeline.sh update          # = sources -> collect -> analyze -> rag
RESULTS_SUFFIX=_update1 ./run_pipeline.sh evaluate
```

- `sources` pulls (git pull) the new malicious packages of the sources.
- `collect` rebuilds the sample list (a backup of the previous one is kept in `work/`).
- `analyze` runs CodeQL **only for the new packages**: anything that already has a result in
  `dataset/analyzed_chains/` is skipped, as are packages that already failed (`RETRY_FAILED=1` to retry
  them) and the legitimate MalwareBench packages. The payload scan follows, also only for the new ones.
- `rag` rebuilds the selection, the split and the index (~5 minutes). The selection (one package per
  distinct code) and the family split are made over the **whole** set, so the new train/test differs
  from the previous one: the results are a **new version** and are not directly comparable with v12.
  Hence the `RESULTS_SUFFIX`.

### C. From scratch

```bash
./run_pipeline.sh all             # collect -> analyze -> benign -> rag -> evaluate
```

Indicative times (Apple M5, 10 cores, 24 GB):

| Stage | Time |
|---|---|
| `analyze` (~14,500 malware, 4–6 workers) | ~3–4 days |
| `benign` (~500 packages) | ~2 hours with 4 workers |
| `rag` | ~10 minutes |
| `evaluate` (~25,000 LLM calls per configuration, incl. the obfuscated copies) | ~10 hours for the four configurations with `PARALLEL_MODES=1` |

`./run_pipeline.sh status` shows at any time how much is done and what is missing.

### D. Publishing the Behavior Chains (GitHub Release)

```bash
./run_pipeline.sh pack            # -> dist/behavior_chains.tar.gz.part-aa, -ab, ... + SHA256SUMS
```

Then create the Release, either from the GitHub web page (Releases → Draft a new release → tag
`chains-v12` → attach every file of `dist/` → Publish release) or with the GitHub CLI:

```bash
gh release create chains-v12 dist/behavior_chains.tar.gz.part-* dist/SHA256SUMS \
  --title "Behavior Chains v12" --notes "See PIPELINE.md, scenario A"
```

- GitHub accepts files of up to 100 MB inside the repository, but up to **2 GB per file in a Release**.
  That is why `pack` splits the archive into parts of 1.9 GB. For permanent archiving with a DOI, the
  same files can also be uploaded to Zenodo.
- Contents: `analyzed_chains/`, `benign_test_set/`, `rag_train/`, `rag_test/`, `indexes/`, the JSON files of
  `dataset/`, the LLM reports `results/v12_*/` (not the `*_smoke` ones) and `expected_labels.json`. Run it
  **after** `evaluate` has finished, so that it also contains the results.
- Behavior Chains are descriptions of code (call names, snippets, URLs), not executable packages.
  **Do not upload** the malware sources or `policy_sources/semgrep_rules.json` (Semgrep Rules License:
  internal use only).

### E. Evaluation with another LLM

All providers use **the same** evaluator (`inference/llm_evaluator.py`): the same prompt, the same parsing
of the answer, the same retries for failing chains, the same aggregation and report format. Only the model
call changes (`inference/llm_providers.py`). In `.env`:

| `LLM_PROVIDER` | What it needs | Results in |
|---|---|---|
| `deepseek` (default, the thesis experiments) | `DEEPSEEK_API_KEY` (+ `DEEPSEEK_MODEL`, default `deepseek-flash`) | `results/v12_<mode>/` |
| `gemini` | `GEMINI_API_KEY` (+ `GEMINI_MODEL`) | `results/v12_<mode>_gemini/` |
| `lmstudio` (local, nothing leaves the computer) | LM Studio with its server running (+ `LM_STUDIO_URL`, `LM_STUDIO_MODEL`) | `results/v12_<mode>_lmstudio/` |
| `openrouter` | `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` (a specific model) | `results/v12_<mode>_openrouter/` |

```bash
LLM_PROVIDER=gemini MODES=sum ./run_pipeline.sh evaluate   # or permanently: LLM_PROVIDER=gemini in .env
```

Every report records `llm_provider`/`llm_model`, and every chain verdict its `model_used`. The model is
never switched silently: if a provider fails or runs out of quota, the chain is retried and, if it fails
for good, the package stays `INCOMPLETE` for the next run.

**Local-model experiment.** A local model is evaluated on a fixed subset of the test sets
(`dataset/preparation/select_local_subset.py` → `dataset/local_subset.json`: 120 malware + 60 benign
packages, 1,709 chains per mode), compared package by package with DeepSeek:
```bash
sudo sysctl iogpu.wired_limit_mb=20480     # 24 GB Mac: GPU memory for a ~20k-token context (until reboot)
bash results/run_local_subset.sh           # sum and llm -> results/v13_{sum,llm}/; checks the context first; resumable
python3 results/progress.py --watch 60     # progress, in a second terminal
```

**v14: extended evaluation.** Same index, knowledge base and prompt as v12; the evaluation sets grow and
the dependency graph of every package is checked:
```bash
bash run_pipeline.sh sources && bash run_pipeline.sh collect && bash run_pipeline.sh analyze
bash run_pipeline.sh addtest                                           # new malware -> rag_test only
python3 dataset/preparation/select_extra_benign.py --extend 460        # 40 curated + 460 sampled = 500 benign
bash run_pipeline.sh benign                                            # CodeQL for the new benign packages
bash run_pipeline.sh obfuscate                                         # 100+100 obfuscated copies, levels A and B
bash run_pipeline.sh deps                                              # dependency findings in every chains file
RESULTS_PREFIX=v14 PARALLEL_MODES=1 bash run_pipeline.sh evaluate      # the 4 configurations -> results/v14_*/
```
The obfuscation tool is set up once as described in `dataset/preparation/build_obfuscated_set.py`. Every
report records `final_verdict` (the LLM on the package's own code) and `final_verdict_with_dependencies`
(also MALICIOUS when a known malicious package is in its dependency graph, `inference/dependency_check.py`).
The CodeQL analysis also extracts the constant arguments of the calls (`constant_args_py.ql`: file names,
URLs, commands, e.g. which file `exec(open(...).read())` runs); they are listed in the LLM text of every
Behavior Chain, while the retrieval text is unchanged, so the index of v12 is reused.

## 3. All commands

| Command | What it does |
|---|---|
| `setup` | `.env`, venv + `requirements.txt`, `codeql pack install` for the queries |
| `check` | check of the prerequisites |
| `status` | analysed / pending / failed, RAG size, progress of the results |
| `sources` | clone the missing sources + git pull |
| `collect` | `prepare_dataset_diverse` → `collect_all_samples` → `extract_samples` → `malwarebench_false_positives` |
| `analyze` | CodeQL (without installing dependencies) for the missing malware, `WORKERS` in parallel + `payload_scan` |
| `benign` | download of sdists from the PyPI JSON API (no pip) + CodeQL for the missing benign packages |
| `policy` | a **new** snapshot of the knowledge base (current versions of MITRE/CWE/CAPEC and of the rules). Not part of `all`/`update`, so that the knowledge base of the experiments stays the same |
| `rag` | `rebuild_rag.py` (descriptions, tags, selection, split, index) + `audit_leakage.py` |
| `evaluate` | for every `RAG_MODE` in `MODES`: `check_test_set` on malware and benign, and `evaluation_summary`; then `results_analysis` |
| `addtest` | new malware samples (names not in `dataset/v12_known_samples.json`) → evaluation set only, with the selection and family-split rules; index and split unchanged |
| `obfuscate` | `build_obfuscated_set.py`: obfuscated copies (Intensio-Obfuscator, levels A and B) of 100 malware + 100 benign evaluation packages + CodeQL → `dataset/obfuscated/` |
| `deps` | `dependency_findings.py`: declared dependencies of every evaluation package and the known malicious packages in its dependency graph → written into the chains files |
| `update` | `sources` → `collect` → `analyze` → `rag` |
| `all` | `collect` → `analyze` → `benign` → `rag` → `evaluate` |
| `pack` / `unpack [DIR]` | packing / restoring for the GitHub Release |

More settings: `BENIGN_WORKERS` (2), `RETRY_FAILED=1`, `MODES`, `RESULTS_PREFIX` (results in `results/<prefix>_<mode>`),
`SETS` (the sets of `evaluate`; default: the evaluation sets and the obfuscated copies), `PARALLEL_MODES=1`
(the configurations in parallel in `evaluate`), `RESULTS_SUFFIX`, `CODEQL_QUERY_TIMEOUT` / `CODEQL_DB_TIMEOUT` /
`BATCH_ANALYSIS_TIMEOUT` (seconds).

## 4. Where files are written

| Folder | Contents |
|---|---|
| `logs/` | `pipeline.log` (all stages), `analyze_w*.log`, `benign_b*.log`, `eval_<mode>_*.log` |
| `work/` | temporary worker folders and backups of the lists (deleted/recreated) |
| `dist/` | files of `pack` |
| `results/` | see `results/README.md` |

`logs/`, `work/`, `dist/`, `old/` and `.env` are in `.gitignore`.

## 5. Common problems

- **The computer went to sleep / the disk was disconnected**: run the same command again, it resumes. On
  macOS the script keeps the computer awake (`caffeinate`), but closing the lid still puts it to sleep.
- **`python_pass_skipped` / `oversized` / `timeout_*` in `status`**: packages CodeQL could not analyse
  (e.g. >50 MB of code). They are recorded and not retried unless `RETRY_FAILED=1` (e.g. with larger
  `CODEQL_QUERY_TIMEOUT` / `BATCH_ANALYSIS_TIMEOUT`).
- **`EVALUATION_FAILED` / `INCOMPLETE` in `evaluate`**: API failures; run `evaluate` again, only these are
  retried.
- **No access to a source** (e.g. `maloss-samples`): the pipeline continues with the available ones. The
  missing samples show up in `status`.

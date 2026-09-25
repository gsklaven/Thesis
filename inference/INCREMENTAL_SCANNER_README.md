# Incremental Malware Scanner - Usage Guide

A planned extension of the system: scanning a Git repository on every push, e.g. from a GitHub Action,
and sending to the LLM only the Behavior Chains that are new since the previous scan.

## Architecture

```
inference/
  chain_fingerprint.py      <- fingerprint computation for behavior chains
  incremental_scanner.py    <- main orchestrator (full + incremental mode)
```

State storage (inside the target repository):
```
.malware_scan/
  .gitignore              <- created automatically
  baseline.json           <- fingerprints of all analysed chains   <- COMMIT TO GIT
  last_scan.json          <- last full report                      <- COMMIT TO GIT
  incremental/
    commit_abc1234.json   <- report per commit
```

> **Note**: add `.malware_scan/` to the `.gitignore` of the CI runner if you do not want to commit the
> state. For persistence between CI runs **without** committing it, use the GitHub Actions cache.

---

## 1. First push - Full Scan (baseline)

The LLM provider and its key are read from the project's `.env` (see `.env.example`).

```bash
export THESIS_BASE_DIR="/path/to/Thesis"

python3 inference/incremental_scanner.py \
    --target /path/to/target-repo \
    --package my-package-name \
    --mode full
```

This:
1. runs CodeQL on the whole repository,
2. evaluates ALL behavior chains with the LLM,
3. stores the fingerprints in `.malware_scan/baseline.json`.

---

## 2. Next commits - Incremental Scan

```bash
python3 inference/incremental_scanner.py \
    --target /path/to/target-repo \
    --package my-package-name \
    --mode incremental \
    --commit abc1234def \
    --prev-commit def5678abc
```

This:
1. finds the files changed between the two commits (`git diff`),
2. runs CodeQL on the **whole** repository (for complete cross-file taint tracking),
3. keeps the chains that touch the changed files,
4. skips chains with a known fingerprint (already analysed),
5. sends **only the new chains** to the LLM.

---

## 3. Example GitHub Actions workflow

```yaml
name: Malware Scan

on:
  push:
    branches: [main, develop]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2  # at least 2 commits are needed for git diff

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install sentence-transformers openai numpy

      - name: Install CodeQL
        run: |
          wget -q https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
          tar -xzf codeql-bundle-linux64.tar.gz
          echo "$PWD/codeql" >> $GITHUB_PATH

      - name: Restore scan baseline
        uses: actions/cache@v4
        with:
          path: .malware_scan/
          key: malware-baseline-${{ github.ref_name }}
          restore-keys: malware-baseline-

      - name: Run Incremental Scan
        env:
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
          THESIS_BASE_DIR: /path/to/thesis
        run: |
          MODE="incremental"
          # without a baseline, run a full scan
          if [ ! -f ".malware_scan/baseline.json" ]; then
            MODE="full"
          fi
          
          python3 /path/to/thesis/inference/incremental_scanner.py \
            --target . \
            --package ${{ github.event.repository.name }} \
            --mode $MODE \
            --commit ${{ github.sha }} \
            --prev-commit ${{ github.event.before }}

      - name: Save scan baseline
        uses: actions/cache@v4
        with:
          path: .malware_scan/
          key: malware-baseline-${{ github.ref_name }}-${{ github.sha }}
```

---

## 4. Fingerprint logic

A chain is **considered the same** (skipped) if it has:
- the same API category (e.g. `network`, `crypto_obfuscation`),
- the same sensitive API call and flow boundary,
- the same normalised data-flow nodes, gating conditions and source flows (lower-cased text,
  collapsed whitespace).

A chain is **considered new** if:
- an API call changes,
- the data flows or their node texts change (this includes renamed variables, which appear in the
  node texts),
- the direction (flow boundary) changes.

**Does NOT affect the fingerprint** (= not analysed again):
- line numbers (code moved to other lines),
- whitespace / formatting changes,
- comments.

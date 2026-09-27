# results/

| Location | Contents | Produced by |
|---|---|---|
| `<version>/report_<package>.json` | full report per package: final verdict, LLM verdict per Behavior Chain, retrieved samples and security entries, prompt | `inference/llm_evaluator.py` (through `check_test_set.py`) |
| `test_set_summaries/test_set_summary_<version>_<test set>.json` | verdict per package, false positives/negatives, static misses, unclear | `check_test_set.py` |
| `analysis/<version>.md`, `analysis/confusion_<version>.svg` / `.tex`, `analysis/ablations.md` | confusion matrix (chart + LaTeX table), metrics with 95% confidence intervals, results per similarity stratum, FP/FN lists, comparison of the ablations; interpretation in `analysis/notes.md` | `results_analysis.py` |
| `analysis/latex/*.tex` | LaTeX tables and figures of Chapters 4-5 of the thesis (datasets, metrics, ablations, strata, SSVC, comparison, confusion matrices), in Greek; copied to `Thesis_text/chapters/generated/` | `thesis_tables.py` |
| `evaluation_summaries/evaluation_summary_<version>.json` | confusion matrix, accuracy/precision/recall/F1/FPR (end-to-end and LLM stage only) | `evaluation_summary.py` |

The `<version>` is `PROMPT_VERSION_RAG_MODE[_provider][RESULTS_SUFFIX]` (e.g. `v12_sum`, `v12_llm`,
`v12_sum_gemini`, `v12_sum_smoke`). The provider is added only when it is not `deepseek` (see `LLM_PROVIDER`).
`v13_sum` and `v13_llm` are the local-model runs (LM Studio) on `dataset/local_subset.json`; their name is set
with `RESULTS_TAG` by `run_local_subset.sh`.
The results of the earlier prompt/pipeline versions `v1`–`v11` (not comparable with v12) are kept in the
git history and locally in `old/results/`.

## Scripts

```bash
RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test          # malware of the test set
RAG_MODE=sum python3 results/check_test_set.py dataset/benign_test_set   # benign packages
python3 results/evaluation_summary.py [v12_samples ...]                  # metrics (without an argument: every v12_*)
python3 results/results_analysis.py                                      # detailed results + confusion matrix -> results/analysis/
python3 results/thesis_tables.py                                         # LaTeX tables/figures of the thesis -> results/analysis/latex/
```

- `check_test_set.py` automatically re-runs `EVALUATION_FAILED` / `INCOMPLETE` / `UNKNOWN` packages and skips
  the ones that already have a final verdict (it can be interrupted and resumed).
- `NO_CHAINS_FOUND` packages (no sensitive call in the static analysis) are excluded from the LLM-stage metrics
  for both classes, and are counted in the end-to-end ones.

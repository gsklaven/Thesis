# results/

| Location | Contents | Produced by |
|---|---|---|
| `<version>/report_<package>.json` | full report per package: final verdict, LLM verdict per Behavior Chain, retrieved samples and security entries, prompt | `inference/llm_evaluator.py` (through `check_test_set.py`) |
| `test_set_summaries/test_set_summary_<version>_<test set>.json` | verdict per package, false positives/negatives, static misses, unclear | `check_test_set.py` |
| `analysis/<version>.md`, `analysis/confusion_<version>.svg` / `.tex`, `analysis/ablations.md` | confusion matrix (chart + LaTeX table), metrics with 95% confidence intervals, results per similarity stratum, FP/FN lists, comparison of the ablations; interpretation in `analysis/notes.md` | `results_analysis.py` |
| `analysis/latex/*.tex` | LaTeX tables of Chapters 2-5 of the thesis (datasets, metrics, ablations, strata, SSVC, comparison), in Greek, copied to `Thesis_text/tables/`; `analysis/latex/images/*.png` are the confusion matrices, copied to `Thesis_text/images/chapter5/` | `thesis_tables.py` |
| `analysis/retrieval_sensitivity.json` | change of the top-1 similarity and of the similarity strata when the compact representation keeps 5, 20 or all slice nodes instead of 10 (Section 4.3 of the thesis) | `retrieval_sensitivity.py` |
| `evaluation_summaries/evaluation_summary_<version>.json` | confusion matrix, accuracy/precision/recall/F1/FPR (end-to-end and LLM stage only) | `evaluation_summary.py` |

The `<version>` is `PROMPT_VERSION_RAG_MODE[_provider][RESULTS_SUFFIX]` (e.g. `v12_sum`, `v12_llm`,
`v12_sum_gemini`, `v12_sum_smoke`). The provider is added only when it is not `deepseek` (see `LLM_PROVIDER`).
`v14_local_sum` and `v14_local_llm` are the local-model runs of the thesis (LM Studio, `run_local_subset.sh`) on
`dataset/local_subset.json`, with the final Behavior Chains; they are compared with `v14_sum`/`v14_llm` on the same
packages. `v13_sum` and `v13_llm` are the earlier local runs on the Behavior Chains without constant arguments.
`v14_<mode>` (the four configurations, `RESULTS_PREFIX=v14 PARALLEL_MODES=1 bash run_pipeline.sh evaluate`)
are the final results of the thesis: the evaluation sets (451 malware, 499 benign) and the obfuscated copies,
with the index, knowledge base and prompt `v12`; the LLM text of every chain also lists the constant arguments
of its calls, and the reports carry the dependency-graph check. `analysis/latex/images/*.png` are the figures
(copied to `Thesis_text/images/chapter5/`).
The results of the earlier prompt/pipeline versions `v1`–`v11` (not comparable with v12) are kept in the
git history and in the archive of `old/` kept outside the repository.

## Scripts

```bash
RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test          # malware of the test set
RAG_MODE=sum python3 results/check_test_set.py dataset/benign_test_set   # benign packages
python3 results/evaluation_summary.py v14_sum [v14_llm ...]              # metrics of the given runs
python3 results/results_analysis.py                                      # detailed results + confusion matrix -> results/analysis/
python3 results/thesis_tables.py                                         # LaTeX tables/figures of the thesis -> results/analysis/latex/
python3 results/retrieval_sensitivity.py                                 # slice-node limit sensitivity -> results/analysis/
python3 results/progress.py v14_sum v14_llm --sets dataset/rag_test dataset/benign_test_set --watch 60   # progress of a run
```

- `check_test_set.py` automatically re-runs `EVALUATION_FAILED` / `INCOMPLETE` / `UNKNOWN` packages and skips
  the ones that already have a final verdict (it can be interrupted and resumed).
- `NO_CHAINS_FOUND` packages (no sensitive call in the static analysis) are excluded from the LLM-stage metrics
  for both classes, and are counted in the end-to-end ones.

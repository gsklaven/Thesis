# results/

| Θέση | Περιεχόμενο | Παράγεται από |
|---|---|---|
| `<έκδοση>/report_<πακέτο>.json` | πλήρης αναφορά ανά πακέτο: τελική απόφαση, απόφαση του LLM ανά Behavior Chain, ανακτημένα δείγματα και εγγραφές ασφάλειας, prompt | `inference/llm_evaluator.py` (μέσω του `check_test_set.py`) |
| `test_set_summaries/test_set_summary_<έκδοση>_<test set>.json` | απόφαση ανά πακέτο, false positives/negatives, static misses, ασαφή | `check_test_set.py` |
| `analysis/<έκδοση>.md`, `analysis/confusion_<έκδοση>.svg` / `.tex`, `analysis/ablations.md` | confusion matrix (γράφημα + πίνακας LaTeX), μετρικές με 95% διάστημα εμπιστοσύνης, ανάλυση ανά ζώνη ομοιότητας, λίστες FP/FN, σύγκριση ablations· ερμηνεία στο `analysis/notes.md` | `results_analysis.py` |
| `evaluation_summaries/evaluation_summary_<έκδοση>.json` | confusion matrix, accuracy/precision/recall/F1/FPR (end-to-end και μόνο στάδιο LLM) | `evaluation_summary.py` |

Η `<έκδοση>` είναι `PROMPT_VERSION_RAG_MODE[_πάροχος][RESULTS_SUFFIX]` (π.χ. `v12_sum`, `v12_llm`,
`v12_sum_gemini`, `v12_sum_smoke`). Ο πάροχος προστίθεται μόνο όταν δεν είναι ο `deepseek` (βλ. `LLM_PROVIDER`).
Οι φάκελοι `v1`–`v11` είναι προηγούμενες εκδόσεις του prompt/pipeline και δεν είναι συγκρίσιμοι με το v12.

## Scripts

```bash
RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test          # malware του test
RAG_MODE=sum python3 results/check_test_set.py dataset/benign_test_set   # νόμιμα πακέτα
python3 results/evaluation_summary.py [v12_samples ...]                  # μετρικές (χωρίς όρισμα: όλα τα v12_*)
python3 results/confusion_matrix_by_category.py                          # recall ανά κατηγορία επίθεσης, όλες οι εκδόσεις
python3 results/results_analysis.py                                      # αναλυτικά αποτελέσματα + confusion matrix -> results/analysis/
```

- `check_test_set.py` ξανατρέχει αυτόματα τα `EVALUATION_FAILED` / `INCOMPLETE` / `UNKNOWN` και παραλείπει
  όσα έχουν ήδη τελική απόφαση (μπορεί να διακοπεί και να συνεχιστεί).
- Τα `NO_CHAINS_FOUND` (καμία ευαίσθητη κλήση στη στατική ανάλυση) εξαιρούνται από τις μετρικές του σταδίου LLM
  και για τις δύο κλάσεις, και μετρούν στις end-to-end.

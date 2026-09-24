# results/

| Θέση | Περιεχόμενο | Παράγεται από |
|---|---|---|
| `<έκδοση>/report_<πακέτο>.json` | πλήρης αναφορά ανά πακέτο: τελική απόφαση, απόφαση του LLM ανά Behavior Chain, ανακτημένα δείγματα και εγγραφές ασφάλειας, prompt | `inference/llm_evaluator_deepseek.py` (μέσω του `check_test_set.py`) |
| `test_set_summaries/test_set_summary_<έκδοση>.json` | απόφαση ανά πακέτο, false positives/negatives, static misses, ασαφή | `check_test_set.py` |
| `evaluation_summaries/evaluation_summary_<έκδοση>.json` | confusion matrix, accuracy/precision/recall/F1/FPR (end-to-end και μόνο στάδιο LLM) | `evaluation_summary.py` |

Η `<έκδοση>` είναι `PROMPT_VERSION_RAG_MODE[RESULTS_SUFFIX]` (π.χ. `v12_sum`, `v12_llm`, `v12_sum_smoke`).
Οι φάκελοι `v1`–`v11` είναι προηγούμενες εκδόσεις του prompt/pipeline και δεν είναι συγκρίσιμοι με το v12.

## Scripts

```bash
RAG_MODE=sum python3 results/check_test_set.py dataset/rag_test          # malware του test
RAG_MODE=sum python3 results/check_test_set.py dataset/benign_test_set   # νόμιμα πακέτα
RAG_MODE=sum python3 results/evaluation_summary.py                       # μετρικές
python3 results/confusion_matrix_by_category.py                          # recall ανά κατηγορία επίθεσης, όλες οι εκδόσεις
```

- `check_test_set.py` ξανατρέχει αυτόματα τα `EVALUATION_FAILED` / `INCOMPLETE` / `UNKNOWN` και παραλείπει
  όσα έχουν ήδη τελική απόφαση (μπορεί να διακοπεί και να συνεχιστεί).
- Τα `NO_CHAINS_FOUND` (καμία ευαίσθητη κλήση στη στατική ανάλυση) εξαιρούνται από τις μετρικές του σταδίου LLM
  και για τις δύο κλάσεις, και μετρούν στις end-to-end.

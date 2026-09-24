# Αποτελέσματα v12_samples — μόνο κακόβουλα δείγματα

Αναφορές: 73/591 πακέτα · **λείπουν 518** (η εκτέλεση δεν έχει ολοκληρωθεί)

![confusion matrix](confusion_v12_samples.svg)

## Confusion matrix (στάδιο LLM)

| Πραγματική \ Απόφαση | MALICIOUS | BENIGN |
|---|---|---|
| **Malware** | TP = 36 | FN = 2 |
| **Benign** | FP = 0 | TN = 27 |

Εκτός σταδίου LLM (κανένα Behavior Chain): malware 3, benign 5.

## Μετρικές

| Μετρική | Τιμή | 95% διάστημα εμπιστοσύνης |
|---|---|---|
| Recall (στάδιο LLM) | **94,7%** (36/38) | [82,7% – 98,5%] |
| False positive rate | **0,0%** (0/27) | [0,0% – 12,5%] |
| Precision | **100,0%** | [90,4% – 100,0%] |
| F1 | **97,3%** | |
| Accuracy (στάδιο LLM) | **96,9%** | |
| Balanced accuracy | **97,4%** | |
| Recall end-to-end | 87,8% | |
| Accuracy end-to-end | 93,2% | |

## Ανά ζώνη ομοιότητας με το ευρετήριο

Μέγιστη ομοιότητα οποιουδήποτε Behavior Chain του πακέτου με το ευρετήριο (από την εκτέλεση `v12_sum`).

| Ζώνη | Malware | Recall | Benign | False positives |
|---|---|---|---|---|
| ≥0,98 γνωστή παραλλαγή | 18 | 17/18 = 94,4% | 11 | 0/11 = 0,0% |
| 0,90–0,98 κοντινό | 18 | 17/18 = 94,4% | 13 | 0/13 = 0,0% |
| <0,90 νέο | 2 | 2/2 = 100,0% | 3 | 0/3 = 0,0% |

## False positives (0)

Με ακριβώς ένα κακόβουλο Behavior Chain: 0/0.

| Πακέτο | Chains | Κακόβουλα | Μέγ. ομοιότητα | Κατηγορία / API / αρχείο του κακόβουλου chain |
|---|---|---|---|---|

## False negatives (2)

| Πακέτο | Chains | Μέγ. ομοιότητα |
|---|---|---|
| @bigid-ui | 2 | 0.9091 |
| ansiicolor | 1 | 1.0 |

Malware χωρίς Behavior Chains (static misses): NPM - coa - Versions diffs - 2.0.2 → 2.0.4 - Diffend - OSS supply chain security and management platform_files, atlassian-exp, atlassian-praz

_Παράγεται από το `results/results_analysis.py`. Σχόλια/ερμηνεία: `results/analysis/notes.md`._

# Αποτελέσματα v12_policy — μόνο βάση γνώσης ασφάλειας

Αναφορές: 45/591 πακέτα · **λείπουν 546** (η εκτέλεση δεν έχει ολοκληρωθεί)

![confusion matrix](confusion_v12_policy.svg)

## Confusion matrix (στάδιο LLM)

| Πραγματική \ Απόφαση | MALICIOUS | BENIGN |
|---|---|---|
| **Malware** | TP = 1 | FN = 0 |
| **Benign** | FP = 2 | TN = 35 |

Εκτός σταδίου LLM (κανένα Behavior Chain): malware 0, benign 7.

## Μετρικές

| Μετρική | Τιμή | 95% διάστημα εμπιστοσύνης |
|---|---|---|
| Recall (στάδιο LLM) | **100,0%** (1/1) | [20,7% – 100,0%] |
| False positive rate | **5,4%** (2/37) | [1,5% – 17,7%] |
| Precision | **33,3%** | [6,1% – 79,2%] |
| F1 | **50,0%** | |
| Accuracy (στάδιο LLM) | **94,7%** | |
| Balanced accuracy | **97,3%** | |
| Recall end-to-end | 100,0% | |
| Accuracy end-to-end | 95,6% | |

## Ανά ζώνη ομοιότητας με το ευρετήριο

Μέγιστη ομοιότητα οποιουδήποτε Behavior Chain του πακέτου με το ευρετήριο (από την εκτέλεση `v12_sum`).

| Ζώνη | Malware | Recall | Benign | False positives |
|---|---|---|---|---|
| ≥0,98 γνωστή παραλλαγή | 0 | 0/0 = — | 14 | 1/14 = 7,1% |
| 0,90–0,98 κοντινό | 1 | 1/1 = 100,0% | 19 | 1/19 = 5,3% |
| <0,90 νέο | 0 | 0/0 = — | 4 | 0/4 = 0,0% |

## False positives (2)

Με ακριβώς ένα κακόβουλο Behavior Chain: 2/2.

| Πακέτο | Chains | Κακόβουλα | Μέγ. ομοιότητα | Κατηγορία / API / αρχείο του κακόβουλου chain |
|---|---|---|---|---|
| daff | 15 | 1 | 0.9425 | process_exec `python_lib_Subprocess.call(...)` daff/__init__.py (sim 0.0, TRACK*) |
| fabric | 6 | 1 | 1.0 | process_exec `exec(...)` setup.py (sim 0.0, TRACK*) |

## False negatives (0)

| Πακέτο | Chains | Μέγ. ομοιότητα |
|---|---|---|

_Παράγεται από το `results/results_analysis.py`. Σχόλια/ερμηνεία: `results/analysis/notes.md`._

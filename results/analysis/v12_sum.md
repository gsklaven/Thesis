# Αποτελέσματα v12_sum — πλήρες σύστημα (δείγματα + πολιτικές)

Αναφορές: 591/591 πακέτα

![confusion matrix](confusion_v12_sum.svg)

## Confusion matrix (στάδιο LLM)

| Πραγματική \ Απόφαση | MALICIOUS | BENIGN |
|---|---|---|
| **Malware** | TP = 404 | FN = 12 |
| **Benign** | FP = 8 | TN = 122 |

Εκτός σταδίου LLM (κανένα Behavior Chain): malware 6, benign 39.

## Μετρικές

| Μετρική | Τιμή | 95% διάστημα εμπιστοσύνης |
|---|---|---|
| Recall (στάδιο LLM) | **97,1%** (404/416) | [95,0% – 98,3%] |
| False positive rate | **6,2%** (8/130) | [3,2% – 11,7%] |
| Precision | **98,1%** | [96,2% – 99,0%] |
| F1 | **97,6%** | |
| Accuracy (στάδιο LLM) | **96,3%** | |
| Balanced accuracy | **95,5%** | |
| Recall end-to-end | 95,7% | |
| Accuracy end-to-end | 95,6% | |

## Ανά ζώνη ομοιότητας με το ευρετήριο

Μέγιστη ομοιότητα οποιουδήποτε Behavior Chain του πακέτου με το ευρετήριο (από την εκτέλεση `v12_sum`).

| Ζώνη | Malware | Recall | Benign | False positives |
|---|---|---|---|---|
| ≥0,98 γνωστή παραλλαγή | 235 | 233/235 = 99,1% | 29 | 4/29 = 13,8% |
| 0,90–0,98 κοντινό | 139 | 129/139 = 92,8% | 83 | 4/83 = 4,8% |
| <0,90 νέο | 42 | 42/42 = 100,0% | 18 | 0/18 = 0,0% |

## False positives (8)

Με ακριβώς ένα κακόβουλο Behavior Chain: 8/8.

| Πακέτο | Chains | Κακόβουλα | Μέγ. ομοιότητα | Κατηγορία / API / αρχείο του κακόβουλου chain |
|---|---|---|---|---|
| psutil | 94 | 1 | 0.9658 | file_ops `tempfile.NamedTemporaryFile(...)` scripts/internal/install_pip.py (sim 0.9377, ACT) |
| oauth2client | 70 | 1 | 0.9624 | crypto_obfuscation `pickle.loads(...)` oauth2client/contrib/django_util/models.py (sim 0.9002, ATTEND) |
| frozendict | 18 | 1 | 0.96 | process_exec `exec(...)` setup.py (sim 0.96, ATTEND) |
| daff | 15 | 1 | 0.9425 | process_exec `call(...)` setup.py (sim 0.9172, ATTEND) |
| opencensus | 8 | 1 | 1.0 | process_exec `exec(...)` setup.py (sim 1.0, ATTEND) |
| fabric | 6 | 1 | 1.0 | process_exec `exec(...)` setup.py (sim 1.0, ATTEND) |
| crossplane | 6 | 1 | 0.997 | process_exec `os.system(...)` setup.py (sim 0.9959, ATTEND) |
| opentelemetry-exporter-gcp-monitoring | 1 | 1 | 0.9909 | process_exec `exec(...)` setup.py (sim 0.9909, ATTEND) |

## False negatives (12)

| Πακέτο | Chains | Μέγ. ομοιότητα |
|---|---|---|
| @bigid-ui | 2 | 0.9091 |
| celery-flower | 5 | 0.9136 |
| celium-collateral-upgrade | 3 | 0.931 |
| dmclc | 1 | 0.9329 |
| huzzleup | 1 | 0.954 |
| juk | 1 | 0.9359 |
| lium-4.96 | 19 | 0.9427 |
| pyphetools | 9 | 0.9735 |
| rasterkit | 80 | 1.0 |
| rblxtools | 2 | 1.0 |
| set-utils | 2 | 0.9516 |
| set_utils | 2 | 0.926 |

Malware χωρίς Behavior Chains (static misses): NPM - coa - Versions diffs - 2.0.2 → 2.0.4 - Diffend - OSS supply chain security and management platform_files, atlassian-exp, atlassian-praz, free-onlyfans-no-subscription-premium-hack, guan, pyg-utils

_Παράγεται από το `results/results_analysis.py`. Σχόλια/ερμηνεία: `results/analysis/notes.md`._

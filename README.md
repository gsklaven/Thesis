# Behavioral RAG για την Ανίχνευση Κακόβουλων Πακέτων

Σύστημα που ανιχνεύει κακόβουλα πακέτα Python (PyPI) με τρία στάδια:

1. **Στατική ανάλυση (CodeQL)**: για κάθε ευαίσθητη κλήση (δίκτυο, εκτέλεση εντολών, αρχεία,
   κωδικοποίηση) εξάγεται ένα *Behavior Chain*: οι ροές δεδομένων προς την κλήση, οι συνθήκες
   ελέγχου και οι κλήσεις βιβλιοθηκών γύρω της.
2. **Υβριδικό RAG**: κάθε Behavior Chain συγκρίνεται (all-MiniLM-L6-v2, ομοιότητα συνημιτόνου)
   με (α) Behavior Chains γνωστών κακόβουλων πακέτων και (β) μια βάση γνώσης ασφάλειας
   (MITRE ATT&CK, CAPEC, CWE, Semgrep, Bandit, GuardDog, SLSA, OWASP).
3. **LLM (DeepSeek)**: δομημένο prompt τριών ερωτημάτων → απόφαση `MALICIOUS`/`BENIGN` ανά
   Behavior Chain → συγκέντρωση σε απόφαση πακέτου (ένα `MALICIOUS` chain αρκεί).

## Δομή

```
dataset/
  preparation/               όλα τα scripts προετοιμασίας (βλ. ροή παρακάτω)
    policy_sources/          στατικές πηγές της βάσης γνώσης (Semgrep, Bandit, GuardDog, OWASP, SLSA ...)
  malware_dataset*.json      λίστα δειγμάτων malware και θέση του κώδικά τους
  analyzed_chains/           Behavior Chains όλων των malware (ένα JSON ανά πακέτο)
  benign_test_set/           Behavior Chains των νόμιμων πακέτων του test (sdists από το PyPI)
  final_diverse_subset/      επιλεγμένα δείγματα (ένα ανά διαφορετικό κώδικα) + _meta/_packages.json
  rag_train/  rag_test/      διαχωρισμός ανά οικογένεια (καμία κοινή καμπάνια ή κοινός κώδικας)
  indexes/rag_index/         διανύσματα των Behavior Chains του rag_train
  indexes/policy_index/      διανύσματα της βάσης γνώσης ασφάλειας
  payload_scan.json, excluded_*.json, attack_type_tags.json, policy_rules.json, audit_leakage_v12.json
inference/
  codeql_pipeline/           analysis.py, build_behavior_chain.py, python_queries/, js_queries/
  query_rag.py               ανάκτηση + κατασκευή του prompt (RAG_MODE για τα ablations)
  llm_evaluator_deepseek.py  αξιολόγηση με DeepSeek (+ llm_evaluator.py: Gemini, llm_evaluator_lmstudio.py: τοπικά)
results/
  <έκδοση>/report_*.json     αναφορά ανά πακέτο (π.χ. v12_sum/, v12_llm/)
  test_set_summaries/        test_set_summary_<έκδοση>.json
  evaluation_summaries/      evaluation_summary_<έκδοση>.json
  check_test_set.py, evaluation_summary.py, confusion_matrix_by_category.py
expected_labels.json         ετικέτες αξιολόγησης (malicious για το rag_test, benign για το benign_test_set)
old/                         ό,τι δεν χρησιμοποιεί πλέον το pipeline (εκτός git)
```

## Προαπαιτούμενα

- Python 3.14 και `venv/` (`source venv/bin/activate`): sentence-transformers, numpy, scikit-learn, openai.
- CodeQL CLI 2.27.0 στο `PATH`.
- Τα ακατέργαστα δείγματα malware σε εξωτερικό δίσκο (`THESIS_USB_MOUNT`, προεπιλογή `/Volumes/GIORGOS_128`)
  και κλώνος του OSV malicious-packages (`THESIS_OSV_DIR`).
- `DEEPSEEK_API_KEY` για το στάδιο του LLM.

## Ροή εκτέλεσης

Όλες οι εντολές τρέχουν από τη ρίζα του έργου, με ενεργό το `venv`.

### 1. Συλλογή δειγμάτων malware

```bash
python3 dataset/preparation/prepare_dataset_diverse.py   # OSV malicious-packages -> dataset/malware_dataset.json
python3 dataset/preparation/collect_all_samples.py       # + Datadog, MalwareBench, pypi_malregistry, maloss -> malware_dataset_all_sources.json
python3 dataset/preparation/extract_samples.py           # αντιστοίχιση με τον κώδικα στον δίσκο -> malware_dataset_matched.json
python3 dataset/preparation/malwarebench_false_positives.py  # νόμιμα πακέτα του MalwareBench (threat_type=false_positive)
```

### 2. Στατική ανάλυση (Behavior Chains)

Χωρίς εγκατάσταση εξαρτήσεων (`CODEQL_NO_VENDOR=1`). Τα πακέτα που έχουν ήδη αποτέλεσμα παραλείπονται,
οπότε μια διακοπείσα εκτέλεση συνεχίζει από εκεί που σταμάτησε.

```bash
# malware -> dataset/analyzed_chains/ (λίστα: {"targets": [ονόματα πακέτων]})
python3 -c "import json; json.dump({'targets': [i['package_name'] for i in json.load(open('dataset/malware_dataset_matched.json')) if i.get('package_name')]}, open('/tmp/targets.json', 'w'))"
CODEQL_NO_VENDOR=1 CODEQL_QUERY_TIMEOUT=600 CODEQL_DB_TIMEOUT=900 BATCH_ANALYSIS_TIMEOUT=1200 \
  python3 dataset/preparation/rerun_chains.py --packages-file /tmp/targets.json --key targets
#   παράλληλα: N διεργασίες με --shard i/N, --pipeline-dir <ιδιωτικό αντίγραφο του inference/codeql_pipeline>
#   και BATCH_STAGING_DIR=<ιδιωτικός φάκελος> ανά διεργασία

# νόμιμα πακέτα: sdists από το PyPI JSON API (χωρίς pip) -> dataset/benign_test_set/
python3 dataset/preparation/select_extra_benign.py       # επιλογή (benign_extra_selection.json)
CODEQL_NO_VENDOR=1 python3 dataset/preparation/fetch_benign_test_set.py

# σάρωση για κακόβουλο κώδικα, ανεξάρτητη από το CodeQL -> dataset/payload_scan.json
python3 dataset/preparation/payload_scan.py
```

### 3. Βάση γνώσης ασφάλειας

```bash
python3 dataset/preparation/harvest_semgrep_python_rules.py    # -> policy_sources/*.json
python3 dataset/preparation/harvest_guarddog_rules.py
python3 dataset/preparation/harvest_registry_policies.py
python3 dataset/preparation/harvest_extra_policy_sources.py
python3 dataset/preparation/build_policy_dataset.py            # + MITRE ATT&CK, CWE, CAPEC -> dataset/policy_rules.json
python3 dataset/preparation/build_policy_index.py              # -> dataset/indexes/policy_index/
```

### 4. RAG: επιλογή, διαχωρισμός, ευρετήριο

```bash
python3 dataset/preparation/rebuild_rag.py            # --dry-run για προεπισκόπηση, --from-step N για συνέχεια
python3 dataset/preparation/audit_leakage.py --out dataset/audit_leakage_v12.json
```

Το `rebuild_rag.py` εκτελεί με τη σειρά:

| Βήμα | Script | Τι κάνει |
|---|---|---|
| 1 | `backfill_osv_descriptions.py` | συμπληρώνει τις περιγραφές OSV |
| 2 | `attack_type_tagger.py` | ετικέτες επίθεσης και υπογραφές καμπάνιας |
| 3 | `build_final_dataset.py` | εξαιρεί false positives/no_payload, κρατά ένα πακέτο ανά διαφορετικό κώδικα (≤5 ανά καμπάνια), static misses με την αναλογία του πληθυσμού |
| 4 | `split_train_test.py` | 80/20 ανά οικογένεια (καμπάνια ή ίδιος κώδικας), seed 42 |
| 5 | `build_rag_index.py` | διανύσματα των Behavior Chains του rag_train |
| — | (ενσωματωμένο) | ενημέρωση `expected_labels.json` και έλεγχος ορθότητας |

Το `audit_leakage.py` ελέγχει: μηδενική επικάλυψη train/test, κανένα κοινό κώδικα, κανένα prompt με
πληροφορία για το ίδιο το πακέτο, ζώνες ομοιότητας (γνωστή παραλλαγή / κοντινό / νέο) και shortcuts.

### 5. Αξιολόγηση με LLM (4 ablations)

```bash
export DEEPSEEK_API_KEY=...
for MODE in sum samples policy llm; do     # sum = πλήρες σύστημα, llm = χωρίς ανάκτηση
  RAG_MODE=$MODE python3 results/check_test_set.py dataset/rag_test
  RAG_MODE=$MODE python3 results/check_test_set.py dataset/benign_test_set
  RAG_MODE=$MODE python3 results/evaluation_summary.py
done
python3 results/confusion_matrix_by_category.py
```

- Αναφορές ανά πακέτο: `results/v12_<mode>/report_<πακέτο>.json`, συνόψεις στα `results/test_set_summaries/`
  και `results/evaluation_summaries/`.
- Το `check_test_set.py` ξανατρέχει αυτόματα ό,τι είναι `EVALUATION_FAILED`/`INCOMPLETE`/`UNKNOWN`
  και παραλείπει όσα έχουν ήδη τελική απόφαση.
- `RESULTS_SUFFIX=_smoke` για δοκιμαστικές εκτελέσεις που δεν αναμειγνύονται με τα πραγματικά αποτελέσματα.

## Μεταβλητές περιβάλλοντος

| Μεταβλητή | Χρήση |
|---|---|
| `CODEQL_NO_VENDOR=1` | οι εξαρτήσεις καταγράφονται κατ' όνομα και δεν εγκαθίστανται |
| `CODEQL_QUERY_TIMEOUT`, `CODEQL_DB_TIMEOUT`, `BATCH_ANALYSIS_TIMEOUT`, `BENIGN_ANALYSIS_TIMEOUT` | χρονικά όρια (δευτερόλεπτα) |
| `BATCH_STAGING_DIR` | προσωρινός φάκελος ανάλυσης (ένας ανά παράλληλη διεργασία) |
| `THESIS_USB_MOUNT`, `THESIS_OSV_DIR`, `THESIS_BASE_DIR` | θέσεις δεδομένων |
| `RAG_MODE` | `sum` \| `samples` \| `policy` \| `llm` |
| `RESULTS_SUFFIX` | επίθημα του φακέλου αποτελεσμάτων (π.χ. `_smoke`) |
| `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL` | πρόσβαση στο LLM (προεπιλογή `deepseek-flash`) |

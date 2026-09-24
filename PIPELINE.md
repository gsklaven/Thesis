# Οδηγός εκτέλεσης: `run_pipeline.sh`

Το `run_pipeline.sh` εκτελεί όλο το pipeline σε στάδια. **Κάθε στάδιο συνεχίζει από εκεί που
σταμάτησε**: ό,τι έχει ήδη αποτέλεσμα παραλείπεται, οπότε μια διακοπή (ρεύμα, αποσύνδεση δίσκου,
Ctrl+C) δεν χάνει δουλειά. Αρκεί να ξανατρέξεις την ίδια εντολή.

Το μόνο που πρέπει να δώσεις εσύ είναι **πού βρίσκονται οι πηγές** (ο δίσκος ή φάκελος με τους
κλώνους των datasets malware) και, για την αξιολόγηση, **το κλειδί του LLM**. Γράφονται μία φορά
στο `pipeline.env` (δεν ανεβαίνει στο git).

## 1. Εγκατάσταση σε νέο μηχάνημα

Χρειάζονται: Python 3.14, git (+ `git-lfs` για την πηγή MalwareBench) και το
[CodeQL CLI 2.27.0](https://github.com/github/codeql-action/releases) στο `PATH` (macOS: `brew install codeql`).

```bash
git clone <αυτό το αποθετήριο> Thesis && cd Thesis
./run_pipeline.sh setup    # ρωτά τη θέση των πηγών -> pipeline.env, φτιάχνει venv, εγκαθιστά τα πακέτα CodeQL
./run_pipeline.sh check    # επιβεβαιώνει venv, CodeQL, πηγές, κλειδί
```

Ρυθμίσεις στο `pipeline.env` (υπόδειγμα: `pipeline.env.example`):

| Μεταβλητή | Τι είναι |
|---|---|
| `THESIS_SOURCES_DIR` | φάκελος με τους κλώνους των πηγών (π.χ. `/Volumes/USB`). Χρειάζεται για `sources`, `collect`, `analyze`, `rag` |
| `DEEPSEEK_API_KEY` | μόνο για το `evaluate` |
| `WORKERS` | παράλληλες αναλύσεις CodeQL (προεπιλογή 4· ~4 GB RAM η καθεμία) |

Οι διαδρομές των δειγμάτων στο `dataset/malware_dataset_matched.json` έχουν καταγραφεί σε άλλο
μηχάνημα. Όλα τα scripts τις μεταφράζουν αυτόματα στο `THESIS_SOURCES_DIR`
(`utils.resolve_source_path`), άρα **δεν χρειάζεται καμία αλλαγή σε κώδικα ή δεδομένα**.

### Πηγές

```bash
./run_pipeline.sh sources  # clone όσων λείπουν στο THESIS_SOURCES_DIR, git pull στα υπάρχοντα
```

| Φάκελος | Αποθετήριο | Σημείωση |
|---|---|---|
| `malicious-packages/` | github.com/ossf/malicious-packages | αναφορές OSV (περιγραφές, καμπάνιες) |
| `pypi_malregistry/` | github.com/lxyeternal/pypi_malregistry | κύρια πηγή δειγμάτων PyPI |
| `pypi/` | github.com/MalwareBench/pypi | git-lfs· μόνο `threat_type = malware`, τα `false_positive` είναι νόμιμα πακέτα και εξαιρούνται |
| `malicious-software-packages-dataset/` | github.com/DataDog/malicious-software-packages-dataset | κρυπτογραφημένα zip (κωδικός `infected`), αποσυμπιέζονται από το `collect` στο `malware_samples/` |
| `maloss-samples/` | github.com/osssanitizer/maloss-samples | μπορεί να απαιτεί αίτημα πρόσβασης στους δημιουργούς |

> Οι πηγές περιέχουν **πραγματικό κακόβουλο κώδικα**. Το pipeline δεν τον εκτελεί ποτέ (μόνο στατική
> ανάλυση, χωρίς `pip install`). Μην τις ανοίγεις/εκτελείς εκτός pipeline και μην τις ανεβάζεις πουθενά.

## 2. Σενάρια

### Α. Αναπαραγωγή των αποτελεσμάτων χωρίς ξανά CodeQL (το πιο γρήγορο)

Τα Behavior Chains, το train/test και τα ευρετήρια δημοσιεύονται ως GitHub Release (βλ. Δ).
Δεν χρειάζονται οι πηγές malware.

```bash
gh release download <tag> -p 'behavior_chains*' -p SHA256SUMS -D dist   # ή λήψη από τη σελίδα του Release
./run_pipeline.sh unpack          # έλεγχος checksums + επαναφορά στο dataset/
./run_pipeline.sh evaluate        # MODES="sum samples policy llm" (προεπιλογή)
```

### Β. Συνέχεια από εκεί που σταματήσαμε / ενημέρωση με νέα πακέτα

```bash
./run_pipeline.sh unpack          # (αν ξεκινάς από Release) τα ήδη αναλυμένα, για να μην ξανατρέξει το CodeQL
./run_pipeline.sh update          # = sources -> collect -> analyze -> rag
RESULTS_SUFFIX=_update1 ./run_pipeline.sh evaluate
```

- `sources` τραβά (git pull) τα νέα κακόβουλα πακέτα των πηγών.
- `collect` ξαναφτιάχνει τη λίστα δειγμάτων (κρατά backup της προηγούμενης στο `work/`).
- `analyze` τρέχει το CodeQL **μόνο για τα νέα πακέτα**: ό,τι έχει ήδη αποτέλεσμα στο
  `dataset/analyzed_chains/` παραλείπεται, όπως και όσα έχουν ήδη αποτύχει (`RETRY_FAILED=1` για
  να ξαναδοκιμαστούν) και τα νόμιμα πακέτα του MalwareBench. Ακολουθεί η σάρωση payload, επίσης μόνο για τα νέα.
- `rag` ξαναχτίζει επιλογή, διαχωρισμό και ευρετήριο (~5 λεπτά). Η επιλογή (ένα πακέτο ανά
  διαφορετικό κώδικα) και ο διαχωρισμός ανά οικογένεια γίνονται **σε όλο** το σύνολο, οπότε το νέο
  train/test διαφέρει από το προηγούμενο: τα αποτελέσματα είναι **νέα έκδοση** και δεν συγκρίνονται
  απευθείας με το v12. Γι' αυτό το `RESULTS_SUFFIX`.

### Γ. Από την αρχή

```bash
./run_pipeline.sh all             # collect -> analyze -> benign -> rag -> evaluate
```

Ενδεικτικοί χρόνοι (Apple M5, 10 πυρήνες, 24 GB):

| Στάδιο | Χρόνος |
|---|---|
| `analyze` (~14.500 malware, 4–6 workers) | ~3–4 ημέρες |
| `benign` (170 πακέτα) | ~2 ώρες |
| `rag` | ~10 λεπτά |
| `evaluate` (~16.500 κλήσεις LLM ανά ablation) | ~8 ώρες ανά ablation |

`./run_pipeline.sh status` δείχνει ανά πάσα στιγμή πόσα έχουν γίνει και τι λείπει.

### Δ. Δημοσίευση των Behavior Chains (GitHub Release)

```bash
./run_pipeline.sh pack            # -> dist/behavior_chains.tar.gz.part-aa, -ab, ... + SHA256SUMS
gh release create chains-v12 dist/behavior_chains.tar.gz.part-* dist/SHA256SUMS \
  --title "Behavior Chains v12" --notes "Βλ. PIPELINE.md, σενάριο Α"
```

- Το GitHub δέχεται αρχεία έως 100 MB μέσα στο αποθετήριο, αλλά έως **2 GB ανά αρχείο σε Release**.
  Γι' αυτό το `pack` κόβει το αρχείο σε κομμάτια των 1,9 GB. Για μόνιμη αρχειοθέτηση με DOI, τα ίδια
  αρχεία μπορούν να ανέβουν και στο Zenodo.
- Περιέχει: `analyzed_chains/`, `benign_test_set/`, `rag_train/`, `rag_test/`, `indexes/`, τα JSON του `dataset/`
  (μαζί με το `malware_dataset_matched.json`, που δεν είναι στο git) και το `expected_labels.json`.
- Τα Behavior Chains είναι περιγραφές κώδικα (ονόματα κλήσεων, αποσπάσματα, URLs), όχι εκτελέσιμα
  πακέτα. **Μην ανεβάζεις** τις πηγές malware ούτε το `policy_sources/semgrep_rules.json`
  (άδεια Semgrep Rules: μόνο εσωτερική χρήση).

## 3. Όλες οι εντολές

| Εντολή | Τι κάνει |
|---|---|
| `setup` | `pipeline.env`, venv + `requirements.txt`, `codeql pack install` για τα queries |
| `check` | έλεγχος προαπαιτούμενων |
| `status` | αναλυμένα / σε εκκρεμότητα / αποτυχημένα, μέγεθος RAG, πρόοδος αποτελεσμάτων |
| `sources` | clone όσων πηγών λείπουν + git pull |
| `collect` | `prepare_dataset_diverse` → `collect_all_samples` → `extract_samples` → `malwarebench_false_positives` |
| `analyze` | CodeQL (χωρίς εγκατάσταση εξαρτήσεων) για όσα malware λείπουν, με `WORKERS` παράλληλα + `payload_scan` |
| `benign` | λήψη sdists από το PyPI JSON API (χωρίς pip) + CodeQL για όσα νόμιμα πακέτα λείπουν |
| `policy` | **νέο** snapshot της βάσης γνώσης (τρέχουσες εκδόσεις MITRE/CWE/CAPEC και κανόνων). Δεν περιλαμβάνεται στα `all`/`update`, για να μένει ίδια η βάση των πειραμάτων |
| `rag` | `rebuild_rag.py` (περιγραφές, ετικέτες, επιλογή, διαχωρισμός, ευρετήριο) + `audit_leakage.py` |
| `evaluate` | για κάθε `RAG_MODE` του `MODES`: `check_test_set` σε malware και benign, και `evaluation_summary` |
| `update` | `sources` → `collect` → `analyze` → `rag` |
| `all` | `collect` → `analyze` → `benign` → `rag` → `evaluate` |
| `pack` / `unpack [DIR]` | συσκευασία / επαναφορά για GitHub Release |

Επιπλέον ρυθμίσεις: `BENIGN_WORKERS` (2), `RETRY_FAILED=1`, `MODES`, `PARALLEL_SETS=1` (malware και
benign test ταυτόχρονα στο `evaluate`), `RESULTS_SUFFIX`, `CODEQL_QUERY_TIMEOUT` / `CODEQL_DB_TIMEOUT` /
`BATCH_ANALYSIS_TIMEOUT` (δευτερόλεπτα).

## 4. Πού γράφονται τα αρχεία

| Φάκελος | Περιεχόμενο |
|---|---|
| `logs/` | `pipeline.log` (όλα τα στάδια), `analyze_w*.log`, `benign_b*.log`, `eval_<mode>_*.log` |
| `work/` | προσωρινοί φάκελοι των workers και backups των λιστών (σβήνονται/ξαναφτιάχνονται) |
| `dist/` | αρχεία του `pack` |
| `results/` | βλ. `results/README.md` |

Τα `logs/`, `work/`, `dist/`, `old/` και `pipeline.env` είναι στο `.gitignore`.

## 5. Συνήθη προβλήματα

- **Ο υπολογιστής κοιμήθηκε / αποσυνδέθηκε ο δίσκος**: ξανατρέξε την ίδια εντολή, συνεχίζει. Σε macOS
  το script κρατά τον υπολογιστή ξύπνιο (`caffeinate`), αλλά το κλείσιμο του καπακιού τον κοιμίζει.
- **`python_pass_skipped` / `oversized` / `timeout_*` στο `status`**: πακέτα που το CodeQL δεν μπόρεσε
  να αναλύσει (π.χ. >50 MB κώδικα). Καταγράφονται και δεν ξαναδοκιμάζονται, εκτός αν `RETRY_FAILED=1`
  (π.χ. με μεγαλύτερα `CODEQL_QUERY_TIMEOUT` / `BATCH_ANALYSIS_TIMEOUT`).
- **`EVALUATION_FAILED` / `INCOMPLETE` στο `evaluate`**: αποτυχίες του API· ξανατρέξε το `evaluate`,
  δοκιμάζονται ξανά μόνο αυτά.
- **Χωρίς πρόσβαση σε μια πηγή** (π.χ. `maloss-samples`): το pipeline συνεχίζει με όσες υπάρχουν. Τα
  δείγματα που λείπουν εμφανίζονται στο `status`.

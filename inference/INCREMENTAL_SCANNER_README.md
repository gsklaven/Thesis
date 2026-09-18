# Incremental Malware Scanner — Οδηγός Χρήσης

## Αρχιτεκτονική

```
inference/
  chain_fingerprint.py      ← Fingerprint υπολογισμός για behavior chains
  incremental_scanner.py    ← Κύριος ορχηστρατόρας (full + incremental mode)
```

Αποθήκευση state (μέσα στο target repo):
```
.malware_scan/
  .gitignore              ← Δημιουργείται αυτόματα
  baseline.json           ← Fingerprints όλων των αναλυμένων chains  ← COMMIT ΣΤΟ GIT
  last_scan.json          ← Τελευταίο full report                    ← COMMIT ΣΤΟ GIT
  incremental/
    commit_abc1234.json   ← Report ανά commit
```

> **Σημείωση**: Πρόσθεσε `.malware_scan/` στο `.gitignore` του CI runner αν δεν θέλεις να commítεις το state. Αν θέλεις persistence μεταξύ CI runs **χωρίς** να κάνεις commit, χρησιμοποίησε GitHub Actions cache.

---

## 1. Πρώτο push — Full Scan (Baseline)

```bash
export DEEPSEEK_API_KEY="your_key_here"
export THESIS_BASE_DIR="/Users/giorgos/Documents/Thesis"

python3 inference/incremental_scanner.py \
    --target /path/to/target-repo \
    --package my-package-name \
    --mode full
```

Αυτό:
1. Τρέχει CodeQL σε ολόκληρο το repo
2. Αναλύει ΟΛΑ τα behavior chains μέσω DeepSeek
3. Αποθηκεύει fingerprints στο `.malware_scan/baseline.json`

---

## 2. Επόμενα commits — Incremental Scan

```bash
python3 inference/incremental_scanner.py \
    --target /path/to/target-repo \
    --package my-package-name \
    --mode incremental \
    --commit abc1234def \
    --prev-commit def5678abc
```

Αυτό:
1. Βρίσκει changed files μεταξύ των δύο commits (`git diff`)
2. Τρέχει CodeQL σε **ολόκληρο** το repo (για πλήρη cross-file taint tracking)
3. Φιλτράρει chains που αφορούν τα changed files
4. Παραλείπει chains με γνωστό fingerprint (ήδη αναλυμένα)
5. Στέλνει **μόνο τα νέα chains** στο LLM

---

## 3. Παράδειγμα GitHub Actions Workflow

```yaml
name: Malware Scan

on:
  push:
    branches: [main, develop]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2  # Χρειαζόμαστε τουλάχιστον 2 commits για git diff

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install sentence-transformers openai numpy

      - name: Install CodeQL
        run: |
          wget -q https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
          tar -xzf codeql-bundle-linux64.tar.gz
          echo "$PWD/codeql" >> $GITHUB_PATH

      - name: Restore scan baseline
        uses: actions/cache@v4
        with:
          path: .malware_scan/
          key: malware-baseline-${{ github.ref_name }}
          restore-keys: malware-baseline-

      - name: Run Incremental Scan
        env:
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
          THESIS_BASE_DIR: /path/to/thesis
        run: |
          MODE="incremental"
          # Αν δεν υπάρχει baseline, κάνε full scan
          if [ ! -f ".malware_scan/baseline.json" ]; then
            MODE="full"
          fi
          
          python3 /path/to/thesis/inference/incremental_scanner.py \
            --target . \
            --package ${{ github.event.repository.name }} \
            --mode $MODE \
            --commit ${{ github.sha }} \
            --prev-commit ${{ github.event.before }}

      - name: Save scan baseline
        uses: actions/cache@v4
        with:
          path: .malware_scan/
          key: malware-baseline-${{ github.ref_name }}-${{ github.sha }}
```

---

## 4. Λογική Fingerprint

Ένα chain **θεωρείται ίδιο** (παραλείπεται) αν:
- Ίδια κατηγορία API (π.χ. `network`, `crypto_obfuscation`)
- Ίδιο sensitive API call
- Ίδια normalized data flow nodes (text, lowercase, collapsed whitespace)

Ένα chain **θεωρείται νέο** αν:
- Αλλάζει κάποιο API call
- Αλλάζει ο τύπος των data flows
- Αλλάζει η κατεύθυνση (flow boundary)

**ΔΕΝ επηρεάζει το fingerprint** (= δεν τρέχει ξανά):
- Αλλαγή line numbers
- Rename μεταβλητής
- Whitespace / formatting αλλαγές
- Αλλαγή comments

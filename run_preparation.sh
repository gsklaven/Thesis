#!/bin/bash
# ΔΕΝ χρησιμοποιούμε πια "set -e" (abort-on-any-exit) γιατί μερικά scripts
# επιστρέφουν non-zero ακόμα και σε μερική επιτυχία/warnings - με "set -e"
# αυτό θα ακύρωνε ολόκληρο το pipeline αδίκαια. Αντί αυτού, κάθε ΚΡΙΣΙΜΟ
# βήμα ελέγχεται ρητά παρακάτω.

echo "[*] ==================================================="
echo "[*] Ξεκινάει η Προετοιμασία του Dual-Index RAG Pipeline"
echo "[*] ==================================================="

# Πάμε στον κεντρικό φάκελο
cd "${THESIS_BASE_DIR:-/home/sklavenitis/thesis}"

echo -e "\n[1/4] Βήμα 1 — Συλλογή OSV reports & πηγαίου κώδικα από ΟΛΑ τα sources..."
# 1a. Διαβάζει OSV reports από malicious-packages + ossf, εφαρμόζει
#     campaign-based diversity filter → malware_dataset.json
python3 dataset/preparation/prepare_dataset_diverse.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: prepare_dataset_diverse.py απέτυχε."; exit 1; }

# 1b. Ενοποιεί τις υπόλοιπες πηγές (maloss, datadog, pypi_malregistry κ.λπ.)
#     που έχουν ήδη source_code_path, χρησιμοποιώντας ως βάση το malware_dataset.json
#     → malware_dataset_all_sources.json
python3 dataset/preparation/collect_all_samples.py \
    || echo "[!] Προειδοποίηση: collect_all_samples.py - μερικές πηγές δεν βρέθηκαν (συνεχίζω)."

echo -e "\n[2/4] Βήμα 2 — Αντιστοίχιση με κώδικα & Σημασιολογική Ταξινόμηση..."
# 2a. Αντιστοιχίζει κάθε OSV entry με source code στο disk.
#     Entries που ήδη έχουν source_code_path (από collect_all_samples.py) περνούν
#     αυτόματα. → malware_dataset_matched.json
python3 dataset/preparation/extract_samples.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: extract_samples.py απέτυχε."; exit 1; }

# 2b. Keyword/typosquat/campaign tagging ΜΟΝΟ σε matched πακέτα
#     (αποφεύγουμε χρόνο σε unmatched entries χωρίς κώδικα)
#     → attack_type_tags.json
python3 dataset/preparation/attack_type_tagger.py \
    || echo "[!] Προειδοποίηση: attack_type_tagger.py - μερικά πακέτα χωρίς tags (συνεχίζω)."

# 2c. Pre-CodeQL code-based deduplication — αντιμετωπίζει τα 28K+ clones
#     από πηγές χωρίς OSV descriptions (Datadog, MalwareBench, MalOSS).
#     Παράγει code hash ανά πακέτο και κρατάει ελάχιστα ανά "code family".
#     → malware_dataset_deduped.json (διαβάζεται από batch_analyzer.py)
python3 dataset/preparation/code_dedup.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: code_dedup.py απέτυχε."; exit 1; }

echo -e "\n[3/4] Βήμα 3 — Μαζική Στατική Ανάλυση (CodeQL)..."
echo "      (Αυτό το βήμα μπορεί να διαρκέσει αρκετή ώρα)"
python3 dataset/preparation/batch_analyzer.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: batch_analyzer.py απέτυχε."; exit 1; }

echo -e "\n[4/4] Βήμα 4 — Τελική Επιλογή, Train/Test Split & Χτίσιμο Indexes..."
# 4a. Post-CodeQL diversity curation (campaign + technique dedup)
python3 dataset/preparation/build_final_dataset.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: build_final_dataset.py απέτυχε."; exit 1; }

# 4b. Διαχωρισμός σε train/test ΑΝΕΞΑΡΤΗΤΑ ΑΝΑ CAMPAIGN (no leakage)
python3 dataset/preparation/split_train_test.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: split_train_test.py απέτυχε."; exit 1; }

# 4c. Χτίσιμο vector indexes
python3 dataset/preparation/build_policy_dataset.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: build_policy_dataset.py απέτυχε."; exit 1; }
python3 dataset/preparation/build_policy_index.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: build_policy_index.py απέτυχε."; exit 1; }
python3 dataset/preparation/build_rag_index.py \
    || { echo "[!] ΚΡΙΣΙΜΟ ΣΦΑΛΜΑ: build_rag_index.py απέτυχε."; exit 1; }

echo -e "\n[*] ==================================================="
echo "[✓] Ολόκληρο το pipeline προετοιμασίας ολοκληρώθηκε επιτυχώς!"
echo "[*] Τα Indexes είναι έτοιμα στο: dataset/indexes/"
echo "[*]   - dataset/indexes/rag_index/    (malware behavior chains)"
echo "[*]   - dataset/indexes/policy_index/ (MITRE/OWASP/SLSA rules)"
echo "[*] Μπορείς πλέον να τρέξεις το inference/query_rag.py"
echo "[*] ==================================================="
#!/bin/bash
# Σταματάει την εκτέλεση αμέσως αν κάποια εντολή αποτύχει
set -e

echo "[*] ==================================================="
echo "[*] Ξεκινάει η Προετοιμασία του Dual-Index RAG Pipeline"
echo "[*] ==================================================="

# Πάμε στον κεντρικό φάκελο
cd "${THESIS_BASE_DIR:-/home/sklavenitis/thesis}"

echo -e "\n[1/4] Βήμα 1 — Συλλογή OSV reports & πηγαίου κώδικα από ΟΛΑ τα sources..."
# 1a. Διαβάζει OSV reports από malicious-packages + ossf, εφαρμόζει
#     campaign-based diversity filter → malware_dataset.json
python3 dataset/preparation/prepare_dataset_diverse.py

# 1b. Ενοποιεί τις υπόλοιπες πηγές (maloss, datadog, pypi_malregistry κ.λπ.)
#     που έχουν ήδη source_code_path, χρησιμοποιώντας ως βάση το malware_dataset.json
#     → malware_dataset_all_sources.json
python3 dataset/preparation/collect_all_samples.py

echo -e "\n[2/4] Βήμα 2 — Αντιστοίχιση με κώδικα & Σημασιολογική Ταξινόμηση..."
# 2a. Αντιστοιχίζει κάθε OSV entry με source code στο disk.
#     Entries που ήδη έχουν source_code_path (από collect_all_samples.py) περνούν
#     αυτόματα. → malware_dataset_matched.json
python3 dataset/preparation/extract_samples.py

# 2b. Keyword/typosquat/campaign tagging ΜΟΝΟ σε matched πακέτα
#     (αποφεύγουμε χρόνο σε unmatched entries χωρίς κώδικα)
#     → attack_type_tags.json
python3 dataset/preparation/attack_type_tagger.py

# 2c. Pre-CodeQL code-based deduplication — αντιμετωπίζει τα 28K+ clones
#     από πηγές χωρίς OSV descriptions (Datadog, MalwareBench, MalOSS).
#     Παράγει code hash ανά πακέτο και κρατάει ελάχιστα ανά "code family".
#     → malware_dataset_deduped.json (διαβάζεται από batch_analyzer.py)
python3 dataset/preparation/code_dedup.py

echo -e "\n[3/4] Βήμα 3 — Μαζική Στατική Ανάλυση (CodeQL)..."
echo "      (Αυτό το βήμα μπορεί να διαρκέσει αρκετή ώρα)"
python3 dataset/preparation/batch_analyzer.py

echo -e "\n[4/4] Βήμα 4 — Τελική Επιλογή, Train/Test Split & Χτίσιμο Indexes..."
# 4a. Post-CodeQL diversity curation (campaign + technique dedup)
python3 dataset/preparation/build_final_dataset.py

# 4b. Διαχωρισμός σε train/test ΑΝΕΞΑΡΤΗΤΑ ΑΝΑ CAMPAIGN (no leakage)
python3 dataset/preparation/split_train_test.py

# 4c. Χτίσιμο vector indexes
python3 dataset/preparation/build_policy_dataset.py
python3 dataset/preparation/build_policy_index.py
python3 dataset/preparation/build_rag_index.py

echo -e "\n[*] ==================================================="
echo "[✓] Ολόκληρο το pipeline προετοιμασίας ολοκληρώθηκε επιτυχώς!"
echo "[*] Τα Indexes είναι έτοιμα στο: dataset/indexes/"
echo "[*]   - dataset/indexes/rag_index/    (malware behavior chains)"
echo "[*]   - dataset/indexes/policy_index/ (MITRE/OWASP/SLSA rules)"
echo "[*] Μπορείς πλέον να τρέξεις το inference/query_rag.py"
echo "[*] ==================================================="
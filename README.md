# Behavioral RAG for Malware Threat Intelligence

Αυτό το αποθετήριο περιέχει ένα ολοκληρωμένο σύστημα κυβερνοασφάλειας που εντοπίζει, αναλύει και εξηγεί κακόβουλα πακέτα (malware) σε οικοσυστήματα ανοιχτού κώδικα (PyPI, npm).

Το σύστημα χρησιμοποιεί **Στατική Ανάλυση Κώδικα (CodeQL)** για την εξαγωγή "Αλυσίδων Συμπεριφοράς" (Behavior Chains) και ένα **Διπλό RAG (Retrieval-Augmented Generation) Index** για να συγκρίνει νέα άγνωστα πακέτα με:
1. Γνωστές ιστορικές καμπάνιες Malware.
2. Παγκόσμια πρότυπα κυβερνοασφάλειας (MITRE ATT&CK, OWASP, SLSA, CWE).

Στη συνέχεια, τα δεδομένα μορφοποιούνται ώστε ένα LLM να πραγματοποιήσει αξιολόγηση κινδύνου βάσει της μεθοδολογίας **SSVC (Stakeholder-Specific Vulnerability Categorization)**.

## 📂 Αρχιτεκτονική & Δομή Φακέλων

- `dataset/sources/`: Ακατέργαστα δεδομένα, JSON reports (OSV, Datadog) και zip/tar αρχεία malware.
- `dataset/preparation/`: Το Data Engineering pipeline. Scripts που προετοιμάζουν, καθαρίζουν, αναλύουν τα malware και χτίζουν τις βάσεις διανυσμάτων (Vector DBs).
- `dataset/indexes/`: Οι τελικές βάσεις διανυσμάτων (rag_index για malware, policy_index για κανόνες).
- `inference/`: Ο κώδικας εκτέλεσης σε πραγματικό χρόνο. Περιέχει το `query_rag.py` (που ρωτάει το RAG) και το CodeQL pipeline για νέα πακέτα.
- `results/`: Καταγραφή σφαλμάτων και τελικά reports αξιολόγησης.

## 🚀 Ροή Εκτέλεσης (Data Pipeline)

Το σύστημα λειτουργεί σε δύο φάσεις:

### Φάση 1: Προετοιμασία (Training & Indexing)
1. **Συλλογή & Επιλογή:** Συλλέγονται τα reports, φιλτράρονται για ποικιλομορφία (`prepare_dataset_diverse.py`) και εξάγεται ο πηγαίος κώδικας (`extract_samples.py`).
2. **Σημασιολογικός Χαρακτηρισμός (Tagging):** Εξαγωγή campaign signatures και typosquatting ετικετών (`attack_type_tagger.py`).
3. **Στατική Ανάλυση:** Το `batch_analyzer.py` τρέχει το CodeQL σε κάθε πακέτο και δημιουργεί τα Behavior Chains.
4. **Vectorization:** Τα JSONs και οι κανόνες (MITRE, OWASP) μετατρέπονται σε διανύσματα (`build_rag_index.py`, `build_policy_index.py`).

### Φάση 2: Αξιολόγηση (Inference)
Όταν ένα νέο, ύποπτο πακέτο εισέρχεται στο σύστημα:
- Το `inference/codeql_pipeline/analysis.py` εξάγει τα Data/Control Flows του.
- Το `inference/query_rag.py` αναζητά ομοιότητες στα δύο Indexes (Malware & Policies).
- Δημιουργείται το τελικό Prompt (με οδηγίες SSVC) έτοιμο για το LLM.
# Σημειώσεις ερμηνείας αποτελεσμάτων (για το Κεφάλαιο 5)

Τα νούμερα, οι πίνακες και οι λίστες παράγονται από το `results/results_analysis.py`
(`<tag>.md`, `confusion_<tag>.svg/.tex`, `ablations.md`). Εδώ γράφονται οι παρατηρήσεις και η
ερμηνεία, που το script δεν ξαναγράφει.

## v12_sum - πλήρες σύστημα (δείγματα + πολιτικές)

**Κύρια αποτελέσματα** (στάδιο LLM, 416 malware / 130 benign με Behavior Chains)

- Recall 97,1% [95,0-98,3], FPR 6,2% [3,2-11,7], precision 98,1%, F1 97,6%, accuracy 96,3%,
  balanced accuracy 95,5%. End-to-end (μαζί με τα πακέτα χωρίς Behavior Chains): accuracy 95,6%.
- Καμία αξιολόγηση `EVALUATION_FAILED` / `INCOMPLETE`: όλα τα πακέτα πήραν τελική απόφαση.
- Τα νούμερα προκύπτουν μετά από όλους τους καθαρισμούς: σωστές ετικέτες (χωρίς τα νόμιμα πακέτα του
  MalwareBench), κανένας κοινός κώδικας ανάμεσα σε ευρετήριο και test (διαχωρισμός ανά οικογένεια),
  καμία ανάλυση κώδικα βιβλιοθηκών (χωρίς vendoring).
- Δεν συγκρίνεται απευθείας με το v11 (άλλο test set, άλλο ευρετήριο, άλλα chains). Ενδεικτικά, το v11
  είχε recall 88% και FPR 27% (10/37).

**Γενίκευση σε νέο malware** (ζώνες μέγιστης ομοιότητας με το ευρετήριο)

- ≥0,98 (γνωστή παραλλαγή): recall 233/235 = 99,1%.
- 0,90-0,98 (κοντινό): recall 129/139 = 92,8%.
- <0,90 (νέο, χωρίς κοντινό γείτονα): recall **42/42 = 100%**. Το σύστημα δεν στηρίζεται απλώς στην
  ομοιότητα με γνωστά δείγματα: το LLM αναγνωρίζει τη συμπεριφορά από το Τμήμα Α.
- Αντίθετα, στα benign τα FP συγκεντρώνονται στις υψηλές ζώνες: 4/29 (≥0,98), 4/83 (0,90-0,98), 0/18 (<0,90).
  Να ελεγχθεί με το ablation `llm` (χωρίς ανάκτηση) αν η υψηλή ομοιότητα με malware ωθεί προς FP.

**False positives: ένα σαφές, επαναλαμβανόμενο μοτίβο**

- Και τα 8 FP έχουν **ακριβώς ένα** κακόβουλο Behavior Chain ανάμεσα σε πολλά (π.χ. psutil 1/94,
  oauth2client 1/70): συνέπεια του κανόνα «ένα `MALICIOUS` chain αρκεί».
- 6 από τα 8 είναι κώδικας του `setup.py` που εκτελείται στην εγκατάσταση:
  - 4 (frozendict, opencensus, fabric, opentelemetry-exporter-gcp-monitoring): το γνωστό νόμιμο μοτίβο
    ανάγνωσης της έκδοσης, `exec(open("<pkg>/version.py").read(), namespace)`.
  - crossplane: `os.system("{python} setup.py sdist bdist_wheel --universal")` (εντολή δημοσίευσης).
  - daff: εκτέλεση τοπικού script `make` κατά το build.
- Τα άλλα 2: psutil (`tempfile.NamedTemporaryFile` σε script εγκατάστασης του pip), oauth2client
  (`pickle.loads` σε μοντέλο του Django).
- **Αιτία**: το Behavior Chain δείχνει την ανάγνωση ως `open(...)`, χωρίς το όρισμα (όνομα αρχείου),
  οπότε το LLM δεν μπορεί να ξεχωρίσει το «exec του version.py» από το «exec ενός κρυμμένου payload» -
  και οι όμοιες ροές στο ευρετήριο είναι όντως κακόβουλες (ομοιότητα 0,99-1,0).
- Πιθανή βελτίωση (μελλοντική εργασία / v13): να περιλαμβάνονται στα κείμενα των κόμβων τα σταθερά
  ορίσματα των κλήσεων (π.χ. `open("pkg/version.py")`) - αλλαγή στο `find_flow.ql`/`readableExpr`,
  απαιτεί νέα ανάλυση CodeQL. Όχι αλλαγή στο prompt: χωρίς το όνομα αρχείου, ένας κανόνας «το exec στο
  setup.py είναι αθώο» θα έκρυβε πραγματικό malware.

**False negatives** (12) - να εξεταστούν αναλυτικά: `@bigid-ui`, `celery-flower`,
`celium-collateral-upgrade`, `dmclc`, `huzzleup`, `juk`, `lium-4.96`, `pyphetools`, `rasterkit` (80 chains),
`rblxtools`, `set-utils`, `set_utils`. Static misses (κανένα chain): 6 malware (1,4%).

**Στατιστική ισχύς**

- Το FPR στηρίζεται σε 130 benign με chains, γι' αυτό το διάστημα εμπιστοσύνης είναι φαρδύ (3,2-11,7%).
  Extra (v13): αξιολόγηση και στα ~3.200 νόμιμα πακέτα που το MalwareBench είχε σημάνει λανθασμένα ως
  malware («δύσκολα» benign) - θα σταθεροποιούσε την εκτίμηση του FPR.
- Οι κλάσεις δεν είναι ισορροπημένες (416 έναντι 130): να αναφέρονται μαζί με την accuracy και τα
  balanced accuracy / F1.

**Εκτέλεση**: ~2,5 ώρες για malware και benign παράλληλα (δύο τερματικά), 8 παράλληλες κλήσεις ανά πακέτο.

## Ablations (samples / policy / llm)

Συγκεντρωτικός πίνακας: `ablations.md`. Η σύγκριση γίνεται στα ίδια πακέτα και με το ίδιο ευρετήριο, οπότε
διαφέρει μόνο το περιεχόμενο των Τμημάτων Β/Γ του prompt.

### v12_samples - μόνο δείγματα malware (χωρίς βάση γνώσης ασφάλειας)

- Recall 96,6% [94,4-98,0], FPR **3,1%** [1,2-7,6], precision 99,0%, F1 97,8%, accuracy 96,7%, balanced
  accuracy 96,8%, end-to-end accuracy 95,9%. Όλα τα πακέτα πήραν τελική απόφαση.
- Σε σχέση με το `sum`: FP 8 → 4, FN 12 → 14. Ανά πακέτο:
  - benign που έπαψαν να είναι FP (5): oauth2client, crossplane, opentelemetry-exporter-gcp-monitoring,
    frozendict, opencensus· νέο FP (1): qtconsole (`exec` στο `setup.py`)· κοινά FP (3): psutil, daff, fabric.
  - malware που χάθηκαν (4): ansiicolor, moneyprinter-api, pohttp, ttensorflow-gpu· malware που πιάστηκαν
    μόνο εδώ (2): rblxtools, set-utils.
  - McNemar (ακριβές): benign 5 έναντι 1, p = 0,22· malware 4 έναντι 2, p = 0,69. Οι δύο διαμορφώσεις είναι
    στατιστικά ισοδύναμες σε συνολική απόδοση· διαφέρουν στο σημείο λειτουργίας (ευαισθησία έναντι FPR).
- **Ρόλος της βάσης γνώσης ασφάλειας: ανεβάζει την ευαισθησία.** Όταν το Τμήμα Γ περιέχει κανόνα που ονομάζει
  τη συμπεριφορά, το LLM τον χρησιμοποιεί ως ενίσχυση της ύποπτης ερμηνείας· χωρίς αυτόν, δέχεται πιο εύκολα
  μια αθώα εξήγηση. Παραδείγματα (ίδιο Behavior Chain, ίδιοι γείτονες στο Τμήμα Β):
  - pohttp: base64 → `__import__` στο `setup.py`. Με το GuardDog `threat_runtime_obfuscation_base64exec`:
    MALICIOUS· χωρίς πολιτικές: «setup scripts commonly … use base64», BENIGN.
  - ansiicolor: test που κατεβάζει binary από το Dropbox και το εκτελεί. Με το GuardDog
    `threat_process_download_exec`: MALICIOUS· χωρίς: «string literal used in tests», BENIGN.
  - moneyprinter-api, ttensorflow-gpu: εκτέλεση τοπικού script / `subprocess.Popen` στο `setup.py`. Με τα
    Semgrep `dangerous-os-exec` / `subprocess-injection`: MALICIOUS· χωρίς: «standard setup.py functionality».
  - frozendict (benign): `exec` του version file στο `setup.py`. Με το Bandit B102 (`exec`) και το Semgrep
    `exec-injection`: MALICIOUS· χωρίς: «standard build-time metadata/version extraction», BENIGN.
- **Το μοτίβο `exec(open(...).read())` στο `setup.py` είναι αμφίσημο από το Behavior Chain.** Το set-utils
  (malware) εκτελεί με ακριβώς τον ίδιο τρόπο το `para/about.py`, όπως τα νόμιμα frozendict/opencensus το
  αρχείο έκδοσης. Οι αποφάσεις σε αυτά τα πακέτα αλλάζουν ανάμεσα στις διαμορφώσεις, επιβεβαιώνοντας ότι η
  διάκριση απαιτεί το περιεχόμενο του αρχείου που εκτελείται (βλ. μελλοντική εργασία παραπάνω).
- Ζώνες ομοιότητας: ≥0,98 recall 232/235, FP 2/29· 0,90-0,98 recall 128/139, FP 2/83· <0,90 recall
  **42/42**, FP 0/18. Και χωρίς πολιτικές, το νέο malware (χωρίς κοντινό γείτονα) εντοπίζεται πλήρως.

### v12_policy - μόνο βάση γνώσης ασφάλειας (χωρίς δείγματα)

- Recall 96,2% [93,8-97,6], FPR 4,6% [2,1-9,7], precision 98,5%, F1 97,3%, accuracy 96,0%, balanced
  accuracy 95,8%, end-to-end accuracy 95,3%. Όλα τα πακέτα πήραν τελική απόφαση.
- Έλεγχοι εγκυρότητας: το Τμήμα Β είναι κενό («No similar malware found») και στα 16.488 Behavior Chains· οι
  διαδρομές αρχείων στο prompt είναι σχετικές με το πακέτο και στις δύο κλάσεις (`setup.py`,
  `azure/__init__.py`), χωρίς ίχνος της πηγής του δείγματος· οι λέξεις «malware»/«malicious» εμφανίζονται μόνο
  από το πρότυπο του prompt, ισόποσα στις δύο κλάσεις.
- Σε σχέση με το `sum`: malware 5 χάθηκαν / 1 κερδήθηκε (McNemar p = 0,22)· benign 4 FP διορθώθηκαν / 2 νέα
  (p = 0,69). Στατιστικά ισοδύναμο.
- FP (6): google-auth, opencensus, fabric, furl, opentelemetry-exporter-gcp-monitoring (όλα `exec` στο
  `setup.py`) και daff (`Subprocess.call`). Τα 5 από τα 6 είναι το μοτίβο `exec` του αρχείου έκδοσης, με
  ανακτημένους κανόνες Bandit B102 / Semgrep `exec-injection`: οι κανόνες για `exec` είναι αυτοί που ωθούν
  προς MALICIOUS, και χωρίς δείγματα.
- FN (16): @bigid-ui, celery-flower, celium-collateral-upgrade, colorfades, dmclc, easy-https, huzzleup,
  lightmock, lium-4.96, pantheon-agents, pyphetools, rasterkit, rblxtools, reuquests, set-utils, set_utils.
- Ζώνες ομοιότητας (από το `sum`): ≥0,98 recall 228/235, FP 4/29· 0,90-0,98 recall 130/139, FP 2/83· <0,90
  recall 42/42, FP 0/18. Οι γνωστές παραλλαγές εντοπίζονται και χωρίς να δει το LLM τα όμοια δείγματα.

Παρατηρήσεις:
- Στα benign το LLM ελέγχει μία-μία τις ανακτημένες πολιτικές απέναντι στον κώδικα και απορρίπτει όσες
  ταιριάζουν μόνο στο όνομα της κλήσης (π.χ. «Matches the API, but the data written is test attachment
  content»). Χωρίς Τμήμα Β δεν υπάρχει γείτονας malware με συγκεκριμένα tags, οπότε η απόφαση στηρίζεται
  αποκλειστικά στο Τμήμα Α.
- Τα fabric (`exec` στο `setup.py`, με Bandit B102 / Semgrep `exec-injection`) και daff είναι FP όπως στο
  `sum`: οι κανόνες για `exec`/`subprocess` ωθούν προς MALICIOUS και χωρίς δείγματα. Στο daff το chain είναι
  `Subprocess.call` στο `__init__.py` και η αιτιολόγηση μιλά για πιθανό command injection - το LLM συγχέει εδώ
  την ευπάθεια (που περιγράφει ο κανόνας Semgrep) με κακόβουλη πρόθεση.

### Συμφωνία των διαμορφώσεων: το σήμα βρίσκεται στο Behavior Chain

- Malware (416 με chains): 395 εντοπίζονται και από τις τρεις διαμορφώσεις (`sum`, `samples`, `policy`), 9
  από καμία· οι διαφορές αφορούν 12 πακέτα. Benign (130): 119 σωστά και στις τρεις, 2 FP και στις τρεις
  (fabric, daff)· οι διαφορές αφορούν 9 πακέτα.
- Το Τμήμα Α αρκεί για την πλειονότητα των αποφάσεων, γιατί το Behavior Chain κάνει ρητή την κακόβουλη
  συμπεριφορά. Στην αιτιολόγηση των 400 TP του `policy`, το LLM αναφέρει: διαρροή δεδομένων συστήματος ή
  διαπιστευτηρίων (hostname, username, tokens) 167, αποκωδικοποίηση/απόκρυψη (base64 κ.λπ.) 143, εκτέλεση κατά
  την εγκατάσταση 131, κατέβασμα και εκτέλεση 73, μη τεκμηριωμένο εξωτερικό προορισμό 74. Κατηγορία του
  κακόβουλου chain: network 156, process_exec 136, crypto_obfuscation 75, file_ops 33.
- Η ανάκτηση ρυθμίζει το σημείο λειτουργίας στα οριακά πακέτα: τα δείγματα μειώνουν τα FP (το LLM βλέπει ότι
  ο γείτονας δεν έχει συγκεκριμένα tags ή ότι η ροή είναι γενική), οι πολιτικές αυξάνουν την ευαισθησία
  (κανόνες που ονομάζουν τη συμπεριφορά).

### v12_llm - χωρίς ανάκτηση

- Recall 96,2% [93,8-97,6], FPR **0,8%** [0,1-4,2], precision 99,8%, F1 97,9%, accuracy 96,9%, balanced
  accuracy 97,7%, end-to-end accuracy 96,1%. Όλα τα πακέτα πήραν τελική απόφαση.
- FP (1): psutil (`shutil.rmtree` σε `scripts/internal/purge_installation.py`).
- FN (16): @bigid-ui, celery-flower, celium-collateral-upgrade, dmclc, huzzleup, juk, lium-4.96,
  pantheon-agents, pxhttp, pyphetools, pyshftuler, rasterkit, set-utils, set_utils, solana-web3-alt,
  ttensorflow-gpu.
- Τα FP των διαμορφώσεων με ανάκτηση που αφορούν `exec`/`subprocess` στο `setup.py` (fabric, frozendict,
  opencensus, daff κ.λπ.) είναι εδώ BENIGN με confidence 0,90-0,95 («ordinary setup.py functionality such as
  reading a requirements file, version file…»).
- Ζώνες ομοιότητας (από το `sum`): ≥0,98 recall 231/235, FP 0/29· 0,90-0,98 recall 127/139, FP 1/83· <0,90
  recall 42/42, FP 0/18.

## Σύνθεση των ablations: τι προσφέρει η ανάκτηση

| | `sum` | `samples` | `policy` | `llm` |
|---|---|---|---|---|
| Recall | **97,1%** (404) | 96,6% (402) | 96,2% (400) | 96,2% (400) |
| FPR | 6,2% (8) | 3,1% (4) | 4,6% (6) | **0,8%** (1) |
| F1 | 97,6% | 97,8% | 97,3% | **97,9%** |
| Balanced accuracy | 95,5% | 96,8% | 95,8% | **97,7%** |
| TP με SSVC `ACT` | **343** | 339 | 301 | 313 |
| FP με SSVC `ACT` | 1 | 1 | 0 | 1 |

**1. Το Behavior Chain φέρει το κύριο σήμα.** 392 από τα 416 malware εντοπίζονται και από τις τέσσερις
διαμορφώσεις, 9 από καμία· 119 από τα 130 benign είναι σωστά και στις τέσσερις, κανένα δεν είναι FP σε όλες.
Οι διαμορφώσεις διαφέρουν σε 15 malware και 11 benign. Στη ζώνη «νέο» (<0,90) το recall είναι 42/42 σε όλες.

**2. Η ανάκτηση εντοπίζει malware κρυμμένο μέσα σε νόμιμο κώδικα.** Πιάνονται από όλες τις διαμορφώσεις με
ανάκτηση, όχι χωρίς αυτήν:
- pyshftuler (152 chains, αντίγραφο του `requests`): base64 → `compile` → `exec` στο `models.py`. Χωρίς
  ανάκτηση το LLM το αποδίδει σε «documented functionality of the requests library» (BENIGN, 0,95)· με
  ανάκτηση βρίσκει τον ίδιο κώδικα στο ευρετήριο (ομοιότητα 1,0) και γείτονα με tag `data_exfiltration`.
- pxhttp: base64 → `__import__` στο `setup.py`. Χωρίς ανάκτηση: «common legitimate setup.py patterns» (0,7).
- solana-web3-alt: το `setup.py` εκτελεί κρυφό `trigger.py`. Με ανάκτηση ο γείτονας pylogfmt (0,92, tags
  `supply_chain_downloader`, `spyware_infostealer`) περιγράφει ακριβώς το ίδιο μοτίβο.
- Επιπλέον pantheon-agents (ανάγνωση διαπιστευτηρίων Gemini CLI, γείτονας με tag `credential_stealer`) και
  ttensorflow-gpu.
Σε αυτά, το LLM μόνο του εκλογικεύει τη συμπεριφορά μέσα από τη νόμιμη λειτουργία του πακέτου· το
ανακτημένο δείγμα με συγκεκριμένα tags ανατρέπει την εκλογίκευση.

**3. Η ανάκτηση αυξάνει τη βεβαιότητα στο πραγματικό malware.** Με το πλήρες σύστημα, 343/404 TP (85%)
παίρνουν την υψηλότερη απόφαση SSVC `ACT`, έναντι 313/400 (78%) χωρίς ανάκτηση, με τον ίδιο αριθμό FP σε `ACT`
(1). Τα υπόλοιπα FP του `sum` είναι `ATTEND` (έλεγχος από αναλυτή), όχι αυτόματη αντίδραση.

**4. Η ανάκτηση ωθεί προς MALICIOUS τα αμφίσημα μοτίβα εγκατάστασης.** Όλα τα FP των διαμορφώσεων με
ανάκτηση που λείπουν από το `llm` είναι `exec`/`subprocess` στο `setup.py` ή σε scripts: οι γείτονες malware
έχουν το ίδιο σχήμα κώδικα και οι κανόνες ονομάζουν το ίδιο API. `sum` έναντι `llm` στα benign: 0 έναντι 7,
McNemar p = 0,016 - η μόνη στατιστικά σημαντική διαφορά ανάμεσα στις διαμορφώσεις.

**5. Τεκμηρίωση.** Στο `sum` κάθε απόφαση MALICIOUS (412/412) συνοδεύεται από το πιο όμοιο γνωστό malware και
από συγκεκριμένους κανόνες ασφάλειας (ATT&CK/CWE/CAPEC/Bandit/GuardDog/Semgrep)· στο `llm` καμία.

**Στατιστικά (McNemar, έναντι `llm`)**: `sum` malware 5/1 p = 0,22, benign 0/7 p = 0,016, σύνολο 5/8 p = 0,58·
`samples` σύνολο 5/6 p = 1,0· `policy` σύνολο 6/11 p = 0,33. Σε συνολική ακρίβεια οι τέσσερις διαμορφώσεις
είναι ισοδύναμες· διαφέρουν στο είδος των λαθών και στη βεβαιότητα.

**Συμπέρασμα για το Κεφάλαιο 5**: η ανάκτηση λειτουργεί ως ρυθμιστής ευαισθησίας - εντοπίζει malware που
μιμείται νόμιμο κώδικα και δίνει πιο αποφασιστικές και τεκμηριωμένες αποφάσεις, με κόστος περισσότερους
συναγερμούς ελέγχου σε αμφίσημα μοτίβα εγκατάστασης. Βελτίωση για μελλοντική εργασία: σταθερά ορίσματα στα
Behavior Chains (π.χ. `open("pkg/version.py")`), ώστε οι γείτονες και οι κανόνες να μην ταιριάζουν μόνο στο
σχήμα της κλήσης.

"""
thesis_tables.py - LaTeX tables and figures for Chapters 4-5 of the thesis, generated from the
dataset files and the final reports (results/<MAIN>_*, MAIN = v14), so that no number is copied by hand.

Writes to results/analysis/latex/:
  dataset_sources.tex      malware samples per source: collected, excluded, train / test
  dataset_sets.tex         final sets (incl. the obfuscated copies): packages, with Behavior Chains, chains
  dataset_attack_types.tex attack-type tags of the selected malware samples
  policy_sources.tex       entries of the security knowledge base per source (dataset/policy_rules.json)
  main_metrics.tex         metrics of the full system with 95% Wilson intervals
  ablations.tex            metrics of the four configurations (LLM stage + end-to-end)
  strata.tex               recall / false positives per similarity stratum and configuration
  agreement.tex            agreement of the four configurations per package
  ssvc.tex                 SSVC priority of true / false positives per configuration
  act_only.tex             operating point when only the ACT priority raises an alert
  confidence.tex           self-reported confidence of true / false positives per configuration (+ AUROC)
  false_positives.tex      false positives of the full system (package, chains, flagged chain)
  benign_groups.tex        false positive rate on the curated and on the randomly sampled benign packages
  dependencies.tex         verdicts without / with the dependency-graph check
  natural_obfuscation.tex  detection of malware that decodes and executes code, and of the rest
  obfuscation.tex          obfuscated copies (levels A, B) next to the same packages unobfuscated
  comparison.tex           comparison with the tools evaluated in IntelGuard (Table 1 of that paper)
  rag_literature.tex       accuracy / FPR without and with retrieval: IntelGuard RQ4 next to ours
  local_model.tex          v13: the local model (LM Studio) and DeepSeek on the same subset (v12 data)
  confusion_sum.tex        figure: confusion matrix of the full system (images/confusion_sum.png)
  confusion_grid.tex       figure: the four confusion matrices (images/confusion_<config>.png)

Copy the .tex files to Thesis_text/chapters/generated/ (the chapters \\input them) and images/*.png to
Thesis_text/images/chapter5/ (the figures are PNG images drawn from TikZ with xelatex + PyMuPDF).
The generated text (captions, headers, numbers with a decimal comma) is in Greek, the language of the
thesis; everything else in this file is in English.
Usage: python3 results/thesis_tables.py
"""
import glob
import json
import os
import re
import shutil
import sys
from collections import Counter
from statistics import median

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import results_analysis as ra  # noqa: E402  (same definitions of metrics and strata)
from utils import is_pure_vendor_chain, source_name  # noqa: E402  (dataset/preparation, on sys.path via results_analysis)

ROOT = ra.ROOT
DS = os.path.join(ROOT, "dataset")
OUT = os.path.join(ra.OUT, "latex")
IMG = os.path.join(OUT, "images")   # the figures as PNG -> Thesis_text/images/chapter5/
IMG_REF = "images/chapter5"          # their path in the thesis
CONFIGS = ["sum", "samples", "policy", "llm"]
MAIN = "v14"   # the evaluation of Chapter 5 (the local-model table keeps v12, the data that model ran on)
TAGS = [f"{MAIN}_{c}" for c in CONFIGS]
OBF = [("A", "malware"), ("A", "benign"), ("B", "malware"), ("B", "benign")]
# A package "decodes and executes" (natural obfuscation) when one of its Behavior Chains is a decoding call
# and another executes code or commands (the process_exec category).
DECODE_API = re.compile(r"(b64decode|b32decode|b85decode|a85decode|decodebytes|decompress|marshal\.loads|fromhex|"
                        r"unhexlify|codecs\.decode|b64d)\b")
# Short Greek names of the configurations, as used in the thesis text.
NAME = {"sum": "Πλήρες σύστημα", "samples": "Μόνο δείγματα", "policy": "Μόνο πολιτικές", "llm": "Χωρίς RAG"}
# Readable names of the sample sources (first directory of each sample's path under THESIS_SOURCES_DIR).
SOURCE_LABEL = {
    "pypi_malregistry": "pypi\\_malregistry~\\cite{guo2023empirical}",
    "pypi": "MalwareBench (PyPI)~\\cite{malwarebench_pypi}",
    "malware_samples": "Datadog Malicious Software Packages~\\cite{datadog_malicious}",
    "malicious-software-packages-dataset": "Datadog Malicious Software Packages~\\cite{datadog_malicious}",
    "maloss-samples": "MalOSS~\\cite{duan2021measuring}",
}
# IntelGuard, Table 1 "Detection Performance Comparison on PyPI" (ge2026bridging):
# tool -> (accuracy, precision, recall, F1), in %.
INTELGUARD_TABLE1 = [
    ("Bandit4Mal", 28.65, 34.58, 47.90, 40.17), ("GuardDog", 87.30, 91.54, 82.20, 86.62),
    ("OSSGadget", 51.90, 51.10, 87.90, 64.63), ("PyPIWarehouse", 53.25, 51.69, 99.30, 67.99),
    ("SocketAI", 90.30, 93.06, 87.10, 89.98), ("SAP-DT", 60.90, 90.07, 24.50, 38.52),
    ("SAP-RF", 88.95, 98.27, 79.30, 87.77), ("SAP-XGB", 66.30, 92.89, 35.30, 51.16),
    ("MalGuard-DT", 90.35, 100.00, 80.70, 89.32), ("MalGuard-MLP", 94.45, 99.89, 89.00, 94.13),
    ("MalGuard-NB", 63.35, 98.19, 27.20, 42.60), ("MalGuard-RF", 90.15, 100.00, 80.30, 89.07),
    ("MalGuard-SVM", 94.75, 99.89, 89.60, 94.46), ("MalGuard-XGB", 89.65, 100.00, 79.30, 88.46),
    ("IntelGuard", 99.00, 99.49, 98.50, 98.99),
]
# IntelGuard, RQ4 "Knowledge Contribution" (ge2026bridging): direct GPT-4o-mini analysis without retrieved
# knowledge vs IntelGuard - (setting, accuracy without, FPR without, accuracy with, FPR with), in %.
INTELGUARD_RQ4 = [("PyPI", 96.99, 2.11, 99.00, 0.50), ("συγκεκαλυμμένος κώδικας", 52.82, None, 96.50, None)]


def num(x, digits=1):
    """Greek number format: decimal comma, thousands dot (1.692 / 97,1)."""
    if isinstance(x, int):
        return f"{x:,}".replace(",", ".")
    return f"{x:.{digits}f}".replace(".", ",")


def p(x, digits=1):
    """Percentage for LaTeX (97,1\\%)."""
    return num(x, digits) + "\\%"


def ci(pair):
    return f"[{num(pair[0])}--{num(pair[1])}]"


def tikz_png(name, tikz):
    """
    Compile a TikZ drawing with the font of the thesis and save it as a PNG (300 dpi, with its real size) in
    OUT/images/, so that the thesis includes an image (it also compiles on Overleaf without TikZ figures).
    """
    import subprocess
    import tempfile
    import pymupdf
    xelatex = shutil.which("xelatex") or "/Library/TeX/texbin/xelatex"
    doc = ["\\documentclass[border=2pt]{standalone}", "\\usepackage{fontspec}",
           "\\setmainfont[Mapping=tex-text]{Times New Roman}", "\\usepackage{tikz}", "\\begin{document}"]
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "fig.tex"), "w", encoding="utf-8") as f:
            f.write("\n".join(doc + tikz + ["\\end{document}"]))
        subprocess.run([xelatex, "-interaction=nonstopmode", "-halt-on-error", "fig.tex"], cwd=d,
                       capture_output=True, check=True)
        pix = pymupdf.open(os.path.join(d, "fig.pdf"))[0].get_pixmap(dpi=300)
        pix.set_dpi(300, 300)
        os.makedirs(IMG, exist_ok=True)
        pix.save(os.path.join(IMG, f"{name}.png"))


def write(name, lines):
    os.makedirs(OUT, exist_ok=True)
    head = "% Generated by results/thesis_tables.py - do not edit by hand.\n"
    open(os.path.join(OUT, name), "w", encoding="utf-8").write(head + "\n".join(lines) + "\n")


def table(caption, label, spec, header, rows, note=None, size="\\small", sep=None):
    """A floating table with horizontal rules only (hline), in the style of Chapter 3."""
    out = ["\\begin{table}[H]", "\\centering", size] + ([f"\\setlength{{\\tabcolsep}}{{{sep}}}"] if sep else []) + [
           f"\\begin{{tabular}}{{{spec}}}", "\\hline",
           header + " \\\\", "\\hline"]
    out += [r + " \\\\" if not r.startswith("\\hline") else r for r in rows]
    out += ["\\hline", "\\end{tabular}"]
    if note:
        out.append(f"\\par\\smallskip{{\\footnotesize {note}}}")
    out += [f"\\caption{{{caption}}}", f"\\label{{{label}}}", "\\end{table}"]
    return out


# ----------------------------------------------------------------------------- dataset (Chapter 4)
def dataset_tables():
    matched = json.load(open(os.path.join(DS, "malware_dataset_matched.json"), encoding="utf-8"))
    src = {}
    for e in matched:
        src.setdefault(e["package_name"], source_name(e.get("source_code_path") or "") or "?")
    fp = json.load(open(os.path.join(DS, "excluded_malwarebench_false_positive.json"), encoding="utf-8"))
    fp_names = set(fp.get("false_positive", [])) | set(fp.get("mixed_versions", []))
    no_payload = json.load(open(os.path.join(DS, "excluded_no_payload_packages.json"), encoding="utf-8"))
    no_payload = set(no_payload if isinstance(no_payload, list) else no_payload.get("packages", no_payload))
    train, test = ra.names(os.path.join(DS, "rag_train")), ra.names(ra.MAL_DIR)
    group = lambda s: SOURCE_LABEL.get(s, s)
    order = []
    for s in ("pypi_malregistry", "pypi", "malware_samples", "malicious-software-packages-dataset", "maloss-samples"):
        if group(s) not in order:
            order.append(group(s))
    count = lambda names: Counter(group(src.get(n, "?")) for n in names)
    label_names = fp_names & set(src)
    no_payload_names = (no_payload & set(src)) - label_names
    collected, lab, npc = count(src), count(label_names), count(no_payload_names)
    trc, tec = count(train), count(test)
    # everything else was analysed but not selected (same code as a selected package, campaign cap,
    # sampling of the packages without chains), or its static analysis did not complete
    rest = {g: collected[g] - lab[g] - npc[g] - trc[g] - tec[g] for g in order}
    report = json.load(open(os.path.join(DS, "final_dataset_report.json"), encoding="utf-8"))
    # samples added later to the evaluation set only (add_test_samples.py): the ones that reached the
    # static analysis count as analysed, the added ones as selected
    added = json.load(open(os.path.join(DS, "added_test_samples.json"), encoding="utf-8"))["decisions"]
    before_analysis = ("excluded: legitimate MalwareBench package", "excluded: no payload code (payload_scan)",
                       "excluded: not analysed")
    analysed = report["total_analyzed_samples"] + sum(d not in before_analysis for d in added.values())
    selected = report["total_selected"] + sum(d == "added" for d in added.values())
    no_analysis = len(src) - len(label_names) - len(no_payload_names) - analysed
    not_selected = analysed - selected
    assert sum(rest.values()) == no_analysis + not_selected, "the sample accounting does not add up"
    rows = [f"{g} & {num(collected[g])} & {num(lab[g])} & {num(npc[g])} & {num(rest[g])} & {num(trc[g])} & {num(tec[g])}"
            for g in order]
    rows += ["\\hline", f"Σύνολο & {num(len(src))} & {num(len(label_names))} & {num(len(no_payload_names))} & "
             f"{num(sum(rest.values()))} & {num(len(train))} & {num(len(test))}"]
    col = lambda w: f">{{\\raggedleft\\arraybackslash}}p{{{w}\\linewidth}}"
    write("dataset_sources.tex", table(
        "Δείγματα κακόβουλων πακέτων ανά πηγή, από τη συλλογή μέχρι το τελικό σύνολο: κάθε γραμμή αθροίζει "
        "στο πλήθος των δειγμάτων της πηγής.", "tab:dataset_sources",
        "|>{\\raggedright\\arraybackslash}p{0.25\\linewidth}|"
        + "|".join(col(w) for w in (0.08, 0.08, 0.12, 0.08, 0.09, 0.10)) + "|",
        "Πηγή & Δείγματα & Λάθος ετικέτα & Χωρίς κακόβουλο κώδικα & Εκτός επιλογής & Ευρετήριο & Αξιολόγηση", rows,
        note="Λάθος ετικέτα: νόμιμα πακέτα με ετικέτα malware· χωρίς κακόβουλο κώδικα: δείγματα χωρίς κανένα σήμα "
             f"κακόβουλης λειτουργικότητας. Εκτός επιλογής: {num(not_selected)} δείγματα που αναλύθηκαν αλλά δεν "
             "επιλέχθηκαν (ίδιος κώδικας με ήδη επιλεγμένο πακέτο, όριο πέντε πακέτων ανά καμπάνια, δειγματοληψία "
             f"των πακέτων χωρίς Behavior Chains) και {num(no_analysis)} δείγματα των οποίων η στατική ανάλυση δεν "
             "ολοκληρώθηκε.", size="\\footnotesize"))

    # final sets: packages / with chains / chains, from the chains files themselves
    meta = json.load(open(os.path.join(DS, "indexes", "rag_index", "metadata.json"), encoding="utf-8"))
    index_chains = len(meta) if isinstance(meta, list) else len(meta.get("entries", meta))

    def chain_counts(folder):
        """Chains per package that the LLM evaluates (pure-vendor chains are skipped, as in query_rag.py)."""
        out = []
        for f in sorted(glob.glob(os.path.join(folder, "*.json"))):
            if not os.path.basename(f).startswith("_"):
                chs = json.load(open(f, encoding="utf-8")).get("behavior_chains") or []
                out.append(sum(not is_pure_vendor_chain(c) for c in chs))
        return out
    rows = [f"Ευρετήριο κακόβουλων δειγμάτων (\\textit{{rag\\_train}}) & {num(len(train))} & -- & {num(index_chains)}"]
    for label, folder in [("Αξιολόγηση: κακόβουλα", ra.MAL_DIR), ("Αξιολόγηση: νόμιμα", ra.BEN_DIR)] + [
            (f"Συγκάλυψη {lvl}: {'κακόβουλα' if cls == 'malware' else 'νόμιμα'}", os.path.join(DS, "obfuscated", f"{lvl}_{cls}"))
            for lvl, cls in OBF]:
        cc = chain_counts(folder)
        rows.append(f"{label} & {num(len(cc))} & {num(sum(1 for c in cc if c))} & {num(sum(cc))}")
    write("dataset_sets.tex", table(
        "Τα τελικά σύνολα δεδομένων.", "tab:dataset_sets", "|l|r|r|r|",
        "Σύνολο & Πακέτα & Με Behavior Chains & Behavior Chains", rows))

    # attack-type tags of the selected samples: those of the index build (attack_type_tags.json) and, for the
    # samples added later, the same tagger on their description
    import attack_type_tagger as att  # noqa: E402  (dataset/preparation)
    from backfill_osv_descriptions import OSV_DIR, extract_description  # noqa: E402
    tags = json.load(open(os.path.join(DS, "attack_type_tags.json"), encoding="utf-8"))
    by_name = {e["package_name"]: e for e in matched}
    osv = {re.sub(r"[-_.]+", "-", d).lower(): d for d in os.listdir(OSV_DIR)} if os.path.isdir(OSV_DIR) else {}
    popular = att.load_popular_packages()
    dist = Counter()
    for n in train | test:
        if n in tags:
            dist.update(tags[n]["attack_type_tags"])
            continue
        e = by_name.get(n, {})
        desc = (e.get("description") or "").strip()
        key = re.sub(r"[-_.]+", "-", n).lower()
        if not desc and key in osv:
            desc = extract_description(os.path.join(OSV_DIR, osv[key]))
        t = att.detect_keyword_tags(f"{e.get('summary', '')} {desc}")
        if att.detect_typosquat(n, popular):
            t.append("typosquatting")
        dist.update(sorted(set(t)) or ["unclassified"])
    rows = [f"\\texttt{{{k.replace('_', '\\_')}}} & {num(v)}" for k, v in sorted(dist.items(), key=lambda x: (-x[1], x[0]))]
    write("dataset_attack_types.tex", table(
        f"Ετικέτες τύπου επίθεσης των {num(len(train | test))} επιλεγμένων κακόβουλων πακέτων "
        "(ένα πακέτο μπορεί να φέρει περισσότερες από μία ετικέτες).", "tab:attack_types", "|l|r|",
        "Ετικέτα & Πακέτα", rows))


# Greek labels (with citations) of the knowledge-base sources, by the "source" field of policy_rules.json.
POLICY_LABEL = {
    "MITRE ATT&CK": "MITRE ATT\\&CK (τεχνικές)~\\cite{strom2018attack,mitre_attack}",
    "CAPEC Attack Patterns": "CAPEC (μοτίβα επίθεσης)~\\cite{mitre_capec}",
    "CWE Database": "CWE (κατηγορίες αδυναμιών)~\\cite{mitre_cwe}",
    "Semgrep Community Rules": "Κανόνες κοινότητας Semgrep~\\cite{semgrep_rules}",
    "Bandit (PyCQA) Security Checks": "Κανόνες Bandit (PyCQA)~\\cite{bandit}",
    "GuardDog (Datadog) Detection Rules": "Κανόνες ανίχνευσης GuardDog (Datadog)~\\cite{guarddog}",
    "GuardDog (Datadog) Metadata Heuristics": "Μεταδεδομένα ευρετικών GuardDog~\\cite{guarddog}",
    "SLSA v0.1 Threat Model": "Μοντέλο απειλών SLSA v0.1~\\cite{slsa_v01_threats}",
    "SLSA Framework": "Πλαίσιο SLSA~\\cite{slsa}",
    "OWASP Top 10:2025": "OWASP Top 10:2025~\\cite{owasp_top10_2025}",
    "OWASP Software Component Verification Standard": "OWASP Software Component Verification Standard~\\cite{owasp_scvs}",
    "OWASP Top 10 CI/CD Security Risks": "OWASP Top 10 CI/CD Security Risks~\\cite{owasp_cicd}",
    "OWASP Secure Coding Practices": "OWASP Secure Coding Practices~\\cite{owasp_scp}",
    "Threat Hunting Heuristics": "Ευρετικές μέθοδοι threat hunting (επιμέλεια)",
    "Package Registry Acceptable-Use Policies": "Πολιτικές αποδεκτής χρήσης αποθετηρίων (PyPI/npm/GitHub)~\\cite{pypi_aup,npm_terms,github_aup}",
}


def policy_label(source):
    """Greek label of a knowledge-base source: the POLICY_LABEL key that its name starts with."""
    key = max((k for k in POLICY_LABEL if source.startswith(k)), key=len, default=None)
    if key is None:
        sys.exit(f"[!] No label for the knowledge-base source {source!r} - add it to POLICY_LABEL")
    return POLICY_LABEL[key]


def knowledge_base_table():
    """Entries of the security knowledge base (dataset/policy_rules.json) per source."""
    rules = json.load(open(os.path.join(DS, "policy_rules.json"), encoding="utf-8"))
    counts = Counter(policy_label(r["source"]) for r in rules)
    rows = [f"{label} & {num(n)}" for label, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
    rows += ["\\hline", f"Σύνολο & {num(len(rules))}"]
    write("policy_sources.tex", table(
        "Σύνθεση της βάσης δομημένης γνώσης ασφάλειας ανά πηγή.", "tab:policy_sources", "|l|r|",
        "Πηγή & Εγγραφές", rows))


def subset_rows(runs, subset):
    """Rows (model, configuration, confusion matrix and metrics) of runs on the subset, one \\hline per model."""
    rows = []
    for model, tag, conf in runs:
        R = ra.load(tag)
        flag = lambda n: R[n]["final_verdict"] in ra.POSITIVE
        tp = sum(flag(n) for n in subset["malware"]); fn = len(subset["malware"]) - tp
        fp = sum(flag(n) for n in subset["benign"]); tn = len(subset["benign"]) - fp
        rec, fpr, prec = 100 * ra.div(tp, tp + fn), 100 * ra.div(fp, fp + tn), 100 * ra.div(tp, tp + fp)
        f1 = ra.div(2 * prec * rec, prec + rec)
        acc = 100 * ra.div(tp + tn, tp + fn + fp + tn)
        if rows and model != rows[-1][0]:
            rows.append(("\\hline",))
        rows.append((model, f"{model} & {NAME.get(conf, conf)} & {tp} & {fn} & {fp} & {tn} & {p(rec)} & {p(fpr)} & "
                            f"{p(prec)} & {p(f1)} & {p(acc)}"))
    return [r[-1] if len(r) == 2 else r[0] for r in rows]


def local_model_table():
    """v13: the local model (LM Studio) next to DeepSeek on the same subset (dataset/local_subset.json).
    The local model ran on the v12 data, so it is compared with the v12 DeepSeek runs."""
    if not all(os.path.isdir(os.path.join(ROOT, "results", t)) for t in ("v13_sum", "v13_llm")):
        print("[!] results/v13_sum or v13_llm is missing - local_model.tex skipped")
        return
    subset = json.load(open(os.path.join(DS, "local_subset.json"), encoding="utf-8"))
    runs = [("DeepSeek (API)", "v12_sum", "sum"), ("DeepSeek (API)", "v12_llm", "llm"),
            ("gemma-4-26b-a4b (τοπικά)", "v13_sum", "sum"), ("gemma-4-26b-a4b (τοπικά)", "v13_llm", "llm")]
    rows = subset_rows(runs, subset)
    write("local_model.tex", table(
        f"Το τοπικό μοντέλο και το DeepSeek στο υποσύνολο αξιολόγησης του τοπικού μοντέλου "
        f"({num(len(subset['malware']))} κακόβουλα και {num(len(subset['benign']))} νόμιμα πακέτα), με το Πλήρες "
        "σύστημα και χωρίς RAG, και με την αναπαράσταση των Behavior Chains χωρίς τα σταθερά ορίσματα για τα "
        "δύο μοντέλα.", "tab:local_model", "|l|l|r|r|r|r|r|r|r|r|r|",
        "Μοντέλο & Διαμόρφωση & TP & FN & FP & TN & Recall & FPR & Prec. & F1 & Acc.",
        rows, size="\\footnotesize", sep="3.5pt"))


# ----------------------------------------------------------------------------- results (Chapter 5)
def extra_tables(reports, scored, lab, res):
    """The v14 tables beyond the metrics: ACT-only operating point, curated / sampled benign packages,
    dependency-graph check, natural and artificial obfuscation."""
    pos = lambda c, n: reports[c][n]["final_verdict"] in ra.POSITIVE
    mal = [n for n in scored if lab[n] == "malicious"]
    ben = [n for n in scored if lab[n] == "benign"]
    frac = lambda k, n: f"{k}/{n}" if n else "--"

    # operating point when only the ACT priority raises an alert
    def act(c, n):
        return any(ch.get("llm_evaluation", {}).get("verdict") in ra.POSITIVE
                   and ch["llm_evaluation"].get("ssvc_decision") == "ACT"
                   for ch in reports[c][n].get("chain_details", []))
    rows = []
    for c in CONFIGS:
        tp, fp = sum(pos(c, n) for n in mal), sum(pos(c, n) for n in ben)
        ta, fa = sum(act(c, n) for n in mal), sum(act(c, n) for n in ben)
        rows.append(f"{NAME[c]} & {p(100 * tp / len(mal))} & {p(100 * fp / len(ben))} & "
                    f"{p(100 * ta / len(mal))} & {p(100 * fa / len(ben))}")
    write("act_only.tex", table(
        "Recall και FPR όταν συναγερμό σημαίνει κάθε απόφαση \\texttt{MALICIOUS} και όταν τον σημαίνει μόνο το "
        "επίπεδο προτεραιότητας \\texttt{ACT} (πακέτα με Behavior Chains).", "tab:act_only", "|l|r|r|r|r|",
        "Διαμόρφωση & \\multicolumn{2}{c|}{Κάθε \\texttt{MALICIOUS}} & \\multicolumn{2}{c|}{Μόνο \\texttt{ACT}}",
        ["& Recall & FPR & Recall & FPR", "\\hline"] + rows))

    # false positive rate on the curated and on the randomly sampled popular benign packages
    sel = json.load(open(os.path.join(DS, "preparation", "benign_extra_selection.json"), encoding="utf-8"))
    sampled = {x["package"] for x in sel["packages"]}
    groups = [("Επιλεγμένα", [n for n in ben if n not in sampled]), ("Τυχαία δημοφιλή", [n for n in ben if n in sampled])]
    rows = []
    for c in CONFIGS:
        cells = []
        for _, S in groups:
            k = sum(pos(c, n) for n in S)
            cells.append(f"{frac(k, len(S))} & {p(100 * ra.div(k, len(S)))} & {ci(ra.wilson(k, len(S)))}")
        rows.append(f"{NAME[c]} & " + " & ".join(cells))
    write("benign_groups.tex", table(
        "False positives στα επιλεγμένα νόμιμα πακέτα (γνωστές βιβλιοθήκες με ευαίσθητες λειτουργίες) και στα "
        "τυχαία επιλεγμένα δημοφιλή πακέτα του PyPI (πακέτα με Behavior Chains), με διάστημα εμπιστοσύνης 95\\% "
        "(Wilson).", "tab:benign_groups", "|l|r|r|c|r|r|c|",
        f"Διαμόρφωση & \\multicolumn{{3}}{{c|}}{{{groups[0][0]}}} & \\multicolumn{{3}}{{c|}}{{{groups[1][0]}}}",
        ["& FP & FPR & Δ.Ε. 95\\% & FP & FPR & Δ.Ε. 95\\%", "\\hline"] + rows, size="\\footnotesize"))

    # verdicts without / with the dependency-graph check, end-to-end (packages without chains included)
    allm, allb = ra.names(ra.MAL_DIR), ra.names(ra.BEN_DIR)
    rows, via_deps = [], {}
    for c in CONFIGS:
        R = reports[c]
        v0 = lambda n: R[n]["final_verdict"] in ra.POSITIVE
        v1 = lambda n: R[n].get("final_verdict_with_dependencies", R[n]["final_verdict"]) in ra.POSITIVE
        M, B = [n for n in allm if n in R], [n for n in allb if n in R]
        tp0, tp1 = sum(map(v0, M)), sum(map(v1, M))
        fp0, fp1 = sum(map(v0, B)), sum(map(v1, B))
        for n in M + B:
            if v1(n) and not v0(n):
                via_deps[n] = sorted({f["dependency"] for f in R[n].get("dependency_findings") or []})
        rows.append(f"{NAME[c]} & {tp0}/{len(M)} & {tp1}/{len(M)} & {fp0}/{len(B)} & {fp1}/{len(B)}")
    note = "; ".join(f"{n.replace('_', '\\_')} ({', '.join(d.replace('_', '\\_') for d in deps)})"
                     for n, deps in sorted(via_deps.items()))
    write("dependencies.tex", table(
        "Αποφάσεις χωρίς και με τον έλεγχο του γράφου εξαρτήσεων, σε όλα τα πακέτα των συνόλων αξιολόγησης "
        "(και σε όσα δεν έχουν Behavior Chains).", "tab:dependencies", "|l|r|r|r|r|",
        "Διαμόρφωση & \\multicolumn{2}{c|}{Εντοπισμένα κακόβουλα} & \\multicolumn{2}{c|}{False positives}",
        ["& Χωρίς & Με εξαρτήσεις & Χωρίς & Με εξαρτήσεις", "\\hline"] + rows,
        note=("Πακέτα που εντοπίστηκαν μόνο μέσω των εξαρτήσεών τους (κακόβουλες εξαρτήσεις): " + note + ".")
        if note else None))

    # package size: similarity, detection and false positives by number of Behavior Chains (the package
    # similarity is a maximum over the chains, and the package verdict is MALICIOUS if any chain is)
    from scipy.stats import spearmanr
    nch = lambda n: reports["sum"][n].get("total_chains_analyzed") or 0
    msim = lambda n: ra.max_similarity(reports["sum"][n])
    rho = {cls: spearmanr([nch(n) for n in S], [msim(n) for n in S])[0] for cls, S in (("mal", mal), ("ben", ben))}
    rows = []
    for label, lo, hi in (("1--10", 1, 10), ("11--100", 11, 100), ("$>100$", 101, 10 ** 9)):
        M = [n for n in mal if lo <= nch(n) <= hi]
        B = [n for n in ben if lo <= nch(n) <= hi]
        cells = " & ".join(f"{frac(sum(pos(c, n) for n in M), len(M))} / {sum(pos(c, n) for n in B)}" for c in CONFIGS)
        rows.append(f"{label} & {len(M)} & {len(B)} & {num(median([msim(n) for n in M]), 3)} & "
                    f"{num(median([msim(n) for n in B]), 3)} & {cells}")
    write("chain_buckets.tex", table(
        "Αποτελέσματα ανά πλήθος Behavior Chains του πακέτου: διάμεση μέγιστη ομοιότητα με το ευρετήριο και, σε "
        "κάθε διαμόρφωση, κακόβουλα πακέτα που εντοπίστηκαν / ψευδώς θετικά. Συσχέτιση Spearman ανάμεσα στο "
        f"πλήθος των Behavior Chains και στη μέγιστη ομοιότητα: {num(rho['mal'], 2)} στα κακόβουλα και "
        f"{num(rho['ben'], 2)} στα νόμιμα πακέτα.", "tab:chain_buckets",
        "|l|r|r|r|r|" + "|".join([">{\\centering\\arraybackslash}p{1.35cm}"] * 4) + "|",
        "Chains & Κακόβ. & Νόμιμα & Ομοιότ. (κακόβ.) & Ομοιότ. (νόμιμα) & " + " & ".join(NAME[c] for c in CONFIGS),
        rows, size="\\footnotesize", sep="3pt"))

    # natural obfuscation: malware that decodes and executes code (a decoding chain + an execution chain)
    def decodes_and_executes(n):
        chs = reports["sum"][n].get("chain_details", [])
        return (any(DECODE_API.search(ch.get("sensitive_api") or "") for ch in chs)
                and any(ch.get("category") == "process_exec" for ch in chs))
    natural = [n for n in mal if decodes_and_executes(n)]
    other = [n for n in mal if n not in set(natural)]
    rows = [f"{label} & {len(S)} & " + " & ".join(f"{p(100 * ra.div(sum(pos(c, n) for n in S), len(S)))}" for c in CONFIGS)
            for label, S in (("Αποκωδικοποίηση και εκτέλεση", natural), ("Υπόλοιπα", other))]
    write("natural_obfuscation.tex", table(
        "Recall στα κακόβουλα πακέτα που αποκωδικοποιούν και εκτελούν κώδικα ή εντολές (ένα Behavior Chain "
        "αποκωδικοποίησης base64/zlib/marshal/hex και ένα Behavior Chain εκτέλεσης) και στα υπόλοιπα.",
        "tab:natural_obfuscation", "|l|r|r|r|r|r|",
        "Κακόβουλα πακέτα & Πακέτα & " + " & ".join(NAME[c] for c in CONFIGS), rows,
        size="\\footnotesize", sep="4pt"))

    # artificial obfuscation (Intensio-Obfuscator, levels A and B) next to the same packages unobfuscated
    obf = {}
    for lvl, cls in OBF:
        for f in glob.glob(os.path.join(DS, "obfuscated", f"{lvl}_{cls}", "*.json")):
            d = json.load(open(f, encoding="utf-8"))
            obf.setdefault((lvl, cls), []).append((os.path.basename(f)[:-5], d["obfuscated_from"],
                                                    bool(d.get("behavior_chains"))))

    def row(label, S, has_chains):
        """One row: packages, packages without chains and, per configuration, flagged / packages with chains."""
        with_c = [n for n in S if has_chains[n]]
        cells = []
        for c in CONFIGS:
            done = [n for n in with_c if n in reports[c]]
            cells.append(frac(sum(pos(c, n) for n in done), len(done)) if len(done) == len(with_c) else "--")
        return f"{label} & {len(S)} & {len(S) - len(with_c)} & " + " & ".join(cells)
    rows = []
    for cls, cname in (("malware", "κακόβουλα"), ("benign", "νόμιμα")):
        orig = sorted({o["package"] for lvl in "AB" for _, o, _ in obf.get((lvl, cls), [])})
        folder = ra.MAL_DIR if cls == "malware" else ra.BEN_DIR
        has = {n: bool(json.load(open(os.path.join(folder, f"{n}.json"), encoding="utf-8")).get("behavior_chains"))
               for n in orig}
        rows.append(row(f"Χωρίς συγκάλυψη ({cname})", orig, has))
        for lvl in "AB":
            items = obf.get((lvl, cls), [])
            has = {n: hc for n, _, hc in items}
            rows.append(row(f"Επίπεδο {lvl} ({cname})", [n for n, _, _ in items], has))
            if lvl == "A":
                rows.append(row("\\quad χωρίς αρχεία που δεν αναλύονται", [n for n, o, _ in items
                                                                           if not o.get("unparsable_py_files")], has))
        rows.append("\\hline")
    write("obfuscation.tex", table(
        "Τα αντίγραφα με συγκάλυψη (Intensio-Obfuscator: επίπεδο A μετονομασία και νεκρός κώδικας, επίπεδο B "
        "επιπλέον κωδικοποίηση κάθε αρχείου σε hex που εκτελείται με \\texttt{exec}) δίπλα στα ίδια πακέτα χωρίς "
        "συγκάλυψη. Σε κάθε κελί: πακέτα που χαρακτηρίστηκαν \\texttt{MALICIOUS} / πακέτα με Behavior Chains.",
        "tab:obfuscation",
        "|>{\\raggedright\\arraybackslash}p{4.2cm}|r|r|" + "|".join([">{\\centering\\arraybackslash}p{1.45cm}"] * 4) + "|",
        "Σύνολο & Πακέτα & Χωρίς chains & " + " & ".join(NAME[c] for c in CONFIGS), rows[:-1], size="\\footnotesize"))


def results_tables():
    sim_source = {p_: ra.max_similarity(r) for p_, r in ra.load(f"{MAIN}_sum").items()}
    res = {c: ra.analyze(f"{MAIN}_{c}", sim_source) for c in CONFIGS}
    reports = {c: ra.load(f"{MAIN}_{c}") for c in CONFIGS}
    mal, ben = ra.names(ra.MAL_DIR), ra.names(ra.BEN_DIR)

    def e2e(c):
        m, e = res[c]["metrics"]["llm_stage"], res[c]["metrics"]["end_to_end"]
        prec = 100 * ra.div(e["TP"], e["TP"] + e["FP"])
        f1 = 2 * prec * e["recall"] / (prec + e["recall"])
        return {"accuracy": e["accuracy"], "precision": prec, "recall": e["recall"], "f1": f1,
                "fpr": 100 * ra.div(e["FP"], e["FP"] + e["TN"])}

    # main metrics of the full system
    m, e = res["sum"]["metrics"]["llm_stage"], res["sum"]["metrics"]["end_to_end"]
    rows = [f"Recall (TPR) & {p(m['recall'])} & {m['TP']}/{m['TP'] + m['FN']} & {ci(m['recall_ci95'])}",
            f"FPR & {p(m['fpr'])} & {m['FP']}/{m['FP'] + m['TN']} & {ci(m['fpr_ci95'])}",
            f"Precision & {p(m['precision'])} & {m['TP']}/{m['TP'] + m['FP']} & {ci(m['precision_ci95'])}",
            f"F1 & {p(m['f1'])} & -- & --",
            f"Accuracy & {p(m['accuracy'])} & {m['TP'] + m['TN']}/{m['TP'] + m['FN'] + m['FP'] + m['TN']} & --",
            f"Balanced accuracy & {p(m['balanced_accuracy'])} & -- & --",
            "\\hline",
            f"Κάλυψη στατικής ανάλυσης & {p(100 * ra.div(e['TP'] + e['FN'] - e['malware_no_chains'], e['TP'] + e['FN']))} & "
            f"{e['TP'] + e['FN'] - e['malware_no_chains']}/{e['TP'] + e['FN']} & --",
            f"Recall end-to-end & {p(e['recall'])} & {e['TP']}/{e['TP'] + e['FN']} & --",
            f"Accuracy end-to-end & {p(e['accuracy'])} & {e['TP'] + e['TN']}/{e['TP'] + e['FN'] + e['FP'] + e['TN']} & --"]
    write("main_metrics.tex", table(
        "Μετρικές του πλήρους συστήματος στο σύνολο αξιολόγησης. Για recall, FPR και precision δίνεται "
        "διάστημα εμπιστοσύνης 95\\% κατά Wilson.",
        "tab:main_metrics", "|l|r|r|c|", "Μετρική & Τιμή & Πλήθος & Δ.Ε. 95\\%", rows))

    # the four configurations
    rows = []
    for c in CONFIGS:
        m, x = res[c]["metrics"]["llm_stage"], e2e(c)
        rows.append(f"{NAME[c]} & {m['TP']} & {m['FN']} & {m['FP']} & {m['TN']} & {p(m['recall'])} & {p(m['fpr'])} & "
                    f"{p(m['precision'])} & {p(m['f1'])} & {p(m['accuracy'])} & {p(m['balanced_accuracy'])} & "
                    f"{p(x['accuracy'])}")
    write("ablations.tex", table(
        "Σύγκριση των τεσσάρων διαμορφώσεων του Υβριδικού RAG (στάδιο LLM· η τελευταία στήλη μετρά και τα "
        "πακέτα χωρίς Behavior Chains).", "tab:ablations", "|l|r|r|r|r|r|r|r|r|r|r|r|",
        "Διαμόρφωση & TP & FN & FP & TN & Recall & FPR & Prec. & F1 & Acc. & Bal. acc. & Acc. e2e", rows,
        size="\\footnotesize", sep="3.5pt"))

    # similarity strata: one cell per configuration = recall (%) / false positives
    zone = {0: "$\\geq 0{,}98$ (γνωστή παραλλαγή)", 1: "$0{,}90$--$0{,}98$ (κοντινό)", 2: "$< 0{,}90$ (χαμηλή ομοιότητα)"}
    rows = []
    for i in range(len(ra.STRATA)):
        s0 = res["sum"]["strata"][i]
        cells = " & ".join(f"{p(res[c]['strata'][i]['recall'])} / {res[c]['strata'][i]['false_positives']}"
                           for c in CONFIGS)
        rows.append(f"{zone[i]} & {s0['malware']} & {s0['benign']} & {cells}")
    write("strata.tex", table(
        "Ανίχνευση ανά ζώνη μέγιστης ομοιότητας με το ευρετήριο. Σε κάθε κελί: recall στα κακόβουλα πακέτα / "
        "πλήθος false positives στα νόμιμα πακέτα της ζώνης.", "tab:strata",
        "|>{\\raggedright\\arraybackslash}p{2.6cm}|r|r|" + "|".join([">{\\centering\\arraybackslash}p{1.75cm}"] * 4) + "|",
        "Ζώνη ομοιότητας & Κακόβ. & Νόμιμα & " + " & ".join(NAME[c] for c in CONFIGS), rows,
        size="\\footnotesize"))

    # labels and correctness per package, used by the agreement table
    lab = json.load(open(os.path.join(ROOT, "expected_labels.json"), encoding="utf-8"))
    # the evaluation sets only (the obfuscated copies are reported separately)
    scored = [n for n, r in reports["sum"].items() if n in mal | ben and lab.get(n) in ("malicious", "benign")
              and r["final_verdict"] != "NO_CHAINS_FOUND" and all(n in reports[c] for c in CONFIGS)]
    flag = lambda c, n: reports[c][n]["final_verdict"] in ra.POSITIVE

    # agreement of the four configurations
    rows = []
    for cls, name in (("malicious", "Κακόβουλα"), ("benign", "Νόμιμα")):
        S = [n for n in scored if lab[n] == cls]
        pat = Counter(sum(flag(c, n) for c in CONFIGS) for n in S)
        allpos, none = pat[4], pat[0]
        rows.append(f"{name} & {len(S)} & {allpos} & {none} & {len(S) - allpos - none}")
    write("agreement.tex", table(
        "Συμφωνία των τεσσάρων διαμορφώσεων ανά πακέτο (πακέτα με Behavior Chains).", "tab:agreement",
        "|l|r|r|r|r|", "Κλάση & Πακέτα & MALICIOUS σε όλες & BENIGN σε όλες & Διαφωνία", rows))

    # SSVC priority of true / false positives
    order = ["ACT", "ATTEND", "TRACK*"]
    rank = {k: i for i, k in enumerate(["TRACK", "TRACK*", "ATTEND", "ACT"])}
    rows = []
    for c in CONFIGS:
        tp, fp = Counter(), Counter()
        for n in scored:
            if not flag(c, n):
                continue
            ds = [ch["llm_evaluation"].get("ssvc_decision") for ch in reports[c][n].get("chain_details", [])
                  if ch.get("llm_evaluation", {}).get("verdict") in ra.POSITIVE]
            top = max(ds, key=lambda d: rank.get(d, -1)) if ds else None
            (tp if lab[n] == "malicious" else fp)[top] += 1
        rows.append(f"{NAME[c]} & " + " & ".join(str(tp[k]) for k in order) + " & " +
                    " & ".join(str(fp[k]) for k in order))
    write("ssvc.tex", table(
        "Επίπεδο προτεραιότητας (εμπνευσμένο από το SSVC) των πακέτων που χαρακτηρίστηκαν \\texttt{MALICIOUS}: το υψηλότερο "
        "επίπεδο μεταξύ των κακόβουλων Behavior Chains του πακέτου.", "tab:ssvc", "|l|r|r|r|r|r|r|",
        "Διαμόρφωση & \\multicolumn{3}{c|}{Σωστά (TP)} & \\multicolumn{3}{c|}{False positives}",
        ["& \\texttt{ACT} & \\texttt{ATTEND} & \\texttt{TRACK*} & \\texttt{ACT} & \\texttt{ATTEND} & \\texttt{TRACK*}",
         "\\hline"] + rows))

    # self-reported confidence of true / false positives: the highest among the package's MALICIOUS chains
    def auroc(pos, neg):
        """Probability that a random true positive has a higher confidence than a random false positive."""
        return sum((a > b) + 0.5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg))

    rows = []
    for c in CONFIGS:
        conf = {"malicious": [], "benign": []}
        for n in scored:
            if not flag(c, n):
                continue
            cs = [ch["llm_evaluation"].get("confidence") for ch in reports[c][n].get("chain_details", [])
                  if ch.get("llm_evaluation", {}).get("verdict") in ra.POSITIVE]
            cs = [x for x in cs if isinstance(x, (int, float))]
            if cs:
                conf[lab[n]].append(max(cs))
        tp, fp = conf["malicious"], conf["benign"]
        rows.append(f"{NAME[c]} & {len(tp)} & {num(median(tp), 2)} & {len(fp)} & "
                    f"{num(median(fp), 2) if fp else '--'} & {num(auroc(tp, fp), 2) if len(fp) >= 2 else '--'}")
    write("confidence.tex", table(
        "Αυτο-αναφερόμενη βεβαιότητα (\\texttt{confidence}) του μοντέλου στα πακέτα που χαρακτηρίστηκαν "
        "\\texttt{MALICIOUS}: η μεγαλύτερη τιμή μεταξύ των κακόβουλων Behavior Chains του πακέτου. AUROC: η "
        "πιθανότητα ένα τυχαίο σωστό θετικό να έχει μεγαλύτερη βεβαιότητα από ένα τυχαίο false positive "
        "(υπολογίζεται για τουλάχιστον δύο false positives).", "tab:confidence", "|l|r|r|r|r|r|",
        "Διαμόρφωση & TP & Διάμεση (TP) & FP & Διάμεση (FP) & AUROC", rows))

    # false positives of the full system
    rows = []
    for fpk in sorted(res["sum"]["false_positives"], key=lambda x: x["package"]):
        f0 = fpk["flagged"][0]
        brk = lambda t: t.replace("_", "\\_\\allowbreak ").replace("/", "/\\allowbreak ").replace(".", ".\\allowbreak ")
        api = brk((f0["api"] or "").replace("(...)", ""))
        loc = brk((f0["location"] or "").rsplit(":", 1)[0])
        rows.append(f"{fpk['package'].replace('_', '\\_')} & {fpk['malicious_chains']}/{fpk['chains']} & "
                    f"\\texttt{{{f0['category'].replace('_', '\\_')}}} & \\texttt{{{api}}} & \\texttt{{{loc}}}")
    write("false_positives.tex", table(
        "Τα false positives του πλήρους συστήματος: κακόβουλα / συνολικά Behavior Chains του πακέτου και το "
        "Behavior Chain που κρίθηκε κακόβουλο.", "tab:false_positives",
        "|>{\\raggedright\\arraybackslash}p{2.7cm}|r|l|>{\\raggedright\\arraybackslash}p{3.5cm}|"
        ">{\\raggedright\\arraybackslash}p{3.2cm}|",
        "Πακέτο & Chains & Κατηγορία & Ευαίσθητη κλήση & Αρχείο", rows, size="\\footnotesize"))

    extra_tables(reports, scored, lab, res)

    # comparison with the tools of IntelGuard Table 1 (their PyPI dataset) - our rows end-to-end
    rows = [f"{t} & {num(a, 2)} & {num(pr, 2)} & {num(rc, 2)} & {num(f, 2)}" for t, a, pr, rc, f in INTELGUARD_TABLE1]
    rows.append("\\hline")
    for c in ("sum", "llm"):
        x = e2e(c)
        rows.append(f"\\textbf{{Παρούσα εργασία}}: {NAME[c]} & {num(x['accuracy'], 2)} & "
                    f"{num(x['precision'], 2)} & {num(x['recall'], 2)} & {num(x['f1'], 2)}")
    write("comparison.tex", table(
        "Αποτελέσματα της παρούσας εργασίας και δημοσιευμένες τιμές εργαλείων ανίχνευσης κακόβουλων πακέτων "
        "PyPI. Οι τιμές των υπολοίπων εργαλείων είναι "
        "αυτές που αναφέρει το IntelGuard~\\cite{ge2026bridging} στο δικό του σύνολο αξιολόγησης· οι τιμές "
        "της παρούσας εργασίας αφορούν το σύνολο αξιολόγησης του Κεφαλαίου~\\ref{chapter:implementations}, "
        "μετρημένες end-to-end.", "tab:comparison", "|l|r|r|r|r|",
        "Εργαλείο & Accuracy (\\%) & Precision (\\%) & Recall (\\%) & F1 (\\%)", rows))

    # effect of retrieval: IntelGuard RQ4 (direct GPT-4o-mini vs IntelGuard) next to ours, end-to-end
    rows = [f"IntelGuard~\\cite{{ge2026bridging}}, {name} & {num(a0, 2)} & {num(f0, 2) if f0 is not None else '--'} & "
            f"{num(a1, 2)} & {num(f1, 2) if f1 is not None else '--'}" for name, a0, f0, a1, f1 in INTELGUARD_RQ4]
    x0, x1 = e2e("llm"), e2e("sum")
    rows.append(f"Παρούσα εργασία, end-to-end & {num(x0['accuracy'], 2)} & {num(x0['fpr'], 2)} & "
                f"{num(x1['accuracy'], 2)} & {num(x1['fpr'], 2)}")
    write("rag_literature.tex", table(
        "Accuracy και FPR (\\%) χωρίς και με RAG: οι τιμές που αναφέρει το IntelGuard (απευθείας ανάλυση του κώδικα "
        "με το GPT-4o-mini έναντι του πλήρους IntelGuard) και οι διαμορφώσεις Χωρίς RAG και Πλήρες σύστημα της "
        "παρούσας εργασίας.", "tab:rag_literature",
        "|l|r|r|r|r|",
        "Εργασία, σύνολο & \\multicolumn{2}{c|}{Χωρίς RAG} & \\multicolumn{2}{c|}{Με RAG}",
        ["& Accuracy & FPR & Accuracy & FPR", "\\hline"] + rows))

    def panel(k, c, x=1.45, y=1.1, font="\\footnotesize"):
        """TikZ drawing of one 2x2 confusion matrix (rows: true class, columns: decision)."""
        m = res[c]["metrics"]["llm_stage"]
        cells = [[m["TP"], m["FN"]], [m["FP"], m["TN"]]]
        out = [f"\\begin{{tikzpicture}}[x={x}cm,y={y}cm,font={font}]"]
        for i, row in enumerate(cells):
            tot = sum(row)
            for j, v in enumerate(row):
                fill, txt = ra.cell_color(v / tot if tot else 0)
                r, g, b = (int(fill[q:q + 2], 16) for q in (1, 3, 5))
                out.append(f"\\definecolor{{cm{k}{i}{j}}}{{RGB}}{{{r},{g},{b}}}")
                out.append(f"\\fill[cm{k}{i}{j}] ({j},{-i}) rectangle ++(0.97,-0.97);")
                col = "white" if txt == "#ffffff" else "black"
                out.append(f"\\node[text={col},align=center] at ({j + 0.485:.3f},{-i - 0.485:.3f}) "
                           f"{{\\textbf{{{v}}}\\\\[-1pt]{{\\scriptsize {p(100 * v / tot if tot else 0)}}}}};")
        out += ["\\node[font=\\scriptsize] at (0.485,0.2) {MAL};", "\\node[font=\\scriptsize] at (1.485,0.2) {BEN};",
                "\\node[font=\\scriptsize,rotate=90] at (-0.2,-0.485) {Malware};",
                "\\node[font=\\scriptsize,rotate=90] at (-0.2,-1.485) {Benign};", "\\end{tikzpicture}"]
        return out

    legend = ("Γραμμές: πραγματική κλάση· στήλες: απόφαση του συστήματος (MAL = \\texttt{MALICIOUS}, "
              "BEN = \\texttt{BENIGN})· σε κάθε κελί το πλήθος πακέτων και το ποσοστό ανά πραγματική κλάση, "
              "με την ένταση του χρώματος ανάλογη του ποσοστού.")
    tikz_png("confusion_sum", panel(9, "sum", 2.6, 1.6, "\\normalsize"))
    write("confusion_sum.tex", ["\\begin{figure}[H]", "\\centering", f"\\includegraphics{{{IMG_REF}/confusion_sum.png}}",
                                f"\\caption{{Confusion matrix του πλήρους συστήματος στο στάδιο του LLM. {legend}}}",
                                "\\label{fig:confusion_sum}", "\\end{figure}"])

    # figure: the four confusion matrices
    fig = ["\\begin{figure}[H]", "\\centering"]
    for k, c in enumerate(CONFIGS):
        tikz_png(f"confusion_{c}", panel(k, c))
        fig += ["\\begin{subfigure}[b]{0.24\\textwidth}", "\\centering",
                f"\\includegraphics[width=\\linewidth]{{{IMG_REF}/confusion_{c}.png}}",
                f"\\caption{{{NAME[c]}}}", "\\end{subfigure}"]
        if k < len(CONFIGS) - 1:
            fig.append("\\hfill")
    fig += [f"\\caption{{Confusion matrices των τεσσάρων διαμορφώσεων στο στάδιο του LLM. {legend}}}",
            "\\label{fig:confusion_grid}", "\\end{figure}"]
    write("confusion_grid.tex", fig)
    return res


if __name__ == "__main__":
    dataset_tables()
    knowledge_base_table()
    local_model_table()
    results_tables()
    print(f"[+] LaTeX -> {OUT}")
    for f in sorted(os.listdir(OUT)):
        print("   ", f)

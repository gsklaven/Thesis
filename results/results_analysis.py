"""
results_analysis.py - αναλυτικά αποτελέσματα ανά εκτέλεση, για το Κεφάλαιο 5.

Για κάθε results/<tag>/ (π.χ. v12_sum) γράφει στο results/analysis/:
  <tag>.md                   confusion matrix, μετρικές με 95% διάστημα εμπιστοσύνης (Wilson),
                             ανάλυση ανά ζώνη ομοιότητας, λίστες false positives / false negatives
  <tag>.json                 τα ίδια σε μορφή για επεξεργασία
  confusion_<tag>.svg        το confusion matrix ως γράφημα
  confusion_<tag>.tex        το confusion matrix ως πίνακας LaTeX (\\input στη διπλωματική)
και το ablations.md: σύγκριση όλων των εκτελέσεων (sum / samples / policy / llm).

Ορισμοί (ίδιοι με check_test_set.py / evaluation_summary.py):
  θετικό = MALICIOUS (ή SUSPICIOUS)· στάδιο LLM = χωρίς τα NO_CHAINS_FOUND και στις δύο κλάσεις·
  end-to-end = malware χωρίς chains μετρούν ως FN, benign χωρίς chains ως TN·
  EVALUATION_FAILED / INCOMPLETE / UNKNOWN δεν βαθμολογούνται (αναφέρονται χωριστά).

Usage: python3 results/results_analysis.py [tag ...]   (προεπιλογή: όλα τα results/v12_* εκτός *_smoke*)
"""
import glob
import json
import math
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "dataset", "preparation"))
from utils import display_path  # noqa: E402

MAL_DIR = os.path.join(ROOT, "dataset", "rag_test")
BEN_DIR = os.path.join(ROOT, "dataset", "benign_test_set")
OUT = os.path.join(ROOT, "results", "analysis")
POSITIVE = ("MALICIOUS", "SUSPICIOUS")
UNSCORED = ("EVALUATION_FAILED", "INCOMPLETE", "UNKNOWN")
MODE_NAMES = {"sum": "πλήρες σύστημα (δείγματα + πολιτικές)", "samples": "μόνο κακόβουλα δείγματα",
              "policy": "μόνο βάση γνώσης ασφάλειας", "llm": "χωρίς ανάκτηση (μόνο LLM)"}
STRATA = [("≥0,98 γνωστή παραλλαγή", 0.98, 2.0), ("0,90–0,98 κοντινό", 0.90, 0.98), ("<0,90 νέο", -1.0, 0.90)]
# μονόχρωμη (μπλε) διαβάθμιση, από κοντά στο μηδέν έως το μέγιστο (dataviz reference palette)
RAMP = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5",
        "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"]


def names(d):
    return {f[:-5] for f in os.listdir(d) if f.endswith(".json")} if os.path.isdir(d) else set()


def wilson(k, n, z=1.96):
    if not n:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * (c - h), 100 * (c + h))


def pct(x, digits=1):
    return "—" if x is None or x != x else f"{x:.{digits}f}".replace(".", ",") + "%"


def div(a, b):
    return a / b if b else float("nan")


def load(tag):
    reports = {}
    for f in glob.glob(os.path.join(ROOT, "results", tag, "report_*.json")):
        try:
            reports[os.path.basename(f)[7:-5]] = json.load(open(f, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return reports


def max_similarity(report):
    return max((c.get("top_malware_similarity") or 0 for c in report.get("chain_details", [])), default=0.0)


def analyze(tag, sim_source):
    R = load(tag)
    mal, ben = names(MAL_DIR), names(BEN_DIR)
    verdict = lambda p: R[p].get("final_verdict")
    missing = sorted((mal | ben) - set(R))
    unscored = sorted(p for p in (mal | ben) & set(R) if verdict(p) in UNSCORED)
    nc = lambda S: sorted(p for p in S & set(R) if verdict(p) == "NO_CHAINS_FOUND")
    scored = lambda S: [p for p in S & set(R) if verdict(p) not in UNSCORED + ("NO_CHAINS_FOUND",)]
    m_sc, b_sc = scored(mal), scored(ben)
    TP = sum(verdict(p) in POSITIVE for p in m_sc)
    FN = len(m_sc) - TP
    FP = sum(verdict(p) in POSITIVE for p in b_sc)
    TN = len(b_sc) - FP
    ncm, ncb = nc(mal), nc(ben)
    rec, fpr, prec = div(TP, TP + FN), div(FP, FP + TN), div(TP, TP + FP)
    f1 = div(2 * prec * rec, prec + rec)
    e_tp, e_fn = TP, FN + len(ncm)
    e_tn = TN + len(ncb)
    metrics = {
        "llm_stage": {"TP": TP, "FN": FN, "FP": FP, "TN": TN,
                      "recall": 100 * rec, "recall_ci95": wilson(TP, TP + FN),
                      "fpr": 100 * fpr, "fpr_ci95": wilson(FP, FP + TN),
                      "precision": 100 * prec, "precision_ci95": wilson(TP, TP + FP),
                      "f1": 100 * f1, "accuracy": 100 * div(TP + TN, TP + FN + FP + TN),
                      "balanced_accuracy": 100 * (rec + 1 - fpr) / 2},
        "end_to_end": {"TP": e_tp, "FN": e_fn, "FP": FP, "TN": e_tn,
                       "recall": 100 * div(e_tp, e_tp + e_fn),
                       "accuracy": 100 * div(e_tp + e_tn, e_tp + e_fn + FP + e_tn),
                       "malware_no_chains": len(ncm), "benign_no_chains": len(ncb)},
    }
    # ζώνες ομοιότητας: η ομοιότητα είναι ιδιότητα πακέτου/ευρετηρίου, όχι της εκτέλεσης -> από μια
    # εκτέλεση με ανάκτηση δειγμάτων (sum/samples), ώστε να υπάρχει και για policy/llm.
    strata = []
    for label, lo, hi in STRATA:
        inb = lambda p: p in sim_source and lo <= sim_source[p] < hi
        ms, bs = [p for p in m_sc if inb(p)], [p for p in b_sc if inb(p)]
        k, fp = sum(verdict(p) in POSITIVE for p in ms), sum(verdict(p) in POSITIVE for p in bs)
        strata.append({"stratum": label, "malware": len(ms), "detected": k, "recall": 100 * div(k, len(ms)),
                       "benign": len(bs), "false_positives": fp, "fpr": 100 * div(fp, len(bs))})

    def chain_info(p, want_malicious):
        out = []
        for c in R[p].get("chain_details", []):
            e = c.get("llm_evaluation", {})
            if (e.get("verdict") in POSITIVE) == want_malicious:
                out.append({"category": c.get("category"), "api": c.get("sensitive_api"),
                            "location": display_path(c.get("location")), "similarity": c.get("top_malware_similarity"),
                            "ssvc": e.get("ssvc_decision"), "summary": (e.get("summary") or "")[:220]})
        return out
    fps = sorted(({"package": p, "chains": R[p].get("total_chains_analyzed"),
                   "malicious_chains": R[p].get("malicious_chains"), "max_similarity": sim_source.get(p),
                   "flagged": chain_info(p, True)} for p in b_sc if verdict(p) in POSITIVE),
                 key=lambda x: -(x["chains"] or 0))
    fns = sorted(({"package": p, "chains": R[p].get("total_chains_analyzed"), "max_similarity": sim_source.get(p)}
                  for p in m_sc if verdict(p) not in POSITIVE), key=lambda x: x["package"])
    return {"tag": tag, "reports": len(R), "expected": len(mal) + len(ben), "missing": missing,
            "unscored": unscored, "malware_no_chains": ncm, "metrics": metrics, "strata": strata,
            "false_positives": fps, "false_negatives": fns,
            "single_chain_fp": sum(1 for x in fps if x["malicious_chains"] == 1)}


def cell_color(rate):
    i = min(len(RAMP) - 1, max(0, round(rate * (len(RAMP) - 1))))
    return RAMP[i], ("#ffffff" if i >= 8 else "#0b0b0b")


def title_of(tag):
    mode = tag.split("_")[1] if tag.count("_") >= 1 else tag
    return MODE_NAMES.get(mode, mode)


def svg(res, path):
    m = res["metrics"]["llm_stage"]
    rows = [("Malware", m["TP"], m["FN"]), ("Benign", m["FP"], m["TN"])]
    W, H, x0, y0, cw, ch, gap = 620, 400, 170, 110, 170, 110, 2
    ink, ink2 = "#0b0b0b", "#52514e"
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'font-family="Helvetica, Arial, sans-serif">',
         f'<rect width="{W}" height="{H}" fill="#fcfcfb"/>',
         f'<text x="20" y="32" font-size="17" font-weight="600" fill="{ink}">Confusion matrix — {res["tag"]}</text>',
         f'<text x="20" y="54" font-size="13" fill="{ink2}">{title_of(res["tag"])}, στάδιο LLM '
         f'(ποσοστό ανά πραγματική κλάση)</text>',
         f'<text x="{x0 + cw + gap / 2}" y="{y0 - 34}" font-size="13" fill="{ink2}" text-anchor="middle">Απόφαση συστήματος</text>']
    for j, lab in enumerate(("MALICIOUS", "BENIGN")):
        o.append(f'<text x="{x0 + j * (cw + gap) + cw / 2}" y="{y0 - 12}" font-size="13" font-weight="600" '
                 f'fill="{ink}" text-anchor="middle">{lab}</text>')
    o.append(f'<text transform="translate(28,{y0 + ch + gap / 2}) rotate(-90)" font-size="13" fill="{ink2}" '
             f'text-anchor="middle">Πραγματική κλάση</text>')
    for i, (lab, a, b) in enumerate(rows):
        y = y0 + i * (ch + gap)
        o.append(f'<text x="{x0 - 14}" y="{y + ch / 2 + 5}" font-size="13" font-weight="600" fill="{ink}" '
                 f'text-anchor="end">{lab}</text>')
        tot = a + b
        for j, v in enumerate((a, b)):
            rate = v / tot if tot else 0
            fill, txt = cell_color(rate)
            x = x0 + j * (cw + gap)
            kind = [["TP", "FN"], ["FP", "TN"]][i][j]
            o.append(f'<g><title>{lab} → {("MALICIOUS", "BENIGN")[j]}: {v} ({pct(100 * rate)}) - {kind}</title>'
                     f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="4" fill="{fill}"/>'
                     f'<text x="{x + cw / 2}" y="{y + ch / 2 + 4}" font-size="30" font-weight="700" fill="{txt}" '
                     f'text-anchor="middle">{v}</text>'
                     f'<text x="{x + cw / 2}" y="{y + ch / 2 + 28}" font-size="13" fill="{txt}" '
                     f'text-anchor="middle">{pct(100 * rate)} · {kind}</text></g>')
    e = res["metrics"]["end_to_end"]
    o.append(f'<text x="20" y="{H - 40}" font-size="12" fill="{ink2}">Recall {pct(m["recall"])} · FPR {pct(m["fpr"])} · '
             f'Precision {pct(m["precision"])} · F1 {pct(m["f1"])} · Accuracy {pct(m["accuracy"])}</text>')
    o.append(f'<text x="20" y="{H - 20}" font-size="12" fill="{ink2}">Εκτός σταδίου LLM (χωρίς Behavior Chains): '
             f'malware {e["malware_no_chains"]}, benign {e["benign_no_chains"]} · end-to-end accuracy '
             f'{pct(e["accuracy"])}</text>')
    o.append("</svg>")
    open(path, "w", encoding="utf-8").write("\n".join(o))


def tex(res, path):
    m = res["metrics"]["llm_stage"]

    def cell(v, tot, bold=False):
        rate = v / tot if tot else 0
        fill, txt = cell_color(rate)
        r, g, b = (int(fill[k:k + 2], 16) / 255 for k in (1, 3, 5))
        body = (f"\\textbf{{{v}}}" if bold else f"{v}") + f" ({pct(100 * rate).replace('%', '')}\\%)"
        color = "\\textcolor{white}{" + body + "}" if txt == "#ffffff" else body
        return f"\\cellcolor[rgb]{{{r:.3f},{g:.3f},{b:.3f}}}{color}"
    mt, bt = m["TP"] + m["FN"], m["FP"] + m["TN"]
    lines = [
        "% Παράγεται από το results/results_analysis.py - μην το αλλάζεις με το χέρι.",
        "\\begin{table}[H]", "\\centering",
        f"\\caption{{Confusion matrix στο στάδιο του LLM ({title_of(res['tag'])}). Σε παρένθεση το ποσοστό ανά πραγματική κλάση.}}",
        f"\\label{{tab:confusion_{res['tag']}}}",
        "\\begin{tabular}{|l|c|c|}", "\\hline",
        " & \\multicolumn{2}{c|}{Απόφαση συστήματος} \\\\", "\\cline{2-3}",
        "Πραγματική κλάση & \\texttt{MALICIOUS} & \\texttt{BENIGN} \\\\", "\\hline",
        f"Malware & {cell(m['TP'], mt, True)} & {cell(m['FN'], mt)} \\\\", "\\hline",
        f"Benign & {cell(m['FP'], bt)} & {cell(m['TN'], bt, True)} \\\\", "\\hline",
        "\\end{tabular}", "\\end{table}", ""]
    open(path, "w", encoding="utf-8").write("\n".join(lines))


def markdown(res, path, sim_tag):
    m, e = res["metrics"]["llm_stage"], res["metrics"]["end_to_end"]
    ci = lambda t: f"[{pct(t[0])} – {pct(t[1])}]"
    L = [f"# Αποτελέσματα {res['tag']} — {title_of(res['tag'])}", "",
         f"Αναφορές: {res['reports']}/{res['expected']} πακέτα"
         + (f" · **λείπουν {len(res['missing'])}** (η εκτέλεση δεν έχει ολοκληρωθεί)" if res["missing"] else "")
         + (f" · μη βαθμολογούμενα (EVALUATION_FAILED/INCOMPLETE/UNKNOWN): {len(res['unscored'])}" if res["unscored"] else ""),
         "", f"![confusion matrix](confusion_{res['tag']}.svg)", "",
         "## Confusion matrix (στάδιο LLM)", "",
         "| Πραγματική \\ Απόφαση | MALICIOUS | BENIGN |", "|---|---|---|",
         f"| **Malware** | TP = {m['TP']} | FN = {m['FN']} |", f"| **Benign** | FP = {m['FP']} | TN = {m['TN']} |", "",
         f"Εκτός σταδίου LLM (κανένα Behavior Chain): malware {e['malware_no_chains']}, benign {e['benign_no_chains']}.", "",
         "## Μετρικές", "", "| Μετρική | Τιμή | 95% διάστημα εμπιστοσύνης |", "|---|---|---|",
         f"| Recall (στάδιο LLM) | **{pct(m['recall'])}** ({m['TP']}/{m['TP'] + m['FN']}) | {ci(m['recall_ci95'])} |",
         f"| False positive rate | **{pct(m['fpr'])}** ({m['FP']}/{m['FP'] + m['TN']}) | {ci(m['fpr_ci95'])} |",
         f"| Precision | **{pct(m['precision'])}** | {ci(m['precision_ci95'])} |",
         f"| F1 | **{pct(m['f1'])}** | |",
         f"| Accuracy (στάδιο LLM) | **{pct(m['accuracy'])}** | |",
         f"| Balanced accuracy | **{pct(m['balanced_accuracy'])}** | |",
         f"| Recall end-to-end | {pct(e['recall'])} | |",
         f"| Accuracy end-to-end | {pct(e['accuracy'])} | |", "",
         "## Ανά ζώνη ομοιότητας με το ευρετήριο", "",
         f"Μέγιστη ομοιότητα οποιουδήποτε Behavior Chain του πακέτου με το ευρετήριο (από την εκτέλεση `{sim_tag}`).", "",
         "| Ζώνη | Malware | Recall | Benign | False positives |", "|---|---|---|---|---|"]
    for s in res["strata"]:
        L.append(f"| {s['stratum']} | {s['malware']} | {s['detected']}/{s['malware']} = {pct(s['recall'])} | "
                 f"{s['benign']} | {s['false_positives']}/{s['benign']} = {pct(s['fpr'])} |")
    L += ["", f"## False positives ({len(res['false_positives'])})", "",
          f"Με ακριβώς ένα κακόβουλο Behavior Chain: {res['single_chain_fp']}/{len(res['false_positives'])}.", "",
          "| Πακέτο | Chains | Κακόβουλα | Μέγ. ομοιότητα | Κατηγορία / API / αρχείο του κακόβουλου chain |", "|---|---|---|---|---|"]
    for x in res["false_positives"]:
        det = "; ".join(f"{c['category']} `{c['api']}` {c['location']} (sim {c['similarity']}, {c['ssvc']})" for c in x["flagged"])
        L.append(f"| {x['package']} | {x['chains']} | {x['malicious_chains']} | {x['max_similarity']} | {det} |")
    L += ["", f"## False negatives ({len(res['false_negatives'])})", "", "| Πακέτο | Chains | Μέγ. ομοιότητα |", "|---|---|---|"]
    L += [f"| {x['package']} | {x['chains']} | {x['max_similarity']} |" for x in res["false_negatives"]]
    if res["malware_no_chains"]:
        L += ["", f"Malware χωρίς Behavior Chains (static misses): {', '.join(res['malware_no_chains'])}"]
    L += ["", "_Παράγεται από το `results/results_analysis.py`. Σχόλια/ερμηνεία: `results/analysis/notes.md`._", ""]
    open(path, "w", encoding="utf-8").write("\n".join(L))


def ablations(all_res, path):
    L = ["# Σύγκριση εκτελέσεων (ablations)", "",
         "| Εκτέλεση | Αναφορές | Recall | FPR | Precision | F1 | Accuracy | Balanced acc. | Accuracy end-to-end |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in all_res:
        m, e = r["metrics"]["llm_stage"], r["metrics"]["end_to_end"]
        L.append(f"| `{r['tag']}` {title_of(r['tag'])} | {r['reports']}/{r['expected']} | {pct(m['recall'])} | {pct(m['fpr'])} | "
                 f"{pct(m['precision'])} | {pct(m['f1'])} | {pct(m['accuracy'])} | {pct(m['balanced_accuracy'])} | {pct(e['accuracy'])} |")
    L += ["", "Στάδιο LLM: χωρίς τα πακέτα χωρίς Behavior Chains· end-to-end: μαζί τους (malware = FN, benign = TN).", ""]
    open(path, "w", encoding="utf-8").write("\n".join(L))


def main():
    tags = sys.argv[1:] or sorted(os.path.basename(d) for d in glob.glob(os.path.join(ROOT, "results", "v12_*"))
                                  if os.path.isdir(d) and "smoke" not in d)
    tags = [t for t in tags if load(t)]
    if not tags:
        sys.exit("[!] Δεν βρέθηκαν αποτελέσματα (results/v12_*)")
    # ομοιότητα ανά πακέτο από εκτέλεση με ανάκτηση δειγμάτων
    sim_tag = next((t for t in tags if t.split("_")[1:2] in (["sum"], ["samples"])), tags[0])
    sim_source = {p: max_similarity(r) for p, r in load(sim_tag).items()}
    os.makedirs(OUT, exist_ok=True)
    all_res = []
    for tag in tags:
        res = analyze(tag, sim_source)
        all_res.append(res)
        json.dump(res, open(os.path.join(OUT, f"{tag}.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        markdown(res, os.path.join(OUT, f"{tag}.md"), sim_tag)
        svg(res, os.path.join(OUT, f"confusion_{tag}.svg"))
        tex(res, os.path.join(OUT, f"confusion_{tag}.tex"))
        m = res["metrics"]["llm_stage"]
        print(f"[+] {tag}: {res['reports']}/{res['expected']} | recall {pct(m['recall'])} | FPR {pct(m['fpr'])} | "
              f"F1 {pct(m['f1'])} | accuracy {pct(m['accuracy'])} -> results/analysis/{tag}.md")
    ablations(all_res, os.path.join(OUT, "ablations.md"))
    print("[+] σύγκριση -> results/analysis/ablations.md")


if __name__ == "__main__":
    main()

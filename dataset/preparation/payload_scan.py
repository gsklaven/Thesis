"""
payload_scan.py

Κριτήριο καθαρισμού του malware dataset, ΑΝΕΞΑΡΤΗΤΟ από το CodeQL (για να μην είναι
κυκλικό): για κάθε δείγμα ελέγχεται με απλή σάρωση κειμένου αν ο πηγαίος κώδικάς του
περιέχει ΟΠΟΙΟΔΗΠΟΤΕ σήμα που θα μπορούσε να υλοποιήσει κακόβουλη συμπεριφορά. Αν δεν
βρεθεί ΚΑΝΕΝΑ, το δείγμα χαρακτηρίζεται "no_payload" (π.χ. placeholder, typosquat που απλώς
εξαρτάται από το πραγματικό πακέτο, ή νόμιμη έκδοση καταχωρημένη ως malware) και εξαιρείται
από το dataset (build_final_dataset.py) - δεν αποτελεί έγκυρο δείγμα για ανίχνευση από
κώδικα. Σκόπιμα ΣΥΝΤΗΡΗΤΙΚΟ: αρκεί ΕΝΑ σήμα για να μείνει το δείγμα.

Σήματα (αρκεί ένα):
  python  κλήσεις δικτύου/διεργασιών/αρχείων/κωδικοποίησης/δυναμικής εκτέλεσης (βλ. PY_SIGNALS)
  js      child_process, http/net/dns, fs εγγραφές, eval/Function, process.env
  binary  .exe .dll .so .dylib .pyc .bin
  script  .sh .bat .ps1 .cmd .vbs, .pth
  npm     package.json με preinstall/install/postinstall

Usage: python3 payload_scan.py [--out dataset/payload_scan.json] [--limit N]
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import batch_analyzer as ba  # noqa: E402
from rerun_chains import pick_analysis_root, OLD_MOUNT, NEW_MOUNT, DATASET_JSON  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY_SIGNALS = re.compile(
    r"\bos\.(system|popen|exec\w*|spawn\w*|remove|unlink|rmdir|removedirs|rename|replace|chmod|chown|startfile|getenv|environ)\b"
    r"|\bsubprocess\b|\bpty\.spawn|\bmultiprocessing\.Process"
    r"|\brequests\b|\burllib\b|\burllib2\b|\burllib3\b|\bhttpx\b|\baiohttp\b|\bhttp\.client\b|\bpycurl\b"
    r"|\bsocket\b|\bsmtplib\b|\bftplib\b|\bparamiko\b|\bwebbrowser\b"
    r"|\bbase64\b|\bzlib\b|\bgzip\b|\bbz2\b|\blzma\b|\bmarshal\b|\bpickle\b|\bcodecs\.(de|en)code|\bCrypto(dome)?\b|\bcryptography\b"
    r"|\bexec\s*\(|\beval\s*\(|\bcompile\s*\(|__import__\s*\(|\bimportlib\b|\bctypes\b|\bwinreg\b|\bsqlite3\b"
    r"|\bshutil\.(copy\w*|move|rmtree)|\bopen\s*\([^)]*['\"][wa]b?\+?['\"]|\.write_(text|bytes)\s*\(|\btempfile\b"
    r"|\bgetpass\b|\bplatform\.\w+\s*\(|\bpynput\b|\bpyperclip\b|ImageGrab"
    r"|[A-Za-z0-9+/=]{300,}|(\\x[0-9a-fA-F]{2}){60,}")
JS_SIGNALS = re.compile(
    r"child_process|require\s*\(\s*['\"](https?|net|dns|tls|dgram)['\"]|\bfs\.(write|append|unlink|rm)"
    r"|\beval\s*\(|new\s+Function\s*\(|process\.env|Buffer\.from\([^)]*base64")
BINARY = (".exe", ".dll", ".so", ".dylib", ".pyc", ".bin")
SCRIPT = (".sh", ".bat", ".ps1", ".cmd", ".vbs", ".pth")
ARCHIVE = (".tar.gz", ".tgz", ".tar", ".zip", ".whl")


def scan(root):
    signals = set()
    for r, _, files in os.walk(root):
        for f in files:
            fl, p = f.lower(), os.path.join(r, f)
            if fl.endswith(BINARY):
                signals.add("binary")
            elif fl.endswith(SCRIPT):
                signals.add("script")
            elif fl == "package.json":
                try:
                    s = json.load(open(p, encoding="utf-8", errors="replace")).get("scripts", {}) or {}
                    if any(k in s for k in ("preinstall", "install", "postinstall")):
                        signals.add("npm")
                except Exception:  # noqa: BLE001
                    pass
            elif fl.endswith((".py", ".pyw")) and "python" not in signals:
                try:
                    if PY_SIGNALS.search(open(p, encoding="utf-8", errors="replace").read()):
                        signals.add("python")
                except OSError:
                    pass
            elif fl.endswith((".js", ".mjs", ".cjs")) and "js" not in signals:
                try:
                    if JS_SIGNALS.search(open(p, encoding="utf-8", errors="replace").read()):
                        signals.add("js")
                except OSError:
                    pass
    return sorted(signals)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "dataset", "payload_scan.json"))
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()
    done_dir = os.path.join(ROOT, "dataset", "analyzed_chains")
    pkgs = sorted(f[:-5] for f in os.listdir(done_dir) if f.endswith(".json") and not f.startswith("_"))
    if args.limit:
        pkgs = pkgs[:args.limit]
    ds = {i["package_name"]: i for i in json.load(open(DATASET_JSON)) if i.get("package_name")}
    out = json.load(open(args.out)).get("packages", {}) if os.path.exists(args.out) else {}   # resumable
    work = tempfile.mkdtemp(prefix="payload_")
    t0 = time.time()
    for n, p in enumerate(pkgs, 1):
        if p in out:
            continue
        src = (ds.get(p, {}).get("source_code_path") or "").replace(OLD_MOUNT, NEW_MOUNT)
        if not os.path.isdir(src):
            out[p] = {"has_payload": None, "signals": [], "note": "source_missing"}
            continue
        root = pick_analysis_root(src)
        has_arch = any(f.lower().endswith(ARCHIVE) for _, _, fs in os.walk(root) for f in fs)
        if has_arch:
            stage = os.path.join(work, "s")
            shutil.rmtree(stage, ignore_errors=True)
            os.makedirs(stage)
            ba.copy_recursive(root, stage)
            ba.extract_archives(stage)
            root = stage
        try:
            sig = scan(root)
            out[p] = {"has_payload": bool(sig), "signals": sig}
        except Exception as e:  # noqa: BLE001
            out[p] = {"has_payload": None, "signals": [], "note": f"error: {str(e)[:120]}"}
        if n % 250 == 0:
            json.dump({"packages": out}, open(args.out, "w"))
            print(f"  {n}/{len(pkgs)} ({(time.time() - t0) / 60:.0f} min)", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    src_of = lambda p: (ds.get(p, {}).get("source_code_path") or "").replace(OLD_MOUNT + "/", "").split("/")[0]
    per = {}
    for p, v in out.items():
        s = per.setdefault(src_of(p), {"total": 0, "no_payload": 0})
        s["total"] += 1
        s["no_payload"] += v["has_payload"] is False
    no_payload = sorted(p for p, v in out.items() if v["has_payload"] is False)
    summary = {"scanned": len(out), "no_payload": len(no_payload), "per_source": per,
               "criterion": "no python/js sensitive signal, no binary, no script/.pth, no npm install script"}
    json.dump({"summary": summary, "no_payload": no_payload, "packages": out}, open(args.out, "w"), indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()

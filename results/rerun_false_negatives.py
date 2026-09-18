#!/usr/bin/env python3
"""
Τρέχει το llm_evaluator.py ΜΟΝΟ στα false negatives του v9,
χρησιμοποιώντας το νέο v10 prompt, και τυπώνει πόσα διορθώθηκαν.

Χρήση:
    python3 rerun_false_negatives.py

Προϋπόθεση:
    - GEMINI_API_KEY είναι set στο περιβάλλον
    - Τα original .json αρχεία υπάρχουν στο test_set/ ή rag_test/
"""
import json
import os
import subprocess
import sys

_THESIS_ROOT = os.environ.get("THESIS_BASE_DIR", "/Users/giorgos/Documents/Thesis")
sys.path.insert(0, os.path.join(_THESIS_ROOT, "inference"))
from query_rag import PROMPT_VERSION  # noqa: E402

# Φόρτωση false negatives από v9
SUMMARY_V9 = os.path.join(_THESIS_ROOT, "test_set_summary_v9.json")
with open(SUMMARY_V9) as f:
    v9 = json.load(f)

fn_list = v9["false_negatives"]
print(f"[*] {len(fn_list)} false negatives από v9 | Νέο prompt: {PROMPT_VERSION}")
print(f"[*] Αποτελέσματα θα αποθηκευτούν στο: results/{PROMPT_VERSION}/")
print()

# Βρες όπου βρίσκεται κάθε .json αρχείο (test_set ή rag_test)
TEST_DIRS = [
    os.path.join(_THESIS_ROOT, "test_set"),
    os.path.join(_THESIS_ROOT, "dataset", "rag_test"),
    os.path.join(_THESIS_ROOT, "dataset", "benign_test_set"),
]

INFERENCE_DIR = os.path.join(_THESIS_ROOT, "inference")
LLM_EVALUATOR = os.path.join(INFERENCE_DIR, "llm_evaluator_deepseek.py")
RESULTS_DIR = os.path.join(_THESIS_ROOT, "results", PROMPT_VERSION)

fixed = []
still_fn = []
errored = []

for i, pkg in enumerate(fn_list):
    # Βρες το .json αρχείο
    json_path = None
    for d in TEST_DIRS:
        candidate = os.path.join(d, f"{pkg}.json")
        if os.path.exists(candidate):
            json_path = candidate
            break

    if json_path is None:
        print(f"[{i+1}/{len(fn_list)}] ✗ ΔΕΝ ΒΡΕΘΗΚΕ: {pkg}")
        errored.append(pkg)
        continue

    print(f"[{i+1}/{len(fn_list)}] {pkg}", end=" ... ", flush=True)

    res = subprocess.run(
        ["python3", LLM_EVALUATOR, json_path],
        cwd=INFERENCE_DIR,
        capture_output=True,
        text=True,
    )

    report_path = os.path.join(RESULTS_DIR, f"report_{pkg}.json")
    if os.path.exists(report_path):
        with open(report_path) as f:
            r = json.load(f)
        verdict = r.get("final_verdict", "UNKNOWN")
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            print(f"✓ FIXED -> {verdict}")
            fixed.append((pkg, verdict))
        else:
            print(f"✗ STILL {verdict}")
            still_fn.append((pkg, verdict))
    else:
        print(f"✗ ERROR (no report written)")
        errored.append(pkg)

# --- Σύνοψη ---
print()
print("=" * 70)
print(f"ΑΠΟΤΕΛΕΣΜΑΤΑ RERUN FALSE NEGATIVES (v9 -> {PROMPT_VERSION})")
print("=" * 70)
print(f"Διορθώθηκαν (MALICIOUS/SUSPICIOUS): {len(fixed)}/{len(fn_list)}")
print(f"Παραμένουν FN (BENIGN/other):       {len(still_fn)}/{len(fn_list)}")
print(f"Σφάλματα:                            {len(errored)}/{len(fn_list)}")

if fixed:
    malicious = [p for p, v in fixed if v == "MALICIOUS"]
    suspicious = [p for p, v in fixed if v == "SUSPICIOUS"]
    print(f"\n-> MALICIOUS ({len(malicious)}): {malicious[:10]}{'...' if len(malicious)>10 else ''}")
    print(f"-> SUSPICIOUS ({len(suspicious)}): {suspicious[:10]}{'...' if len(suspicious)>10 else ''}")

if still_fn:
    print(f"\n✗ Παραμένουν FN ({len(still_fn)}): {[p for p,_ in still_fn[:15]]}{'...' if len(still_fn)>15 else ''}")

# Εκτιμώμενο νέο recall
original_tp = v9["correct"]
total_malicious = v9["scored_end_to_end"]
llm_scored = v9["scored_llm_stage_only"]
new_tp = original_tp + len(fixed)
print(f"\n{'='*70}")
print(f"Εκτιμώμενο νέο recall (LLM-stage): {new_tp}/{llm_scored} = {new_tp/llm_scored*100:.1f}%")
print(f"  (Ηταν: {original_tp}/{llm_scored} = {original_tp/llm_scored*100:.1f}%)")

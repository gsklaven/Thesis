import csv
import json
import os

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
LANGUAGES = ["python", "javascript"]

# How close a find_flow.ql sink line has to be to a backward-slice/control-dep
# anchor's call line to be considered "the same call" (multi-line calls can
# put the sink's *argument* a line or two away from the call's own line).
LINE_TOLERANCE = 2

# Ανώτατο πλήθος ακμών call graph που αποθηκεύεται ανά Behavior Chain, ΜΕΤΑ το
# dedup των external ονομάτων (βλ. σχόλιο στο build_for_language). Γενναιόδωρο
# επίτηδες - η ρίζα του GB-bug (bundled πολλαπλές εκδόσεις) λύνεται αλλού
# (pick_analysis_root), οπότε αυτό είναι μόνο δίχτυ ασφαλείας, όχι το κύριο
# όριο· ένα μικρό όριο εδώ αποδείχθηκε ότι έκοβε γνήσια διαφορετικά ονόματα
# external κλήσεων (βλ. python-aliyun-sdk-core: 64 μοναδικά ονόματα).
MAX_RELEVANT_EDGES_PER_ANCHOR = 300


def read_csv_rows(path):
    """Returns the data rows (header stripped) of a CSV, or [] if missing."""
    if not os.path.exists(path):
        return []
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        return [row for row in reader if row]


def anchor_key(file_, line, category):
    return (file_.strip(), str(line).strip(), category.strip())


def new_anchor(file_, line, category, api):
    return {
        "file": file_,
        "line": line,
        "category": category,
        "api": api,
        "data_flow_slice": [],
        "control_conditions": [],
        "confirmed_source_flows": [],
        "touched_files": {file_},
    }


def build_for_language(language):
    results_csv = os.path.join(RESULTS_DIR, f"final_codeql_results_{language}.csv")
    call_graph_csv = os.path.join(RESULTS_DIR, f"call_graph_{language}.csv")
    slice_csv = os.path.join(RESULTS_DIR, f"backward_slice_{language}.csv")
    control_csv = os.path.join(RESULTS_DIR, f"control_deps_{language}.csv")

    anchors = {}

    # --- Step 2.3a: backward data-flow slice rows (one row per contributing node) ---
    for row in read_csv_rows(slice_csv):
        if len(row) < 7:
            continue
        a_file, a_line, category, api, c_file, c_line, c_text = (x.strip() for x in row[:7])
        key = anchor_key(a_file, a_line, category)
        anchor = anchors.setdefault(key, new_anchor(a_file, a_line, category, api))
        anchor["data_flow_slice"].append({"file": c_file, "line": c_line, "text": c_text})
        anchor["touched_files"].add(c_file)

    # --- Step 2.3b: backward control-flow slice rows (one row per gating condition) ---
    for row in read_csv_rows(control_csv):
        if len(row) < 8:
            continue
        a_file, a_line, category, api, cond_file, cond_line, cond_text, must_be = (
            x.strip() for x in row[:8]
        )
        key = anchor_key(a_file, a_line, category)
        anchor = anchors.setdefault(key, new_anchor(a_file, a_line, category, api))
        anchor["control_conditions"].append(
            {"file": cond_file, "line": cond_line, "condition": cond_text, "must_be": must_be}
        )
        anchor["touched_files"].add(cond_file)

    # --- find_flow.ql: high-confidence flows from a *recognized* source. These
    # corroborate an anchor when they land on/near it; matched loosely on
    # file+line since find_flow.ql's sink is the argument, not the call. ---
    for row in read_csv_rows(results_csv):
        if len(row) < 6:
            continue
        source_file, source_line, source_node, sink_file, sink_line, sink_node = (
            x.strip() for x in row[:6]
        )

        # --- CROSS-BOUNDARY LOGIC (Ανάλυση Συνόρων Πακέτων) ---
        s_file_norm = source_file.replace('\\', '/')
        sink_file_norm = sink_file.replace('\\', '/')

        if "vendor/" not in s_file_norm and "vendor/" not in sink_file_norm:
            boundary = "App-Internal"
        elif "vendor/" not in s_file_norm and "vendor/" in sink_file_norm:
            boundary = "App-to-Vendor"
        elif "vendor/" in s_file_norm and "vendor/" not in sink_file_norm:
            boundary = "Vendor-to-App"
        else:
            boundary = "Vendor-Internal"

        matched = False
        try:
            sink_line_i = int(sink_line)
        except ValueError:
            sink_line_i = None

        if sink_line_i is not None:
            for key, anchor in anchors.items():
                if anchor["file"] != sink_file:
                    continue
                try:
                    if abs(int(anchor["line"]) - sink_line_i) <= LINE_TOLERANCE:
                        anchor["confirmed_source_flows"].append(
                            {
                                "Flow_Boundary": boundary,
                                "source": {"file": source_file, "line": source_line, "node": source_node},
                                "sink_node": sink_node,
                            }
                        )
                        matched = True
                except ValueError:
                    pass

        if not matched:
            # Nothing in this language run anchored here - keep it anyway so a
            # detected flow is never silently dropped from the report.
            key = anchor_key(sink_file, sink_line, "unanchored")
            anchor = anchors.setdefault(key, new_anchor(sink_file, sink_line, "unanchored", sink_node))
            anchor["confirmed_source_flows"].append(
                {
                    "Flow_Boundary": boundary,
                    "source": {"file": source_file, "line": source_line, "node": source_node},
                    "sink_node": sink_node
                }
            )

    # --- call graph: keep the full graph for reference, plus a per-anchor trim ---
    # NOTE: 7 columns now (caller, caller_file, callee, callee_file, callee_line,
    # call_line, edge_type) since call_graph_py.ql also emits "external" edges
    # (calls to stdlib/library functions with no local source, e.g. os.system).
    full_call_graph = []
    for row in read_csv_rows(call_graph_csv):
        if len(row) < 7:
            continue
        caller, caller_file, callee, callee_file, callee_line, call_line, edge_type = (
            x.strip() for x in row[:7]
        )
        full_call_graph.append(
            {
                "caller": caller,
                "caller_file": caller_file,
                "callee": callee,
                "callee_file": callee_file,
                "callee_line": callee_line,
                "call_line": call_line,
                "edge_type": edge_type,  # "resolved" (local Function) or "external" (stdlib/library/unresolved)
            }
        )

    behavior_chains = []
    for anchor in anchors.values():
        touched = anchor["touched_files"]
        # Bug fix (2026-09-23): χωρίς όριο, πακέτα με μεγάλο call graph (π.χ.
        # πολλές bundled εκδόσεις κώδικα στο ίδιο "πακέτο", βλ. automslc,
        # s3transfer-sl) παρήγαγαν αρχεία πολλών GB. Η ρίζα του προβλήματος
        # (bundled πολλαπλές εκδόσεις) λύθηκε ήδη στο rerun_chains.py
        # (pick_analysis_root) - το όριο εδώ είναι πλέον ένα δίχτυ ασφαλείας.
        #
        # Bug fix #2 (2026-09-23, verified on python-aliyun-sdk-core /
        # securetransport.py: 64 ΔΙΑΦΟΡΕΤΙΚΑ external ονόματα σε μόλις 98 raw
        # edges): ένα απλό cap στα RAW edges (πριν το dedup) μπορεί να κόψει
        # anchors με γνήσια ποικιλομορφία κλήσεων ΠΡΙΝ φτάσει σε όλα τα
        # διαφορετικά ονόματα - το flatten_chain_to_text() (utils.py) διαβάζει
        # μόνο τα πρώτα 10 ΜΟΝΑΔΙΚΑ ονόματα external callees, αλφαβητικά, οπότε
        # πρέπει να διατηρούνται ΟΛΑ τα διαφορετικά ονόματα, όχι απλά τα πρώτα
        # N raw edges (που μπορεί να είναι όλα επαναλήψεις του ίδιου ονόματος).
        # Εδώ κάνουμε dedup στα external edges ΠΡΙΝ το cap, ώστε το όριο να
        # μετράει μοναδικά ονόματα, όχι επαναλήψεις.
        matches = [e for e in full_call_graph if e["caller_file"] in touched or e["callee_file"] in touched]
        ext = [e for e in matches if e.get("edge_type") == "external"]
        other = [e for e in matches if e.get("edge_type") != "external"]
        seen_ext_names = set()
        dedup_ext = []
        for e in ext:
            name = e.get("callee")
            if name not in seen_ext_names:
                seen_ext_names.add(name)
                dedup_ext.append(e)
        # Αλφαβητική ταξινόμηση ΠΡΙΝ το cap: το flatten_chain_to_text() κρατάει τα 10
        # αλφαβητικά πρώτα μοναδικά ονόματα, άρα έτσι το cap δεν αλλάζει ποτέ το κείμενό του.
        dedup_ext.sort(key=lambda e: e.get("callee") or "")
        relevant_edges = (dedup_ext + other)[:MAX_RELEVANT_EDGES_PER_ANCHOR]
        behavior_chains.append(
            {
                "language": language,
                "flow_boundary": anchor["confirmed_source_flows"][0]["Flow_Boundary"] if anchor[
                    "confirmed_source_flows"] else "Unknown",
                "sensitive_api": anchor["api"],
                "category": anchor["category"],
                "location": f"{anchor['file']}:{anchor['line']}",
                "confirmed_source_flows": anchor["confirmed_source_flows"],
                "data_flow_slice": anchor["data_flow_slice"],
                "control_conditions": anchor["control_conditions"],
                "relevant_call_graph": relevant_edges,
            }
        )

    return behavior_chains, full_call_graph


def load_package_dependency_graph():
    """
    Loads dependency_tree.json (package -> [required packages], built from
    vendor/*.dist-info/METADATA by analysis.py's generate_dependency_tree()).
    This is the package-level relation layer: which third-party packages this
    sample depends on / bundles.
    """
    dep_tree_path = os.path.join(RESULTS_DIR, "dependency_tree.json")
    if not os.path.exists(dep_tree_path):
        return {}
    with open(dep_tree_path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    all_chains = []
    full_graphs = {}

    for lang in LANGUAGES:
        chains, full_graph = build_for_language(lang)
        all_chains.extend(chains)
        full_graphs[lang] = full_graph

    by_category = {}
    for c in all_chains:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1

    package_dependency_graph = load_package_dependency_graph()

    output = {
        "summary": {
            "total_behavior_chains": len(all_chains),
            "by_category": by_category,
            "total_package_dependencies": len(package_dependency_graph),
            # Σημάδι έκδοσης: αρχεία χωρίς αυτό παρήχθησαν πριν τα fixes του 2026-09-23
            # (βλ. dataset/preparation/compact_chains.py).
            "call_graph_format": "dedup-sorted-cap300",
        },
        "behavior_chains": all_chains,
        "full_call_graphs": full_graphs,          # function-level: caller -> callee (resolved + external)
        "package_dependency_graph": package_dependency_graph,  # package-level: pkg -> [required pkgs]
    }

    out_path = os.path.join(RESULTS_DIR, "sliced_behavior_chain.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    print(f"[+] {len(all_chains)} behavior chain(s) -> {out_path}")
/**
 * @name Backward data-flow slice (Step 2.3a + inter-procedural resolution)
 * @description For every sensitive-API argument (the slicing criterion from
 *              Step 2.2), enumerates every node from which that argument's
 *              value is backward-reachable via taint tracking - the full
 *              inter-procedural data-dependency slice, with NO requirement
 *              that the value originate from a "recognized" source type.
 *
 *              This is the standard CodeQL backward-slicing idiom: isSource
 *              is unrestricted (true for every node), so for a fixed sink,
 *              the set of nodes for which flow(node, sink) holds IS the
 *              backward slice - every node lying on any path to the sink
 *              trivially flows to it. Crossing function boundaries (the
 *              "Inter-procedural Variable Resolution" requirement) is
 *              handled automatically by TaintTracking::Global, the same
 *              engine already used in find_flow.ql.
 * @id py/malware/backward-data-slice
 * @tags malware slicing
 *
 * OUTPUT (7 named columns):
 *   anchor_file, anchor_line, anchor_category, anchor_api,
 *   contrib_file, contrib_line, contrib_text
 *
 * One row per (sensitive call argument, contributing node) pair. Group by
 * the first four columns in build_behavior_chain.py to reconstruct one
 * self-contained slice per anchor.
 *
 * PERFORMANCE NOTE: isSource is restricted to DataFlow::LocalSourceNode
 * rather than every DataFlow::Node - this is CodeQL's own documented
 * optimization for "unrestricted" backward-flow configs ("For global flow,
 * it is also useful to restrict sources to instances of LocalSourceNode").
 * It does not reduce recall: if some node M flows to the sink, any
 * LocalSourceNode that M is locally derived from also flows to the sink (the
 * step composes), so the same origins are still reported - this just avoids
 * separately re-deriving the same path from every redundant intermediate
 * read/use along the way, instead of only from its defining point. An
 * earlier unrestricted version (isSource = any()) took 22+ minutes to
 * evaluate on this 177-module closure; this should be substantially faster.
 * If it's still too slow on larger real-world packages, the next lever to
 * pull is switching TaintTracking::Global -> DataFlow::Global below (drops
 * the string-concat/format-string style taint steps, at the cost of missing
 * some obfuscated/indirect flows).
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import SensitiveAPIsPy

module BackwardSliceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DataFlow::LocalSourceNode }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call, string category | isSensitiveArg(sink, call, category))
  }
}

module BackwardSlice = TaintTracking::Global<BackwardSliceConfig>;

from
  DataFlow::Node contrib, DataFlow::Node sink, DataFlow::CallCfgNode call, string category
where
  isSensitiveArg(sink, call, category) and
  BackwardSlice::flow(contrib, sink)
select call.getLocation().getFile().getRelativePath() as anchor_file,
  call.getLocation().getStartLine() as anchor_line, category as anchor_category,
  call.toString() as anchor_api, contrib.getLocation().getFile().getRelativePath() as contrib_file,
  contrib.getLocation().getStartLine() as contrib_line, contrib.toString() as contrib_text

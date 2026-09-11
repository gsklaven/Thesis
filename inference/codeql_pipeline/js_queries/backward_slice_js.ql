/**
 * @name Backward data-flow slice (Step 2.3a + inter-procedural resolution) - JS/TS
 * @description JavaScript/TypeScript counterpart of backward_slice_py.ql.
 *              See that file for the full explanation of the isSource=any()
 *              backward-slicing idiom.
 * @id js/malware/backward-data-slice
 * @tags malware slicing
 *
 * OUTPUT (7 named columns):
 *   anchor_file, anchor_line, anchor_category, anchor_api,
 *   contrib_file, contrib_line, contrib_text
 *
 * PERFORMANCE NOTE: isSource is restricted to DataFlow::SourceNode (the JS
 * equivalent of Python's LocalSourceNode) rather than every DataFlow::Node -
 * see backward_slice_py.ql for the full explanation. An unrestricted
 * isSource = any() took 22+ minutes to evaluate on the (much smaller) Python
 * side of this same project, so this restriction is applied here up front
 * rather than waiting to hit the same wall.
 */

import javascript
import SensitiveAPIsJs

module BackwardSliceConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DataFlow::SourceNode }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::InvokeNode call, string category | isSensitiveArg(sink, call, category))
  }
}

module BackwardSlice = TaintTracking::Global<BackwardSliceConfig>;

from DataFlow::Node contrib, DataFlow::Node sink, DataFlow::InvokeNode call, string category
where
  isSensitiveArg(sink, call, category) and
  BackwardSlice::flow(contrib, sink)
select call.getFile().getRelativePath() as anchor_file,
  call.getLocation().getStartLine() as anchor_line, category as anchor_category,
  call.toString() as anchor_api, contrib.getFile().getRelativePath() as contrib_file,
  contrib.getLocation().getStartLine() as contrib_line, contrib.toString() as contrib_text

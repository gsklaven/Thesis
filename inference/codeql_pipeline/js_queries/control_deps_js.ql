/**
 * @name Backward control-flow slice (Step 2.3b) - JS/TS
 * @description JavaScript/TypeScript counterpart of control_deps_py.ql.
 *              Uses ConditionGuardNode.dominates(): a synthetic CFG node
 *              recording that a condition's outcome is known from that point
 *              on. If such a guard dominates the sensitive call's basic
 *              block, every path reaching the call passed through that
 *              confirmed branch outcome - i.e. it's a control dependency.
 * @id js/malware/backward-control-slice
 * @tags malware slicing
 *
 * OUTPUT (8 named columns):
 *   anchor_file, anchor_line, anchor_category, anchor_api,
 *   condition_file, condition_line, condition_text, branch_must_be
 */

import javascript
import SensitiveAPIsJs

/**
 * Readable text for a JS ControlFlowNode (condition expression).
 * For constant string conditions, show the actual string.
 * For all others, toString() gives readable output in JS CodeQL.
 */
string getReadableCondTextJs(DataFlow::Node n) {
  result = n.getStringValue()
  or
  not exists(n.getStringValue()) and
  result = n.toString()
}

from
  DataFlow::InvokeNode call, string category, ConditionGuardNode guard, BasicBlock sinkBlock
where
  isSensitiveCall(call, category) and
  sinkBlock = call.getEnclosingExpr().(ControlFlowNode).getBasicBlock() and
  guard.dominates(sinkBlock)
select call.getFile().getRelativePath() as anchor_file,
  call.getLocation().getStartLine() as anchor_line, category as anchor_category,
  call.toString() as anchor_api, guard.getTest().getFile().getRelativePath() as condition_file,
  guard.getTest().getLocation().getStartLine() as condition_line,
  guard.getTest().toString() as condition_text, guard.getOutcome() as branch_must_be

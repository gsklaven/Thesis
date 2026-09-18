/**
 * @name Backward control-flow slice (Step 2.3b)
 * @description For every sensitive-API call (the slicing criterion from
 *              Step 2.2), enumerates every condition (if/while/try branch
 *              outcome) that controls whether that call executes at all -
 *              the control-dependency half of the backward slice. Uses
 *              ConditionBlock.controls(), the standard Python library
 *              predicate for control dependency (every path reaching the
 *              call's basic block must pass through this branch outcome).
 * @id py/malware/backward-control-slice
 * @tags malware slicing
 *
 * OUTPUT (8 named columns):
 *   anchor_file, anchor_line, anchor_category, anchor_api,
 *   condition_file, condition_line, condition_text, branch_must_be
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs
import SensitiveAPIsPy

/**
 * ΝΕΟ FIX: ίδιο πρόβλημα με το backward_slice_py.ql - το .toString() σε
 * μια σύνθετη έκφραση (π.χ. Attribute, "self.something") επιστρέφει
 * μόνο το όνομα κλάσης του κόμβου ("Attribute()"), όχι το πραγματικό
 * κείμενο - σημαντικό εδώ αφού πολλές συνθήκες (π.χ. hasattr-gated
 * κλάδοι) εμπλέκουν ακριβώς τέτοιες εκφράσεις.
 */
string getReadableCondText(AstNode n) {
  exists(Attribute attr | attr = n |
    result = attr.getObject().toString() + "." + attr.getName()
  )
  or
  not exists(Attribute attr | attr = n) and
  result = n.toString()
}

from
  DataFlow::CallCfgNode call, string category, ConditionBlock guard, boolean branch,
  BasicBlock sinkBlock
where
  isSensitiveCall(call, category) and
  sinkBlock = call.asExpr().getAFlowNode().getBasicBlock() and
  guard.controls(sinkBlock, branch)
select call.getLocation().getFile().getRelativePath() as anchor_file,
  call.getLocation().getStartLine() as anchor_line, category as anchor_category,
  call.toString() as anchor_api,
  guard.getLastNode().getLocation().getFile().getRelativePath() as condition_file,
  guard.getLastNode().getLocation().getStartLine() as condition_line,
  getReadableCondText(guard.getLastNode().getNode()) as condition_text, branch as branch_must_be

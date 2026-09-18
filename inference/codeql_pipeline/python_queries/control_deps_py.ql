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
 * Ανακατασκευάζει ανθρώπινα-αναγνώσιμο κείμενο για AstNode συνθήκης
 * (guard nodes). Καλύπτει Attribute, Name, StringLiteral.
 */

/** Recursive helper για Expr nodes. */
private string readableCondExpr(Expr e) {
  // Attribute (recursive): self.flag, os.environ.get, κλπ.
  exists(Attribute attr | attr = e |
    result = readableCondExpr(attr.getObject()) + "." + attr.getName()
  )
  or
  // Name: αναγνωριστικό μεταβλητής
  exists(Name nm | nm = e | result = nm.getId())
  or
  // StringLiteral: πραγματική τιμή literal
  exists(StringLiteral lit | lit = e | result = lit.getS())
  or
  // Fallback
  not e instanceof Attribute and
  not e instanceof Name and
  not e instanceof StringLiteral and
  result = e.toString()
}

string getReadableCondText(AstNode n) {
  result = readableCondExpr(n.(Expr))
  or
  not n instanceof Expr and result = n.toString()
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

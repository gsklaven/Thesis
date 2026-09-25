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
 * Rebuilds human-readable text for the AstNode of a condition
 * (guard nodes). Covers Attribute, Name, StringLiteral.
 */

/** Recursive helper for Expr nodes. */
/** Operator symbol for readable text (binary / unary expressions). */
private string opSym(Operator o) {
  o instanceof Add and result = "+"
  or
  o instanceof Sub and result = "-"
  or
  o instanceof Mult and result = "*"
  or
  o instanceof Div and result = "/"
  or
  o instanceof Mod and result = "%"
  or
  o instanceof Pow and result = "**"
  or
  o instanceof FloorDiv and result = "//"
  or
  o instanceof BitOr and result = "|"
  or
  o instanceof BitAnd and result = "&"
  or
  o instanceof BitXor and result = "^"
  or
  o instanceof LShift and result = "<<"
  or
  o instanceof RShift and result = ">>"
}

private string unarySym(Unaryop o) {
  o instanceof Not and result = "not"
  or
  o instanceof USub and result = "-"
  or
  o instanceof UAdd and result = "+"
  or
  o instanceof Invert and result = "~"
}

private string readableCondExpr(Expr e) {
  // Attribute (recursive): self.flag, os.environ.get, etc.
  exists(Attribute attr | attr = e |
    result = readableCondExpr(attr.getObject()) + "." + attr.getName()
  )
  or
  // Name: variable identifier
  exists(Name nm | nm = e | result = nm.getId())
  or
  // StringLiteral: actual literal value
  exists(StringLiteral lit | lit = e | result = lit.getS())
  or
  exists(IntegerLiteral i | i = e | result = i.getN())
  or
  exists(Call c | c = e | result = readableCondExpr(c.getFunc()) + "(...)")
  or
  exists(Subscript s | s = e | result = readableCondExpr(s.getObject()) + "[" + readableCondExpr(s.getIndex()) + "]")
  or
  exists(BinaryExpr b | b = e and exists(opSym(b.getOp())) |
    result = readableCondExpr(b.getLeft()) + " " + opSym(b.getOp()) + " " + readableCondExpr(b.getRight())
  )
  or
  exists(UnaryExpr u | u = e and exists(unarySym(u.getOp())) |
    result = unarySym(u.getOp()) + " " + readableCondExpr(u.getOperand())
  )
  or
  exists(Compare c | c = e and not exists(c.getComparator(1)) |
    result = readableCondExpr(c.getLeft()) + " " + c.getOp(0).getSymbol() + " " + readableCondExpr(c.getComparator(0))
  )
  or
  not e instanceof Attribute and
  not e instanceof Name and
  not e instanceof StringLiteral and
  not e instanceof IntegerLiteral and
  not e instanceof Call and
  not e instanceof Subscript and
  not (e instanceof BinaryExpr and exists(opSym(e.(BinaryExpr).getOp()))) and
  not (e instanceof UnaryExpr and exists(unarySym(e.(UnaryExpr).getOp()))) and
  not (e instanceof Compare and not exists(e.(Compare).getComparator(1))) and
  result = e.toString()
}

string getReadableCondText(AstNode n) {
  result = readableCondExpr(n.(Expr))
  or
  not n instanceof Expr and result = n.toString()
}

/**
 * Readable text of the anchor call ("anchor_api"), as in backward_slice_py.ql: call.toString()
 * would give "ControlFlowNode for Attribute()" instead of the actual call text.
 */
string getReadableCallText(DataFlow::CallCfgNode call) {
  exists(Expr func | func = call.asExpr().(Call).getFunc() |
    result = readableCondExpr(func) + "(...)"
  )
  or
  not exists(Expr func | func = call.asExpr().(Call).getFunc()) and result = call.toString()
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
  getReadableCallText(call) as anchor_api,
  guard.getLastNode().getLocation().getFile().getRelativePath() as condition_file,
  guard.getLastNode().getLocation().getStartLine() as condition_line,
  getReadableCondText(guard.getLastNode().getNode()) as condition_text, branch as branch_must_be

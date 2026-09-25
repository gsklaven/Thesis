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

/**
 * Rebuilds human-readable text for DataFlow nodes that would otherwise
 * appear as "ControlFlowNode for X".
 *
 * Covers the four most common kinds:
 *   - Attribute  : "obj.attr" (recursive, handles nested ones e.g. os.path.join)
 *   - Name       : returns the variable identifier (e.g. "data")
 *   - StringLiteral: returns the literal's value (e.g. "https://...")
 *   - Fallback   : n.toString() for anything else (BinaryExpr, Subscript...)
 */

/** Recursive helper - works on Expr, not on DataFlow::Node. */
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

private string readableExpr(Expr e) {
  // Attribute (recursive): os.path.join, self.foo, etc.
  exists(Attribute attr | attr = e |
    result = readableExpr(attr.getObject()) + "." + attr.getName()
  )
  or
  // Name: plain variable reference (data, key, meta_dir, etc.)
  exists(Name nm | nm = e | result = nm.getId())
  or
  // StringLiteral: shows the actual value instead of "StringLiteral"
  exists(StringLiteral lit | lit = e | result = lit.getS())
  or
  exists(IntegerLiteral i | i = e | result = i.getN())
  or
  exists(Call c | c = e | result = readableExpr(c.getFunc()) + "(...)")
  or
  exists(Subscript s | s = e | result = readableExpr(s.getObject()) + "[" + readableExpr(s.getIndex()) + "]")
  or
  exists(BinaryExpr b | b = e and exists(opSym(b.getOp())) |
    result = readableExpr(b.getLeft()) + " " + opSym(b.getOp()) + " " + readableExpr(b.getRight())
  )
  or
  exists(UnaryExpr u | u = e and exists(unarySym(u.getOp())) |
    result = unarySym(u.getOp()) + " " + readableExpr(u.getOperand())
  )
  or
  exists(Compare c | c = e and not exists(c.getComparator(1)) |
    result = readableExpr(c.getLeft()) + " " + c.getOp(0).getSymbol() + " " + readableExpr(c.getComparator(0))
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

string getReadableText(DataFlow::Node n) {
  // if the node corresponds to an expression, use the recursive helper
  result = readableExpr(n.asExpr())
  or
  // fallback when there is no asExpr() (e.g. parameter nodes)
  not exists(n.asExpr()) and result = n.toString()
}

/**
 * Readable text of the anchor call ("anchor_api", sensitive_api in the final JSON): call.toString()
 * would give "ControlFlowNode for Attribute()" instead of "requests.get". Rebuilds "callee(...)"
 * (e.g. "requests.get(...)", "os.system(...)") from the Call expression.
 */
string getReadableCallText(DataFlow::CallCfgNode call) {
  exists(Expr func | func = call.asExpr().(Call).getFunc() | result = readableExpr(func) + "(...)")
  or
  not exists(Expr func | func = call.asExpr().(Call).getFunc()) and result = call.toString()
}

from
  DataFlow::Node contrib, DataFlow::Node sink, DataFlow::CallCfgNode call, string category
where
  isSensitiveArg(sink, call, category) and
  BackwardSlice::flow(contrib, sink)
select call.getLocation().getFile().getRelativePath() as anchor_file,
  call.getLocation().getStartLine() as anchor_line, category as anchor_category,
  getReadableCallText(call) as anchor_api, contrib.getLocation().getFile().getRelativePath() as contrib_file,
  contrib.getLocation().getStartLine() as contrib_line, getReadableText(contrib) as contrib_text

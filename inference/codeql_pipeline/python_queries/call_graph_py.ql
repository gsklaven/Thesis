/**
 * @name Python call graph (caller -> callee edges, resolved + external)
 * @description Resolves inter-procedural call edges. For calls whose target
 *              is a user-defined function within the analyzed source tree,
 *              records a "resolved" edge (via viableCallable, the same call
 *              graph taint tracking uses). For every other call (stdlib,
 *              uninstalled third-party libraries, dynamically dispatched
 *              calls, etc.) records a best-effort "external" edge using the
 *              dotted name of the callee expression, so calls like
 *              os.system(...) or requests.post(...) still show up as edges
 *              even though their implementation is outside the extracted
 *              source tree.
 * @id py/malware/call-graph
 * @tags malware callgraph
 *
 * OUTPUT (7 named columns):
 *   caller, caller_file, callee, callee_file, callee_line, call_line, edge_type
 *   edge_type is "resolved" or "external".
 *
 * LIMITATION: dynamically dispatched calls (getattr / reflection / runtime-
 *   built callables) still don't resolve to a specific Function, and appear
 *   (if at all) as "external" with a best-effort or "<complex_expr>" name.
 */

import python
private import semmle.python.dataflow.new.internal.DataFlowDispatch

/** Holds if `call` resolves to function `callee` in the current call graph. */
predicate resolvedCall(CallNode call, Function callee) {
  exists(DataFlowCallable dfCallable, DataFlowCall dfCall |
    dfCallable.getScope() = callee and
    dfCall.getNode() = call and
    dfCallable = viableCallable(dfCall)
  )
}

/** Display name for a scope: a function's qualified name, or plain name otherwise. */
string callerName(Scope s) {
  if s instanceof Function
  then result = s.(Function).getQualifiedName()
  else result = s.getName()
}

/** Best-effort dotted name for a callee expression, e.g. `os.system`, `requests.post`. */
string dottedName(Expr e) {
  exists(Name n | n = e | result = n.getId())
  or
  exists(Attribute a | a = e | result = dottedName(a.getObject()) + "." + a.getName())
  or
  not e instanceof Name and not e instanceof Attribute and result = "<complex_expr>"
}

/** One row per call site: either a resolved local edge, or a best-effort external edge. */
predicate edge(
  string caller, string caller_file, string callee, string callee_file,
  string callee_line, string call_line, string edge_type
) {
  exists(CallNode call, Scope callerScope, Function calleeFunc |
    callerScope = call.getScope() and
    exists(callerScope.getLocation().getFile().getRelativePath()) and
    resolvedCall(call, calleeFunc) and
    exists(calleeFunc.getLocation().getFile().getRelativePath()) and
    caller = callerName(callerScope) and
    caller_file = callerScope.getLocation().getFile().getRelativePath() and
    callee = calleeFunc.getQualifiedName() and
    callee_file = calleeFunc.getLocation().getFile().getRelativePath() and
    callee_line = calleeFunc.getLocation().getStartLine().toString() and
    call_line = call.getLocation().getStartLine().toString() and
    edge_type = "resolved"
  )
  or
  exists(CallNode call, Scope callerScope |
    callerScope = call.getScope() and
    exists(callerScope.getLocation().getFile().getRelativePath()) and
    not exists(Function f | resolvedCall(call, f)) and
    caller = callerName(callerScope) and
    caller_file = callerScope.getLocation().getFile().getRelativePath() and
    callee = dottedName(call.getNode().getFunc()) and
    callee_file = "external" and
    callee_line = "" and
    call_line = call.getLocation().getStartLine().toString() and
    edge_type = "external"
  )
}

from
  string caller, string caller_file, string callee, string callee_file,
  string callee_line, string call_line, string edge_type
where edge(caller, caller_file, callee, callee_file, callee_line, call_line, edge_type)
select caller, caller_file, callee, callee_file, callee_line, call_line, edge_type

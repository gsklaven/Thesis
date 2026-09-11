/**
 * @name JavaScript/TypeScript call graph (caller -> callee edges)
 * @description Resolves inter-procedural call edges via CodeQL's JS call
 * resolution.
 * @id js/malware/call-graph
 * @tags malware callgraph
 */

import javascript

/**
 * Helper predicate to extract the caller name safely,
 * mirroring the logic used in the Python version.
 */
string callerName(StmtContainer c) {
  if c instanceof Function
  then result = c.(Function).getName()
  else result = "<toplevel>"
}

from DataFlow::InvokeNode call, Function calleeFunc, StmtContainer callerContainer
where
  calleeFunc = call.getACallee() and
  callerContainer = call.getContainer() and
  exists(calleeFunc.getFile().getRelativePath())
select
  callerName(callerContainer) as caller,
  callerContainer.getFile().getRelativePath() as caller_file,
  calleeFunc.getName() as callee,
  calleeFunc.getFile().getRelativePath() as callee_file,
  calleeFunc.getLocation().getStartLine() as callee_line,
  call.getEnclosingExpr().getLocation().getStartLine() as call_line
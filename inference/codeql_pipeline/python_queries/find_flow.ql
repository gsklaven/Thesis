/**
 * @name Sensitive data flow to a sensitive sink (malware exfiltration heuristic)
 * @description Tracks data flowing from a potentially sensitive SOURCE
 *              (hardcoded secret, environment variable, file read, system info)
 *              into a sensitive SINK / Sensitive API (network egress, process
 *              execution, dynamic code execution). This is the "anchor" query
 *              for the backward-slicing / behavior-chain pipeline.
 * @id py/malware/sensitive-flow
 * @tags security malware
 *
 * NOTE ON OUTPUT SHAPE:
 *   This is deliberately a PLAIN query (no `@kind path-problem`) so that the
 *   `select` can emit exactly six named columns:
 *       source_file, source_line, source_node, sink_file, sink_line, sink_node
 *   These are the columns that cross_validation.py -> parse_codeql_csv() reads.
 *   `codeql bqrs decode --format=csv` emits the column names (from the `as`
 *   aliases) as the header row by default, which the parser uses.
 *
 *   If you instead want the full visual path (source -> ... -> sink) in the
 *   CodeQL VS Code extension, switch to the path-problem variant noted at the
 *   bottom of this file.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import SensitiveAPIsPy

// ---------------------------------------------------------------------------
// Configuration: what counts as a SOURCE and what counts as a SINK.
// The sink catalogue (Data/File ops, Network, Process/Payload exec,
// Encryption/Obfuscation) now lives in SensitiveAPIsPy.qll, shared with the
// backward-slicing queries, so it's maintained in exactly one place.
// ---------------------------------------------------------------------------
module SensitiveFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // (a) Hardcoded string literals: catches demo secrets like "admin123",
    //     "API_KEY_12345" and real hardcoded credentials/tokens/URLs.
    //     `StringLiteral` is the current class (StrConst/Str were renamed to
    //     StringLiteral in CodeQL 2.17.2 and are deprecated).
    source.asExpr() instanceof StringLiteral
    or
    // (b) Environment variables: os.getenv(...) / os.environ.get(...)
    source = API::moduleImport("os").getMember("getenv").getACall()
    or
    source =
      API::moduleImport("os").getMember("environ").getMember("get").getACall()
    or
    // (c) File reads: open(...).read()
    source = API::builtin("open").getReturn().getMember(["read", "readline", "readlines"]).getACall()
    or
    // (d) System / host fingerprinting
    source = API::moduleImport("platform").getMember(_).getACall()
    or
    source = API::moduleImport("socket").getMember("gethostname").getACall()
    or
    source = API::moduleImport("getpass").getMember("getuser").getACall()
    or
    // (e) Command-line arguments / interactive input. asSource() is the
    // correct API::Node -> DataFlow::Node bridge for "uses of this value"
    // (getACall() is the equivalent bridge used everywhere else in this file,
    // but argv isn't called, just referenced/subscripted, so it doesn't apply
    // here).
    source = API::moduleImport("sys").getMember("argv").asSource()
    or
    source = API::builtin("input").getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call, string category | isSensitiveArg(sink, call, category))
  }
}

module SensitiveFlow = TaintTracking::Global<SensitiveFlowConfig>;

/**
 * Ανακατασκευάζει ανθρώπινα-αναγνώσιμο κείμενο για DataFlow::Node source/sink.
 * Κρίσιμο αφού η πρόταση "Data flows from X into Y" εμφανίζεται
 * σε κάθε chain με επιβεβαιωμένη ροή, νωρίς μέσα στο prompt.
 *
 * Καλύπτει:
 *   - Attribute  : "obj.attr" (recursive, fixes nested π.χ. os.path.join)
 *   - Name       : αναγνωριστικό μεταβλητής
 *   - StringLiteral: πραγματική τιμή literal
 *   - Fallback   : n.toString() για όλα τα άλλα (BinaryExpr, Subscript...)
 */

/** Recursive helper — δουλεύει πάνω σε Expr, όχι DataFlow::Node. */
private string readableExpr(Expr e) {
  exists(Attribute attr | attr = e |
    result = readableExpr(attr.getObject()) + "." + attr.getName()
  )
  or
  exists(Name nm | nm = e | result = nm.getId())
  or
  exists(StringLiteral lit | lit = e | result = lit.getS())
  or
  not e instanceof Attribute and
  not e instanceof Name and
  not e instanceof StringLiteral and
  result = e.toString()
}

string getReadableText(DataFlow::Node n) {
  result = readableExpr(n.asExpr())
  or
  not exists(n.asExpr()) and result = n.toString()
}

// ---------------------------------------------------------------------------
// The 6-column result. Relative paths keep the output portable and make the
// file:line matching against Joern (cross_validation.py) reliable.
// ---------------------------------------------------------------------------
from DataFlow::Node source, DataFlow::Node sink
where SensitiveFlow::flow(source, sink)
select source.getLocation().getFile().getRelativePath() as source_file,
  source.getLocation().getStartLine() as source_line, getReadableText(source) as source_node,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line, getReadableText(sink) as sink_node

/*
 * ----------------------------------------------------------------------------
 * OPTIONAL: path-problem variant (for interactive inspection in VS Code).
 * Do NOT use this with cross_validation.py - it changes the column shape.
 *
 *   // add to metadata:  @kind path-problem   @problem.severity warning
 *   import SensitiveFlow::PathGraph
 *   from SensitiveFlow::PathNode source, SensitiveFlow::PathNode sink
 *   where SensitiveFlow::flowPath(source, sink)
 *   select sink.getNode(), source, sink, "Sensitive data reaches a sensitive API."
 * ----------------------------------------------------------------------------
 */

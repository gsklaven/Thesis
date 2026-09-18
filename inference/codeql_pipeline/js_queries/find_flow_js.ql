/**
 * @name Sensitive data flow to a sensitive sink (malware exfiltration heuristic) - JS/TS
 * @description JavaScript/TypeScript counterpart of find_flow.ql. Tracks data
 *              flowing from a potentially sensitive SOURCE (hardcoded secret,
 *              env var, file read, system info, CLI args) into a sensitive
 *              SINK / Sensitive API (network egress, process execution,
 *              dynamic code execution, crypto/obfuscation).
 * @id js/malware/sensitive-flow
 * @tags security malware
 *
 * Same 6-column output shape as find_flow.ql so downstream tooling (the
 * behavior-chain assembly script) can treat both languages uniformly:
 *     source_file, source_line, source_node, sink_file, sink_line, sink_node
 */

import javascript
import SensitiveAPIsJs

module SensitiveFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // (a) Hardcoded string literals
    source.asExpr() instanceof StringLiteral
    or
    // (b) Environment variables: process.env.X
    source = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead()
    or
    // (c) Command-line arguments: process.argv[i]
    source = DataFlow::globalVarRef("process").getAPropertyRead("argv").getAPropertyRead()
    or
    // (d) File reads
    source =
      DataFlow::moduleMember(["fs", "fs/promises"], ["readFile", "readFileSync"]).getACall()
    or
    // (e) System / host fingerprinting
    source = DataFlow::moduleMember("os", ["hostname", "userInfo", "networkInterfaces"]).getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::InvokeNode call, string category | isSensitiveArg(sink, call, category))
  }
}

module SensitiveFlow = TaintTracking::Global<SensitiveFlowConfig>;

/**
 * Readable text for JS DataFlow::Node source/sink.
 * Mirrors the Python getReadableText() approach: show the actual string value
 * for string literals, fall back to toString() for everything else.
 * In JS CodeQL, toString() already gives readable output ("event.data.url",
 * "fetch()", etc.) so this mainly helps for string literal sources.
 */
string getReadableTextJs(DataFlow::Node n) {
  result = n.getStringValue()
  or
  not exists(n.getStringValue()) and
  result = n.toString()
}

from DataFlow::Node source, DataFlow::Node sink
where SensitiveFlow::flow(source, sink)
select source.getFile().getRelativePath() as source_file,
  source.getLocation().getStartLine() as source_line, getReadableTextJs(source) as source_node,
  sink.getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line, getReadableTextJs(sink) as sink_node

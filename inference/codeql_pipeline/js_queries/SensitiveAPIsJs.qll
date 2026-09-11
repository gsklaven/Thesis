/**
 * Shared "Sensitive API" catalogue for JavaScript/TypeScript (Step 2.1).
 * Mirrors SensitiveAPIsPy.qll's categories so both languages feed the same
 * downstream shape:
 *   "network"            - data exfiltration / payload download
 *   "process_exec"       - process spawning / dynamic code execution
 *   "file_ops"           - filesystem read/write/delete
 *   "crypto_obfuscation" - encoding/compression/crypto used to hide payloads
 *
 * Imported by both find_flow_js.ql and the backward-slicing queries.
 */

import javascript

/** Holds if `call` is a call to a sensitive API, tagged with its `category`. */
predicate isSensitiveCall(DataFlow::InvokeNode call, string category) {
  category = "network" and
  (
    call = DataFlow::moduleMember(["http", "https"], ["request", "get"]).getACall()
    or
    call = DataFlow::globalVarRef("fetch").getACall()
    or
    call =
      DataFlow::moduleMember(["axios", "node-fetch", "request", "got", "superagent"], _)
          .getACall()
    or
    call = DataFlow::moduleMember("axios", ["get", "post", "put", "patch", "delete"]).getACall()
    or
    call = DataFlow::moduleMember("net", ["connect", "createConnection"]).getACall()
    or
    call = DataFlow::moduleMember(["ws", "websocket"], _).getAnInvocation()
    or
    call = DataFlow::moduleMember("dgram", "createSocket").getACall()
  )
  or
  category = "process_exec" and
  (
    call =
      DataFlow::moduleMember("child_process",
        ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"])
          .getACall()
    or
    call = DataFlow::globalVarRef("eval").getACall()
    or
    call = DataFlow::globalVarRef("Function").getAnInvocation()
    or
    call =
      DataFlow::moduleMember("vm", ["runInNewContext", "runInThisContext", "Script"])
          .getAnInvocation()
  )
  or
  category = "file_ops" and
  (
    call =
      DataFlow::moduleMember(["fs", "fs/promises"], [
          "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile",
          "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
          "rename", "renameSync", "copyFile", "copyFileSync", "mkdir", "mkdirSync", "chmod",
          "chmodSync", "chown", "chownSync"
        ])
          .getACall()
  )
  or
  category = "crypto_obfuscation" and
  (
    call =
      DataFlow::moduleMember("crypto", [
          "createCipheriv", "createDecipheriv", "createHash", "createHmac", "publicEncrypt",
          "privateDecrypt", "randomBytes"
        ])
          .getACall()
    or
    call = DataFlow::moduleMember("zlib", _).getACall()
    or
    call = DataFlow::globalVarRef(["atob", "btoa", "escape", "unescape"]).getACall()
  )
}

/**
 * Holds if `sink` is an argument of a sensitive API call, tagged with
 * `category`, with `call` itself exposed so callers can anchor on the call's
 * own location. This is the "V" / "s" in the slicing criterion C=<s,V>
 * (Step 2.2).
 */
predicate isSensitiveArg(DataFlow::Node sink, DataFlow::InvokeNode call, string category) {
  isSensitiveCall(call, category) and sink = call.getAnArgument()
}

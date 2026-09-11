/**
 * Shared "Sensitive API" catalogue for Python (Step 2.1 of the architecture).
 *
 * One place that defines every call CodeQL should treat as a malware-relevant
 * anchor, tagged by category:
 *   "network"            - data exfiltration / payload download
 *   "process_exec"       - process spawning / dynamic code execution
 *   "file_ops"           - filesystem read/write/delete
 *   "crypto_obfuscation" - encoding/compression/crypto used to hide payloads
 *
 * Both find_flow.ql (taint source->sink) and the backward-slicing queries
 * import this module, so the catalogue only needs to be maintained in one
 * place. Extend the disjunctions below as you discover more APIs to cover.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

/** Holds if `call` is a call to a sensitive API, tagged with its `category`. */
predicate isSensitiveCall(DataFlow::CallCfgNode call, string category) {
  category = "network" and
  (
    call =
      API::moduleImport("requests")
          .getMember(["get", "post", "put", "patch", "delete", "request", "head"])
          .getACall()
    or
    call =
      API::moduleImport("urllib")
          .getMember("request")
          .getMember(["urlopen", "urlretrieve"])
          .getACall()
    or
    call = API::moduleImport("urllib2").getMember("urlopen").getACall()
    or
    call =
      API::moduleImport("httpx")
          .getMember(["get", "post", "put", "patch", "delete", "request"])
          .getACall()
    or
    call =
      API::moduleImport("http")
          .getMember("client")
          .getMember(["HTTPConnection", "HTTPSConnection"])
          .getReturn()
          .getMember(["request", "putrequest"])
          .getACall()
    or
    call =
      API::moduleImport("socket")
          .getMember("socket")
          .getReturn()
          .getMember(["connect", "send", "sendall", "sendto"])
          .getACall()
    or
    call = API::moduleImport("ftplib").getMember("FTP").getACall()
    or
    call = API::moduleImport("smtplib").getMember(["SMTP", "SMTP_SSL"]).getACall()
    or
    call =
      API::moduleImport("paramiko")
          .getMember("SSHClient")
          .getReturn()
          .getMember("connect")
          .getACall()
    or
    call =
      API::moduleImport("aiohttp")
          .getMember("ClientSession")
          .getReturn()
          .getMember(["get", "post", "request"])
          .getACall()
  )
  or
  category = "process_exec" and
  (
    call =
      API::moduleImport("subprocess")
          .getMember(["run", "Popen", "call", "check_output", "check_call"])
          .getACall()
    or
    call =
      API::moduleImport("os")
          .getMember(["system", "popen", "popen2", "popen3", "popen4"])
          .getACall()
    or
    call =
      API::moduleImport("os")
          .getMember([
              "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"
            ])
          .getACall()
    or
    call =
      API::moduleImport("os")
          .getMember(["spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp"])
          .getACall()
    or
    call = API::builtin(["eval", "exec", "compile", "__import__"]).getACall()
    or
    call = API::moduleImport("importlib").getMember("import_module").getACall()
    or
    call = API::moduleImport("ctypes").getMember(["CDLL", "WinDLL", "PyDLL", "OleDLL"]).getACall()
    or
    call = API::moduleImport("multiprocessing").getMember("Process").getACall()
    or
    call = API::moduleImport("pty").getMember("spawn").getACall()
  )
  or
  category = "file_ops" and
  (
    call = API::builtin("open").getReturn().getMember(["write", "writelines"]).getACall()
    or
    call =
      API::moduleImport("os")
          .getMember([
              "remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace",
              "makedirs", "mkdir", "chmod", "chown"
            ])
          .getACall()
    or
    call =
      API::moduleImport("shutil")
          .getMember(["copy", "copyfile", "copy2", "move", "rmtree"])
          .getACall()
    or
    call =
      API::moduleImport("pathlib")
          .getMember("Path")
          .getReturn()
          .getMember(["write_text", "write_bytes", "unlink", "rmdir"])
          .getACall()
    or
    call =
      API::moduleImport("tempfile")
          .getMember(["NamedTemporaryFile", "mkstemp", "mkdtemp"])
          .getACall()
  )
  or
  category = "crypto_obfuscation" and
  (
    call = API::moduleImport("base64").getMember(_).getACall()
    or
    call = API::moduleImport("codecs").getMember(["encode", "decode"]).getACall()
    or
    call = API::moduleImport("marshal").getMember(["loads", "dumps"]).getACall()
    or
    call = API::moduleImport("pickle").getMember(["loads", "dumps", "load"]).getACall()
    or
    call = API::moduleImport("zlib").getMember(_).getACall()
    or
    call = API::moduleImport("gzip").getMember(_).getACall()
    or
    call = API::moduleImport("bz2").getMember(_).getACall()
    or
    call = API::moduleImport("lzma").getMember(_).getACall()
    or
    call = API::moduleImport("Crypto").getMember(_).getMember(_).getACall()
    or
    call = API::moduleImport("Cryptodome").getMember(_).getMember(_).getACall()
    or
    call = API::moduleImport("cryptography").getMember(_).getMember(_).getACall()
  )
}

/**
 * Holds if `sink` is an argument (positional or keyword) of a sensitive API
 * call, tagged with `category`, with `call` itself exposed so callers can
 * anchor on the call's own location (consistent with isSensitiveCall/the
 * control-flow slicing query) rather than the argument's location, which
 * can differ on multi-line calls. This is the "V" / "s" in the slicing
 * criterion C=<s,V> (Step 2.2).
 */
predicate isSensitiveArg(DataFlow::Node sink, DataFlow::CallCfgNode call, string category) {
  isSensitiveCall(call, category) and
  (sink = call.getArg(_) or sink = call.getArgByName(_))
}

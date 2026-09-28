/**
 * @name Constant arguments of calls
 * @description The data-flow slice abbreviates every call as "callee(...)", so the literal values passed
 *              to it are lost (the file name of open(...), the URL of requests.post(...), the command of
 *              subprocess.run([...])). This query lists, for every call with at least one constant
 *              argument, one row per constant argument: a string, bytes or integer literal, or a list /
 *              tuple of such literals, passed by position or by keyword. build_behavior_chain.py attaches
 *              the rows to the Behavior Chain whose anchor, slice nodes or confirmed flows are on the same
 *              file and line. No data flow is involved, so the query is fast.
 * @id py/malware/constant-call-arguments
 * @tags malware slicing
 *
 * OUTPUT (5 named columns): file, line, callee, arg (position or keyword name), value
 */

import python

/** "os.path.join" / "open" / "self.run" for the function part of a call. */
private string calleeText(Expr f) {
  exists(Name n | n = f | result = n.getId())
  or
  exists(Attribute a | a = f | result = calleeText(a.getObject()) + "." + a.getName())
  or
  not f instanceof Name and not f instanceof Attribute and result = "<expr>"
}

/** Text of a scalar constant: a string/bytes literal (quoted) or an integer literal. */
private string scalarText(Expr e) {
  exists(StringLiteral s | s = e | result = "\"" + s.getS() + "\"")
  or
  exists(IntegerLiteral i | i = e | result = i.getN())
}

/** Text of a constant argument: a scalar, or a list / tuple whose elements are all scalars. */
private string constText(Expr e) {
  result = scalarText(e)
  or
  exists(List l | l = e and exists(l.getAnElt()) and forall(Expr x | x = l.getAnElt() | exists(scalarText(x))) |
    result = "[" + concat(int i, string s | s = scalarText(l.getElt(i)) | s, ", " order by i) + "]"
  )
  or
  exists(Tuple t | t = e and exists(t.getAnElt()) and forall(Expr x | x = t.getAnElt() | exists(scalarText(x))) |
    result = "(" + concat(int i, string s | s = scalarText(t.getElt(i)) | s, ", " order by i) + ")"
  )
}

from Call c, string arg, string value
where
  exists(int i | value = constText(c.getArg(i)) and arg = i.toString())
  or
  exists(Keyword k | k = c.getANamedArg() and value = constText(k.getValue()) and arg = k.getArg())
select c.getLocation().getFile().getRelativePath() as file, c.getLocation().getStartLine() as line,
  calleeText(c.getFunc()) as callee, arg, value

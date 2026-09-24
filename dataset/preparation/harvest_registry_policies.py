"""
harvest_registry_policies.py

Extracts, VERBATIM, the clauses of the public package-registry policies that
define prohibited package behaviour (no rewording by us):
  * PyPI Acceptable Use Policy       - "Active Malware or Exploits", unauthorized access
  * npm Open-Source Terms            - "Acceptable Content" (malicious code, name squatting)
  * GitHub Active Malware or Exploits policy (also the stated position on npm)

Writes policy_sources/registry_policies.json (same {source, rules} format).
Usage: python3 harvest_registry_policies.py
"""
import html
import json
import os
import re
import urllib.request

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy_sources", "registry_policies.json")
PYPI = "https://pypi.org/policy/acceptable-use-policy/"
NPM = "https://docs.npmjs.com/policies/open-source-terms"
GH = "https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits"


def paragraphs(url, article_only=False):
    raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=60).read().decode("utf-8", "replace")
    if article_only:
        m = re.search(r"<article.*?</article>|<main.*?</main>", raw, re.S)
        raw = m.group(0) if m else raw
    raw = re.sub(r"<script.*?</script>|<style.*?</style>|<nav.*?</nav>|<header.*?</header>|<footer.*?</footer>", "", raw, flags=re.S)
    raw = re.sub(r"</?(p|li|ul|ol|h[1-6]|div|br|tr|table|section|article)[^>]*>", "\n", raw)
    text = html.unescape(re.sub(r"<[^>]+>", "", raw))
    return [re.sub(r"\s+", " ", p).strip() for p in text.split("\n") if p.strip()]


def span(paras, start, end=None, include_end=False):
    i = next(k for k, p in enumerate(paras) if p.startswith(start))
    if end is None:
        return paras[i]
    j = next(k for k in range(i + 1, len(paras)) if paras[k].startswith(end))
    return " ".join(paras[i:j + (1 if include_end else 0)])


def main():
    py, npm, gh = paragraphs(PYPI), paragraphs(NPM), paragraphs(GH, article_only=True)
    rules = [
        ("PYPI-AUP-ACTIVE-MALWARE", "PyPI AUP: Active Malware or Exploits",
         span(py, "Being part of a community includes not taking advantage", "Advertising"), PYPI),
        ("PYPI-AUP-UNAUTHORIZED-ACCESS", "PyPI AUP: Unauthorized access / disruption",
         span(py, "You may not use our servers to disrupt", "You may not use information from PyPI"), PYPI),
        ("NPM-TERMS-MALICIOUS-CODE", "npm Terms: Acceptable Content - malicious computer code",
         span(npm, "Content containing malicious computer code"), NPM),
        ("NPM-TERMS-NAME-SQUATTING", "npm Terms: Acceptable Content - name reservation / squatting",
         span(npm, 'Content that exists only to "reserve" a name'), NPM),
        ("GITHUB-AUP-ACTIVE-MALWARE", "GitHub AUP: Active Malware or Exploits",
         span(gh, "Being part of a community includes not taking advantage"), GH),
        ("GITHUB-AUP-NPM-REGISTRY", "GitHub AUP: npm registry is for installation and run-time use, not research",
         span(gh, "GitHub considers the npm registry"), GH),
    ]
    out = {"source": "Package Registry Acceptable-Use Policies (PyPI / npm / GitHub)",
           "rules": [{"id": i, "name": n, "description": f"{d} [Source: {u}]"} for i, n, d, u in rules]}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4, ensure_ascii=False)
    print(f"[+] {len(rules)} verbatim clauses -> {OUT}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
report-check.py — lint a forensic report. It will never tell you it passes.

It checks the things a reviewer checks first, because they are mechanical and
because getting them wrong discredits everything else:

  sections     every section of the structure is present and not empty
  findings     each F-nn cites at least one evidence ID, states a confidence
               from the scale, and records the alternatives considered
  evidence     every E-nn cited anywhere exists in the evidence register
  time         every timestamp says it is UTC (Z, UTC, or a UTC table column)
  absolutes    "certainly", "proves", "definitely"... flagged, and flagged hard
               when the sentence cites no evidence
  personal     IBANs, NIF/NISS-like numbers, phone numbers and unknown mailboxes
               — a forensic report describes data subjects, it never lists them
  executive    the summary fits a page and is free of analyst jargon
  leftovers    TODO placeholders from report-scaffold.py

Usage
    ./report-check.py my-report.md
    ./report-check.py my-report.md --register work/case-bundle/evidence-register.csv
    ./report-check.py my-report.md --quiet        problems only, no warnings
    ./report-check.py summary.md --summary-only   a draft executive summary on its own
                                                  (skips the checks that need a whole report)

Exit status: 1 if there are problems, 0 otherwise.

Why it refuses to say "pass": it can tell whether your findings are traceable,
not whether they are true. A report can satisfy every rule here and still be
wrong about patient zero. The judgement is yours, and then your reviewer's.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

REQUIRED = [  # (label, any of these words in a heading)
    ("case data / cover", ["case data", "cover"]),
    ("executive summary", ["executive summary"]),
    ("scope and questions", ["scope"]),
    ("evidence inventory and custody", ["evidence inventory", "chain of custody", "evidence"]),
    ("methodology and tools", ["methodology"]),
    ("time / clock sources", ["clock", "time:"]),
    ("timeline", ["timeline"]),
    ("findings", ["findings"]),
    ("attack narrative", ["narrative", "att&ck"]),
    ("impact", ["impact"]),
    ("what is not known", ["not known", "limitation"]),
    ("recommendations", ["recommendation"]),
    ("declaration", ["declaration"]),
    ("indicators of compromise", ["indicator", "ioc"]),
    ("commands as run", ["commands"]),
]

CONF_WORDS = ("high", "moderate", "low")
ABSOLUTES = re.compile(r"\b(certainly|definitely|undoubtedly|unquestionabl\w*|indisputabl\w*|irrefutabl\w*|"
                       r"beyond (?:any |all )?doubt|without (?:any )?doubt|conclusively|prove[sdn]?|proving|"
                       r"proof that|guarantee[sd]?|obviously|clearly shows|impossible|no doubt)\b|\b100 ?%", re.I)
EID = re.compile(r"\bE-\d{2,3}\b")
FID = re.compile(r"\bF-\d{2,3}\b")
DATETIME = re.compile(r"\b(20\d\d-\d\d-\d\d)[ T](\d\d:\d\d(?::\d\d)?(?:\.\d+)?)(Z|\s?UTC|\+00:?00)?")
TIME_ONLY = re.compile(r"(?<![\d:.-])(\d\d:\d\d:\d\d)(?![\d:])(?:\.\d+)?(Z|\s?UTC)?")
JARGON = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f]{32,64}|T1\d{3}(?:\.\d{3})?|EID|event ?id|"
                    r"LSASS|rundll32|powershell|Sysmon|USN|\$MFT|rclone|7za|ATT&CK|C2|TTPs?|IOCs?)\b|\b[A-Z]:\\(?=\w)", re.I)
IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?)\b")
NINE = re.compile(r"(?<![\w.,/-])(\d{9})(?![\w/-])(?![.,]\d)")
ELEVEN = re.compile(r"(?<![\w.,/-])([12]\d{10})(?![\w/-])(?![.,]\d)")
PHONE = re.compile(r"(?:\+351[ .]?)?\b(9[1236]\d[ .]?\d{3}[ .]?\d{3}|2\d{2}[ .]?\d{3}[ .]?\d{3})\b")
MAIL = re.compile(r"\b([\w.+-]+)@ceres-alimentar\.example\.com\b", re.I)
# Mailboxes that belong to people and functions the case itself names: actors and
# responders, not data subjects. Anything else at the company domain is flagged.
KNOWN_MAILBOXES = {"m.antunes", "j.pires", "r.calado", "a.fonseca", "l.moreira", "s.teixeira",
                   "c.nogueira", "t.matos", "r.serrano", "contas.pagar", "h.vaz", "p.ramos",
                   "c.mendes", "i.barros", "dpo", "it-incident", "geral", "marketing", "it-alerts"}


class Report:
    def __init__(self, path):
        raw = Path(path).read_text(encoding="utf-8")
        self.path = path
        # Blank out HTML comments (scaffold guidance) but keep line numbers.
        raw = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), raw, flags=re.S)
        self.lines = raw.split("\n")
        self.code = set()
        inside = False
        for i, ln in enumerate(self.lines):
            if ln.lstrip().startswith("```"):
                inside = not inside
                self.code.add(i)
            elif inside:
                self.code.add(i)
        self.headings = [(i, len(m.group(1)), m.group(2).strip())
                         for i, ln in enumerate(self.lines)
                         if i not in self.code and (m := re.match(r"^(#{1,6})\s+(.*)$", ln))]

    def section(self, words, level=2):
        """(start, end) line range of the first heading whose text contains any word."""
        for k, (i, lvl, text) in enumerate(self.headings):
            if lvl <= level and any(w in text.lower() for w in words):
                end = len(self.lines)
                for j, lvl2, _ in self.headings[k + 1:]:
                    if lvl2 <= lvl:
                        end = j
                        break
                return i, end
        return None

    def prose(self, a, b):
        return [(i, self.lines[i]) for i in range(a, b) if i not in self.code]


def mod97_ok(iban):
    s = iban.replace(" ", "")
    s = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in s)) % 97 == 1
    except ValueError:
        return False


def nif_ok(n):
    if n[0] not in "12356789":
        return False
    total = sum(int(d) * w for d, w in zip(n[:8], range(9, 1, -1)))
    check = 11 - total % 11
    return int(n[8]) == (0 if check >= 10 else check)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("--register", default=None,
                    help="evidence-register.csv (default: work/case-bundle/evidence-register.csv if it exists)")
    ap.add_argument("--quiet", action="store_true", help="show problems only")
    ap.add_argument("--summary-only", action="store_true",
                    help="the file holds only an executive summary: skip the section, findings, "
                         "recommendation and timeline checks")
    args = ap.parse_args()

    if not Path(args.report).is_file():
        sys.exit(f" fail  no such file: {args.report}")
    R = Report(args.report)
    problems, warnings = [], []

    def P(i, msg):
        problems.append((i + 1 if i is not None else 0, msg))

    def W(i, msg):
        warnings.append((i + 1 if i is not None else 0, msg))

    # --- register --------------------------------------------------------------
    reg_path = args.register or "work/case-bundle/evidence-register.csv"
    known_ids = None
    if Path(reg_path).is_file():
        with open(reg_path, encoding="utf-8") as fh:
            known_ids = {r["id"] for r in csv.DictReader(fh)}
    else:
        W(None, f"no evidence register at {reg_path}: evidence IDs NOT verified (use --register)")

    # --- sections ----------------------------------------------------------------
    for label, words in ([] if args.summary_only else REQUIRED):
        rng = R.section(words)
        if rng is None:
            P(None, f"missing section: {label}")
            continue
        a, b = rng
        body = " ".join(R.lines[a + 1:b])   # code counts here: Appendix B is mostly code
        n = len(re.findall(r"[A-Za-z]{2,}", body.replace("TODO", "")))
        if n < 15:
            P(a, f"section '{R.lines[a].lstrip('# ')}' is empty or nearly ({n} words)")

    # --- leftovers ---------------------------------------------------------------
    todo = [i for i, ln in enumerate(R.lines) if "TODO" in ln and i not in R.code]
    if todo:
        P(todo[0], f"{len(todo)} line(s) still contain TODO (first at line {todo[0] + 1})")

    # --- evidence IDs everywhere ---------------------------------------------------
    cited = {}
    for i, ln in enumerate(R.lines):
        for e in EID.findall(ln):
            cited.setdefault(e, i)
    if known_ids is not None:
        for e, i in sorted(cited.items()):
            if e not in known_ids:
                P(i, f"{e} is cited but is not in the evidence register")

    # --- findings ------------------------------------------------------------------
    fsec = None if args.summary_only else R.section(["findings"])
    findings = [] if args.summary_only else \
        [(i, text) for i, lvl, text in R.headings if lvl >= 3 and re.match(r"F-\d{2,3}\b", text)]
    if fsec and not findings:
        P(fsec[0], "no findings in the F-nn format (### F-01 — statement)")
    seen = set()
    for k, (i, text) in enumerate(findings):
        fid = text.split()[0]
        if fid in seen:
            P(i, f"{fid} is used twice")
        seen.add(fid)
        end = findings[k + 1][0] if k + 1 < len(findings) else (fsec[1] if fsec and fsec[0] < i < fsec[1] else len(R.lines))
        block = R.lines[i:end]
        btxt = "\n".join(block)
        if not EID.search(btxt):
            P(i, f"{fid} cites no evidence ID (E-nn)")
        m = re.search(r"confidence\W*:?\**\s*:?\s*\**\s*(\w+)", btxt, re.I)
        if not m:
            P(i, f"{fid} states no confidence")
        elif m.group(1).lower() not in CONF_WORDS:
            P(i, f"{fid} confidence '{m.group(1)}' is not on the scale ({' / '.join(CONF_WORDS)})")
        elif not re.search(r"confidence[^\n]*(because|—|-|:)[^\n]*\w{4,}[^\n]*\w{4,}", btxt, re.I):
            W(i, f"{fid} gives a confidence level without saying why")
        alt = re.search(r"alternative[^\n:]*:\**\s*(.*)", btxt, re.I)
        if not alt or len(re.findall(r"\w+", alt.group(1))) < 4:
            P(i, f"{fid} records no alternative explanations (write the ones you rejected, and why)")
        if not re.search(r"type\W*:?\**\s*:?\s*\**\s*(fact|inference)", btxt, re.I):
            W(i, f"{fid} does not say whether it is a fact or an inference")

    # --- time ------------------------------------------------------------------------
    utc_table = False
    for i, ln in enumerate(R.lines):
        if i in R.code:
            continue
        s = ln.strip()
        if s.startswith("|"):
            if not utc_table and re.search(r"\bUTC\b", s) and i + 1 < len(R.lines) and "---" in R.lines[i + 1]:
                utc_table = True
        else:
            utc_table = False
        if utc_table or re.search(r"\bUTC\b", ln):
            continue
        for m in DATETIME.finditer(ln):
            if not m.group(3):
                P(i, f"timestamp '{m.group(0).strip()}' has no zone (write Z or UTC)")
        for m in TIME_ONLY.finditer(ln):
            if m.group(2):
                continue
            if any(d.start() <= m.start() <= d.end() for d in DATETIME.finditer(ln)):
                continue
            W(i, f"time '{m.group(1)}' with no zone on this line — UTC? which clock?")

    # --- absolutes ------------------------------------------------------------------
    for i, ln in enumerate(R.lines):
        if i in R.code:
            continue
        for m in ABSOLUTES.finditer(ln):
            if EID.search(ln) or FID.search(ln):
                W(i, f"'{m.group(0)}' — absolute language; is the evidence on this line really that strong?")
            else:
                P(i, f"'{m.group(0)}' with no evidence cited on the line — unsupported absolute")

    # --- personal data ------------------------------------------------------------------
    for i, ln in enumerate(R.lines):
        for m in IBAN.finditer(ln):
            if mod97_ok(m.group(1)):
                P(i, "an IBAN — personal data of a data subject does not belong in the report")
        for m in NINE.finditer(ln):
            if nif_ok(m.group(1)) and not re.search(re.escape(m.group(1)) + r"\s*(bytes|B\b)", ln):
                W(i, f"'{m.group(1)}' is a valid Portuguese NIF checksum — if it is a person's NIF, remove it")
        for m in ELEVEN.finditer(ln):
            if not re.search(re.escape(m.group(1)) + r"\s*(bytes|B\b)", ln):
                W(i, f"'{m.group(1)}' looks like a NISS (11 digits) — if so, remove it")
        for m in PHONE.finditer(ln):
            W(i, f"'{m.group(0).strip()}' looks like a phone number — whose?")
        for m in MAIL.finditer(ln):
            if m.group(1).lower() not in KNOWN_MAILBOXES:
                W(i, f"mailbox '{m.group(0)}' is not one the case names — is this a data subject?")

    # --- executive summary --------------------------------------------------------------
    es = R.section(["executive summary"])
    if args.summary_only and not es:
        P(None, "no '## 1. Executive summary' heading — put your draft under one")
    if es:
        prose = [(i, t) for i, t in R.prose(es[0] + 1, es[1])]
        words = sum(len(re.findall(r"\b\w[\w'’-]*\b", t)) for _, t in prose)
        if words > 650:
            P(es[0], f"executive summary is {words} words — it must fit one page (aim for 300-500)")
        elif words > 500:
            W(es[0], f"executive summary is {words} words — tight for one page")
        hits = []
        for i, t in prose:
            hits += [(i, m.group(0)) for m in JARGON.finditer(t)]
        if hits:
            sample = ", ".join(sorted({h for _, h in hits})[:8])
            W(hits[0][0], f"executive summary uses analyst vocabulary ({len(hits)}x: {sample}) — write for the board")
        if es and not re.search(r"not (yet )?(known|clear|establish|determin|confirm)|(do|does|did)(n't| not) (yet )?know|unknown|unclear|could not|cannot|open question", " ".join(t for _, t in prose), re.I):
            W(es[0], "executive summary does not say what is NOT known")

    # --- recommendations tied to findings ----------------------------------------------
    rs = None if args.summary_only else R.section(["recommendation"])
    if rs:
        rows = [(i, t) for i, t in R.prose(rs[0] + 1, rs[1])
                if (t.strip().startswith("|") and not re.match(r"^\|\s*[-#]", t.strip()) and "Recommendation" not in t)
                or re.match(r"^\s*([-*]|\d+\.)\s+", t)]
        loose = [i for i, t in rows if not FID.search(t)]
        if rows and loose:
            W(loose[0], f"{len(loose)} recommendation(s) do not name the finding (F-nn) they come from")

    # --- timeline ------------------------------------------------------------------------
    tl = None if args.summary_only else R.section(["timeline"])
    if tl:
        rows = [t for _, t in R.prose(tl[0] + 1, tl[1]) if t.strip().startswith("|") and re.search(r"\d\d:\d\d", t)]
        if len(rows) < 10:
            W(tl[0], f"timeline has {len(rows)} timed rows — is that the whole attack?")
        noev = [t for t in rows if not EID.search(t)]
        if noev:
            W(tl[0], f"{len(noev)} timeline row(s) cite no evidence ID")

    # --- report ------------------------------------------------------------------------------
    print()
    print(f"  {args.report}  —  {len(findings)} finding(s), {len(cited)} evidence ID(s) cited"
          + ("" if known_ids is None else f", register has {len(known_ids)}"))
    print()
    if problems:
        print(f"  PROBLEMS ({len(problems)}) — fix these:")
        for ln, msg in sorted(problems):
            print(f"    {('line ' + str(ln)) if ln else '':>10}  {msg}")
        print()
    if warnings and not args.quiet:
        print(f"  WARNINGS ({len(warnings)}) — judge each one:")
        for ln, msg in sorted(warnings):
            print(f"    {('line ' + str(ln)) if ln else '':>10}  {msg}")
        print()
    if problems:
        print("  Not ready. A reviewer would stop at the first of these.")
    else:
        print("  No mechanical problems found. That is not a pass: this script checked that your")
        print("  findings are traceable, dated and hedged — not that they are right. Now give it")
        print("  to a colleague who will try to prove you wrong.")
    print()
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

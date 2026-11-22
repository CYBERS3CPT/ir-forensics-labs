#!/usr/bin/env python3
"""
report-scaffold.py — the skeleton of the forensic report, with the prompts in place.

The structure follows the logic of ISO/IEC 27037 (identify, collect, acquire,
preserve) and ISO/IEC 27042 (analyse, interpret, report): the reader can see
what you had, how you handled it, what you did to it, what it shows, how sure
you are, and what you could not establish. It is not a certified template; it
is the shape that lets another examiner reproduce your work and a non-expert
reader act on it.

Usage
    ./report-scaffold.py --case INC-2026-007 --author "Your Name" --out my-report.md
    ./report-scaffold.py --register work/case-bundle/evidence-register.csv --author "Your Name"
    ./report-scaffold.py --sections            list the sections and what each is for

With --register, the evidence inventory is pre-filled from the register (IDs,
paths, hashes). Everything else is yours to write.

Guidance sits in HTML comments (<!-- ... -->): it does not show when the
Markdown is rendered, and report-check.py ignores it. Placeholders are TODO;
report-check.py lists every one you leave behind.

Write the executive summary LAST. It is the first thing read and the last
thing knowable.
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

SECTIONS = [
    ("0. Case data", "who asked, who wrote, when, which version — the cover page"),
    ("1. Executive summary", "one page for the board: what happened, impact, what is not known, what to decide"),
    ("2. Scope and questions", "the questions you were asked, and what is out of scope"),
    ("3. Evidence inventory and chain of custody", "every item with ID, hash, source, custody"),
    ("4. Methodology and tools", "what you did, with which tool and which version, and the confidence scale"),
    ("5. Time: clock sources and corrections", "which clocks, which offsets, applied where — once"),
    ("6. Timeline", "the reduced timeline, all UTC, each row with its evidence ID"),
    ("7. Findings", "each: statement, evidence, confidence, alternatives considered"),
    ("8. Attack narrative", "the story, in order, mapped to ATT&CK — built from the findings"),
    ("9. Impact", "systems, data, data subjects, special categories, regulatory relevance"),
    ("10. What is not known", "limitations and open questions, and what would close them"),
    ("11. Recommendations", "each tied to a finding, specific enough to act on"),
    ("12. Declaration", "the examiner's statement of independence and of the limits of the opinion"),
    ("Appendix A — Indicators of compromise", "for the people who will hunt and block"),
    ("Appendix B — Commands as run", "so another examiner can reproduce every finding"),
    ("Appendix C — Review of third-party findings", "where you agree or disagree with earlier reports, and why"),
]

TEMPLATE = """# Forensic Report — {case}

<!-- Mark every page of the exported report with the classification line below. -->
**Classification:** CONFIDENTIAL — prepared at the request of {client}

## 0. Case data

| | |
|---|---|
| Case / incident reference | {case} |
| Client | {client} |
| Requested by | TODO (name, role, date of the instruction) |
| Examiner | {author} |
| Report version | 1.0 — {today} |
| Period examined | TODO (first and last timestamp of the evidence you examined, UTC) |
| Evidence bundle | TODO (MANIFEST.tsv SHA-256, from bundle.sh) |
| Distribution | TODO (who may read this) |

## 1. Executive summary

<!-- ONE page, for the board, the insurer and the DPO. No IP addresses, hashes,
     ATT&CK IDs, file paths or tool names. Answer, in this order:
       What happened, and when (dates, not seconds).
       How it started.
       What was affected: systems, data, people.
       Was data taken? How sure are you?
       What we do NOT know yet.
       The two or three decisions or actions that matter now.
     Write it last. Then ask someone who is not technical to read it. -->

TODO

## 2. Scope and questions

<!-- The questions you were asked. Answer each one explicitly in the findings
     or in section 10, and only those. A report that answers questions nobody
     asked is a report that will be asked about them in court. -->

| # | Question | Answered in |
|---|---|---|
| Q1 | How and when did the attacker first get in? Which host was first compromised? | TODO |
| Q2 | What did the attacker do, in what order, on which hosts? | TODO |
| Q3 | Was data taken? What, how much, when, and to where? | TODO |
| Q4 | Which categories of personal data and how many data subjects are affected? | TODO |
| Q5 | Did anyone else receive the phishing email, and did anyone else act on it? | TODO |
| Q6 | Are the panel firm's initial findings (12 March) correct? | TODO |

**Out of scope:** TODO (e.g. attribution to a named group; recovery of encrypted files; legal advice).

**Authority / instruction:** TODO (who instructed the examination, under what agreement).

## 3. Evidence inventory and chain of custody

<!-- Every item you rely on, with its ID from evidence-register.py and its
     SHA-256. Say where each came from and how it reached you (the HANDOVER
     and the session READMEs tell you). If an item's hash did not verify, say so
     here and do not rely on it. -->

Bundle built with `bundle.sh` on TODO (UTC); MANIFEST.tsv SHA-256 TODO.

{inventory}

**Custody notes:** TODO (who collected what, when, with which tool; deviations — e.g. commands run on a live system before imaging).

## 4. Methodology and tools

<!-- What you did, in enough detail to repeat it. Every tool WITH ITS VERSION.
     Name the standard you followed and any deviation. -->

Approach: TODO (e.g. ISO/IEC 27037 for handling, ISO/IEC 27042 for analysis and interpretation; work on read-only copies; every finding traceable to an evidence ID).

| Tool | Version | Used for |
|---|---|---|
| TODO | TODO | TODO |

**Confidence scale used in this report:**

| Level | Meaning |
|---|---|
| High | Two or more independent sources agree, and no reasonable alternative explanation remains. |
| Moderate | One reliable source, or several that are not independent; alternatives are unlikely but not excluded. |
| Low | Inference from indirect or incomplete evidence; plausible, and stated so it can be tested. |

## 5. Time: clock sources and corrections

<!-- One paragraph, then never mention time zones again: everything below is UTC.
     For each source: which clock wrote it, how you know whether it was right,
     what correction you applied, and where. Show the evidence for any offset. -->

| Source (evidence IDs) | Clock | Offset found | How established | Correction applied |
|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO |

## 6. Timeline

<!-- Reduced: the events that matter, not everything you saw. All times UTC
     (corrected). One evidence ID per row at least. Mark benign events as
     benign rather than deleting them: the reader needs to see you considered them. -->

| Time (UTC) | Host | Event | Evidence | ATT&CK |
|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO |

## 7. Findings

<!-- One block per finding. A finding is what the evidence shows; an inference is
     what you conclude from it — label which is which. Each finding needs:
     at least one evidence ID, a confidence level from the scale in section 4,
     and the alternative explanations you considered and why you rejected them
     (or why you could not). Copy the block for F-02, F-03, ... -->

### F-01 — TODO (one-line statement)

- **Type:** Fact | Inference
- **Statement:** TODO
- **Evidence:** TODO (E-nn: which record, line or field)
- **Confidence:** TODO (High | Moderate | Low) — because TODO
- **Alternative explanations considered:** TODO
- **Answers:** TODO (Q1..Q6)

## 8. Attack narrative

<!-- The story, in order, in prose a manager can follow — built only from the
     findings above (cite them: F-nn). Then the ATT&CK mapping. -->

TODO

| Tactic | Technique (ID) | Where / when (UTC) | Finding |
|---|---|---|---|
| TODO | TODO | TODO | TODO |

## 9. Impact

<!-- Systems (confidentiality, integrity, availability, each). Data: categories,
     counts (aggregate only — NEVER paste personal data from the evidence into a
     report), which were copied and which only encrypted, special categories
     (GDPR art. 9). What this means for the notification obligations — as facts
     for the DPO and counsel, not as legal advice. -->

TODO

## 10. What is not known

<!-- The section that separates an honest report from a confident one. Be
     specific: what you could not establish, why, which findings it affects, and
     what evidence would close it. "More time would have helped" is not a
     limitation. -->

TODO

## 11. Recommendations

<!-- Each one tied to the finding it comes from (F-nn), specific enough to act
     on, with a priority. "Improve security awareness" is not a recommendation;
     "turn workstation EDR from audit to block mode" is. -->

| # | Recommendation | From finding | Priority |
|---|---|---|---|
| R-01 | TODO | TODO | TODO |

## 12. Declaration

I, {author}, declare that this report is my own work; that the opinions in it are
my own and were formed on the evidence listed in section 3; that I have stated
the limits of that evidence in section 10; and that I have no interest in the
outcome of this matter. Where facts are within my own knowledge I have said so;
where they come from others I have named the source.

Signed: {author} — date (UTC): TODO

## Appendix A — Indicators of compromise

| Type | Value | Context | Evidence |
|---|---|---|---|
| TODO | TODO | TODO | TODO |

## Appendix B — Commands as run

<!-- The commands that produced each finding, exactly as you ran them, in the
     order you ran them. Paste from your notes file. -->

```
TODO
```

## Appendix C — Review of third-party findings

<!-- The panel firm's memo of 12 March. For each of its claims: agree /
     disagree / cannot assess, with the evidence. Be fair: say what it got right. -->

| Memo claim | Your assessment | Evidence |
|---|---|---|
| TODO | TODO | TODO |
"""


def inventory_from(register):
    try:
        with open(register, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except OSError as e:
        sys.exit(f" fail  cannot read the register: {e}")
    if not rows or "id" not in rows[0]:
        sys.exit(f" fail  {register} is not an evidence-register.csv")
    out = ["| ID | Item | SHA-256 | Source / how received | Relied on? |", "|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['id']} | `{r['path']}` | `{r['sha256']}` | TODO | TODO |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case", default="INC-2026-007")
    ap.add_argument("--client", default="Ceres Alimentar, S.A.")
    ap.add_argument("--author", default="TODO (your name)")
    ap.add_argument("--register", help="evidence-register.csv from evidence-register.py")
    ap.add_argument("--out", default="report.md")
    ap.add_argument("--sections", action="store_true", help="list the sections and exit")
    args = ap.parse_args()

    if args.sections:
        print()
        for name, why in SECTIONS:
            print(f"  {name:<46} {why}")
        print()
        return

    inventory = inventory_from(args.register) if args.register else (
        "| ID | Item | SHA-256 | Source / how received | Relied on? |\n|---|---|---|---|---|\n"
        "| TODO | TODO | TODO | TODO | TODO |")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    text = TEMPLATE.format(case=args.case, client=args.client, author=args.author,
                           inventory=inventory, today=today)
    out = Path(args.out)
    if out.exists():
        sys.exit(f" fail  {out} exists — not overwriting your draft (choose another --out)")
    out.write_text(text, encoding="utf-8")
    print(f"  wrote {out}")
    print()
    print("  Fill it in order 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11, then 1 last.")
    print(f"  When you think it is done:  ./report-check.py {out}")
    print()


if __name__ == "__main__":
    main()

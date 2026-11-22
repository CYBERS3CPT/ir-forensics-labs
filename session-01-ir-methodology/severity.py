#!/usr/bin/env python3
"""
severity.py — impact x urgency -> P1..P4, with the reasoning written down.

A severity is only useful if two people, rating the same incident at 03h00
without talking to each other, land on the same answer. That happens when the
definitions come with worked examples from YOUR organisation, agreed before
the incident. An abstract definition gets argued about; an example does not.

Usage
    ./severity.py grid                               print the matrix
    ./severity.py score --impact high --urgency medium
    ./severity.py rate                               answer eight questions, get a priority and a justification
    ./severity.py rate --at "2026-03-11 08:31"       ... and stamp the rating with the scenario time (UTC)
    ./severity.py matrix -o severity-matrix.md       write the matrix template for Ceres (deliverable)
    ./severity.py check severity-matrix.md           is it filled in? does it say anything?

The grid is the easy part. The impact and urgency definitions, with worked
examples, are the deliverable.
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

LEVELS = ["low", "medium", "high"]
# rows: impact, cols: urgency. Two P1 cells in the high-impact row and one in
# the high-urgency column — not five. If everything is P1, nothing is.
GRID = {
    ("high", "high"): "P1", ("high", "medium"): "P1", ("high", "low"): "P2",
    ("medium", "high"): "P1", ("medium", "medium"): "P2", ("medium", "low"): "P3",
    ("low", "high"): "P2", ("low", "medium"): "P3", ("low", "low"): "P4",
}
RESPONSE = {
    "P1": "incident manager now, executive informed within 1 h, all hands, regulatory assessment started",
    "P2": "incident manager within 1 h, business hours + agreed overtime, DPO informed if personal data",
    "P3": "next business day, normal queue, owner named",
    "P4": "backlog; fix the cause, tune the detection",
}


def score(impact, urgency):
    return GRID[(impact, urgency)]


def cmd_grid(_a):
    print(f"  {'':<16}" + "".join(f"{'urgency ' + u:<16}" for u in LEVELS))
    for imp in reversed(LEVELS):
        print(f"  {'impact ' + imp:<16}" + "".join(f"{score(imp, u):<16}" for u in LEVELS))
    print()
    for p, r in RESPONSE.items():
        print(f"  {p}  {r}")


def cmd_score(a):
    p = score(a.impact, a.urgency)
    print(f"impact {a.impact} x urgency {a.urgency} -> {p}")
    print(f"  {RESPONSE[p]}")


def yn(q):
    while True:
        try:
            r = input(f"  {q} [y/n/?] ").strip().lower()
        except EOFError:
            print()
            sys.exit("aborted (no input)")
        if r in ("y", "yes"):
            return True
        if r in ("n", "no"):
            return False
        if r == "?":
            return None
        print("    y, n, or ? for 'do not know yet'")


# Impact questions: what is hurt. Urgency questions: how fast it gets worse.
# "Do not know" is a legitimate answer at 08:31 — and it counts UP, not down,
# until somebody finds out. Rating unknowns as "no" is how P1s start as P3s.
IMPACT_Q = [
    ("process", "Is a business process stopped or degraded (e.g. deliveries, invoicing, payroll)?"),
    ("pdata", "Is personal data, or other regulated data, affected (confidentiality, integrity or availability)?"),
    ("tier1", "Is a Tier 1 asset affected (DC, file server, backups, firewall)?"),
    ("scale", "Is more than one team, site or about 20 users affected?"),
]
URGENCY_Q = [
    ("active", "Could the adversary still be active or still have access?"),
    ("spread", "Is it spreading, or could it spread to other hosts?"),
    ("leaving", "Could data be leaving, or have left?"),
    ("clock", "Has a regulatory or contractual clock started (NIS2, GDPR, insurer)?"),
]


def level_from(answers):
    # yes = 1, unknown = 1 (until proven otherwise), no = 0
    n = sum(1 for v in answers if v is not False)
    return "high" if n >= 2 else "medium" if n == 1 else "low"


def cmd_rate(a):
    print("Impact — what is hurt")
    ia = {k: yn(q) for k, q in IMPACT_Q}
    print("Urgency — how fast it gets worse")
    ua = {k: yn(q) for k, q in URGENCY_Q}
    imp, urg = level_from(ia.values()), level_from(ua.values())
    p = score(imp, urg)
    when = a.at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    print()
    print(f"Rating at {when} UTC: impact {imp}, urgency {urg} -> {p}")
    for label, qs, ans in (("impact", IMPACT_Q, ia), ("urgency", URGENCY_Q, ua)):
        for k, q in qs:
            v = ans[k]
            mark = "yes" if v else "UNKNOWN (counted as yes)" if v is None else "no"
            print(f"  {label:<8} {mark:<25} {q}")
    unk = [k for k, v in {**ia, **ua}.items() if v is None]
    if unk:
        print(f"\n  {len(unk)} unknown(s). Each one is a question for the next hour, "
              "and the rating comes down only when it is answered — with evidence.")
    print(f"\n  {RESPONSE[p]}")
    print("  Severity is re-rated, not fixed. Record the next rating with its own time.")


TEMPLATE = """# Severity matrix — Ceres Alimentar, S.A.

| | |
|---|---|
| Owner | ____ |
| Approved by | ____ |
| Version / date (UTC) | ____ |

Impact x urgency. Both defined **with worked examples from Ceres**, before the
incident. Re-rate during the incident; every rating carries its own UTC time.

## Grid

|                   | Low urgency | Medium urgency | High urgency |
|-------------------|-------------|----------------|--------------|
| **High impact**   | P2          | P1             | **P1**       |
| **Medium impact** | P3          | P2             | P1           |
| **Low impact**    | P4          | P3             | P2           |

## What each priority triggers

| Priority | Who is called, how fast | Who must be informed | Working hours |
|---|---|---|---|
| P1 | ____ | ____ | ____ |
| P2 | ____ | ____ | ____ |
| P3 | ____ | ____ | ____ |
| P4 | ____ | ____ | ____ |

## Impact — definitions for Ceres

| Level | Means at Ceres | Ceres example |
|---|---|---|
| High | ____ | ____ |
| Medium | ____ | ____ |
| Low | ____ | ____ |

## Urgency — definitions for Ceres

| Level | Means | Ceres example |
|---|---|---|
| High | ____ | ____ |
| Medium | ____ | ____ |
| Low | ____ | ____ |

## Unknowns

How does an unknown count (e.g. "personal data affected? we do not know yet")?
____

## Ratings of this incident

Paste the output of `./severity.py rate --at "..."` here, one block per rating,
each with its own time (UTC). Answer only with what was known at that time.

```
____
```

## Worked examples — at least six, from the Ceres evidence

| # | Situation (with time, UTC) | Impact | Urgency | Priority | Why (one line, with evidence) |
|---|---|---|---|---|---|
| 1 | ____ | | | | |
| 2 | ____ | | | | |
| 3 | ____ | | | | |
| 4 | ____ | | | | |
| 5 | ____ | | | | |
| 6 | ____ | | | | |

---
*Everything cannot be a P1. If most examples land on P1, the impact
definitions are too broad: fix the definitions, not the scores.*
"""


def cmd_matrix(a):
    out = Path(a.output)
    if out.exists() and not a.force:
        sys.exit(f"refused: {out} exists. Use --force to overwrite your own work.")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(TEMPLATE, encoding="utf-8")
    print(f"wrote {out}")
    print("  the worked examples are the deliverable. The grid is just a grid.")


def cmd_check(a):
    f = Path(a.file)
    if not f.exists():
        sys.exit(f"no such file: {f}")
    txt = f.read_text(encoding="utf-8")
    gaps = 0

    def bad(m, why):
        nonlocal gaps
        gaps += 1
        print(f" fail {m}\n       {why}")

    ph = len(re.findall(r"____|\bTODO\b|\bTBD\b", txt))
    if ph:
        bad(f"{ph} unfilled placeholder(s)", "a matrix with blanks reads as complete and is not")
    else:
        print("   ok no placeholders")
    # Worked examples: rows of the last table with a P-value in them.
    sect = txt.split("## Worked examples", 1)
    rows = []
    if len(sect) == 2:
        for line in sect[1].splitlines():
            cells = [x.strip() for x in line.strip().strip("|").split("|")]
            if len(cells) >= 6 and re.fullmatch(r"P[1-4]", cells[4] or ""):
                rows.append(cells)
    if len(rows) < 6:
        bad(f"{len(rows)} worked example(s) with a priority", "the template asks for at least six")
    else:
        print(f"   ok {len(rows)} worked examples")
    if rows:
        p1 = sum(1 for r in rows if r[4] == "P1")
        if p1 / len(rows) > 0.5:
            bad(f"{p1}/{len(rows)} examples are P1", "if most things are P1, the definitions are too broad")
        else:
            print(f"   ok P1 share {p1}/{len(rows)}")
        badgrid = [r for r in rows if r[2].lower() in LEVELS and r[3].lower() in LEVELS
                   and score(r[2].lower(), r[3].lower()) != r[4]]
        for r in badgrid:
            bad(f"example {r[0]}: {r[2]} x {r[3]} is {score(r[2].lower(), r[3].lower())}, not {r[4]}",
                "either the grid is wrong or the example is; say which")
        whyless = [r[0] for r in rows if len(r[5]) < 15]
        if whyless:
            bad(f"examples without a real 'why': {', '.join(whyless)}", "the why is what makes the next rating repeatable")
        timeless = [r[0] for r in rows if not re.search(r"\d{1,2}:\d{2}", r[1])]
        if timeless:
            print(f" warn examples without a time: {', '.join(timeless)} (severity changes over time)")
    print("─" * 60)
    print("   ok it says something" if gaps == 0 else f" fail {gaps} gap(s)")
    sys.exit(0 if gaps == 0 else 1)


def main():
    p = argparse.ArgumentParser(description="Impact x urgency severity matrix, with reasons.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Usage")[1])
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("grid", help="print the matrix").set_defaults(fn=cmd_grid)
    s = sp.add_parser("score", help="look up one cell")
    s.add_argument("--impact", choices=LEVELS, required=True)
    s.add_argument("--urgency", choices=LEVELS, required=True)
    s.set_defaults(fn=cmd_score)
    s = sp.add_parser("rate", help="eight questions -> priority + justification")
    s.add_argument("--at", help="scenario time of the rating, 'YYYY-MM-DD HH:MM' UTC")
    s.set_defaults(fn=cmd_rate)
    s = sp.add_parser("matrix", help="write the Ceres matrix template")
    s.add_argument("-o", "--output", default="severity-matrix.md")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_matrix)
    s = sp.add_parser("check", help="check a filled matrix")
    s.add_argument("file")
    s.set_defaults(fn=cmd_check)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()

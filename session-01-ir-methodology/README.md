# Session 1 — Incident Response Methodology and Playbooks

**Exercises:** [`EXERCISES.md`](EXERCISES.md). **Deliverable:** triage, playbook and tabletop pack (15 %), due **Thursday 26 November 2026, 18:00**.

Wednesday 11 March 2026, 07:55 UTC. A warehouse supervisor at Ceres cannot
open the delivery schedule. Tonight you live the first four hours of the
response: you triage what the SIEM and the EDR had been saying since Tuesday,
decide how bad it is, write the playbook Ceres should have had, and then run
the morning again as a tabletop exercise.

You will not find out tonight *how* the attacker got in, or what they did on
each machine. That is Sessions 2 to 5. Tonight is about **decisions**: who
takes them, with what information, at what time, and at what cost.

Read [`../CASE.md`](../CASE.md) first.

## What is here

```
evidence/
  alert-queue.csv        40 SIEM / EDR / firewall / M365 alerts, Tue 07:00 → Wed 09:00
  helpdesk-tickets.csv   the helpdesk queue around the same window
  asset-inventory.csv    hosts, owners, criticality, data classification, monitoring coverage
  contacts.md            who to call (all numbers fictional)
  ransom-note.txt        LEIA-ME_CRS3.txt, as found on FS01 (fictional)
  injects.json           the tabletop injects, Wednesday 07:55 → 11:40
  SHA256SUMS             check these before you start
triage.py                work the alert queue; every decision logged with its reason
severity.py              impact × urgency → P1–P4, with the reasoning written down
playbook.sh              write the playbook; check it answers the questions that matter
tabletop.py              run the morning as a timed tabletop; writes the decision log
```

## Before you start

```bash
cd ir-forensics-labs
./check-lab.sh
cd session-01-ir-methodology
(cd evidence && sha256sum -c SHA256SUMS)
mkdir -p work        # git-ignored; everything you produce goes here
```

Python 3.9+ and the standard library only. Nothing here talks to the network.

---

## `triage.py` — an alert queue you can defend afterwards

```bash
./triage.py list                        # the whole queue, oldest first
./triage.py hosts                       # one line per host: count, worst severity, time window
./triage.py list --host WS-FIN-07       # one host
./triage.py list --min-sev medium --sort sev
./triage.py list --search rundll32      # free text over rule, summary and user
./triage.py show ALR-0011               # every field of one alert
./triage.py decide ALR-0011 --verdict escalate \
    --reason "unsigned DLL from Temp, started by PowerShell, prevalence 1" --related ALR-0010
./triage.py status
./triage.py export -o work/triage-log.csv
```

**Three verdicts.** `escalate` (part of an incident), `investigate` (cannot
decide yet — say what you will look at next), `close` (benign — say *why*).

**Severity is normalised, and the mapping is a decision.** Every product has its
own scale: the EDR says `high`, Wazuh says `level 12`, the firewall says
`warning`, M365 says `informational`. `triage.py` maps them onto
info/low/medium/high so you can sort one queue. Read `normalise()` in the
script; you are allowed to disagree with it, in writing.

**Two clocks per alert.** `time_utc` is the time the alert *says* the event
happened. The `clock` column tells you who wrote it: `host` means the host's
own clock (EDR, Sysmon forwarded by Wazuh), `siem` means the SIEM, the firewall
or the cloud service stamped it. `ingested_utc` is when the SIEM received it.
`./triage.py list --clock` shows the difference. A few seconds negative is
transport delay. Anything else is a clock you should not trust.

**What it refuses, and why:**

| Refusal | Why |
|---|---|
| A decision without `--reason` | a decision without a reason is a guess with a timestamp |
| `close` with a label as reason (`fp`, `noise`, `benign`, `known`…) | the next person cannot check a label; they can check "printer driver telemetry, fixed 300 s, since February" |
| Bulk `close` that includes medium/high alerts | bulk closing is where incidents hide |
| `export` while alerts are undecided | a log with gaps reads as complete; use `--partial` and say so |

It also warns when you close an alert on a host where you escalated another:
legitimate, but the reason should say why they are unrelated.

Decisions are appended to `work/triage-decisions.csv`. A new decision on the
same alert replaces the old one in the export, but the history stays in the log.

`export --skew HOST=SECONDS` adds a corrected time column for host-clock alerts
on that host. Use it only when you can say where the number came from.

---

## `severity.py` — the matrix is easy; the examples are the work

```bash
./severity.py grid
./severity.py score --impact high --urgency medium
./severity.py rate --at "2026-03-11 08:31"      # eight questions → priority + justification
./severity.py matrix -o work/severity-matrix.md # the template you fill for Ceres
./severity.py check work/severity-matrix.md
```

`rate` accepts `?` as an answer. **An unknown counts as a yes** until somebody
answers it with evidence — at 08:31 you do not know whether data left, and
rating that as "no" is how a P1 starts its life as a P3.

`check` looks for placeholders, at least six worked examples, a P1 share at or
below half ("everything cannot be a P1"), examples whose priority does not match
the grid, and examples without a real reason or without a time.

---

## `playbook.sh` — a playbook is not a runbook

```bash
cd work                                         # the playbook is written to the current folder
../playbook.sh sections                         # what each section is for
../playbook.sh new "ransomware on a file server" # asks the questions that get skipped
../playbook.sh blank "ransomware on a file server"
../playbook.sh check playbook-ransomware-on-a-file-server.md
```

A runbook says "isolate the host in the EDR" and lists the clicks. A playbook
says **who decides, what it costs, who gets told, which clock starts, and what
has to be preserved first**.

The template has eleven sections: scope and trigger, roles and RACI, decision
rights, triage, containment options, evidence preservation, eradication,
recovery, communication and regulatory clocks, closure criteria, lessons
learned.

`check` exits non-zero until:

- every section is present;
- the RACI table actually has letters in it;
- someone is named for out-of-hours decisions;
- the "aware" moment is defined in words (the "Aware moment at Ceres" line), and the
  24 h / 72 h clocks and the insurer appear;
- the containment table has a **business cost** column, at least three options,
  and **every option has its cost filled in**;
- no `____`, `TODO` or `TBD` remains.

Passing `check` means the playbook is complete. It does not mean it is good.
Final test: read it aloud to someone who was not in the room, and count their
questions.

---

## `tabletop.py` — the morning, again, with a clock

```bash
./tabletop.py --team red                 # timed: 8 scenario minutes per real minute
./tabletop.py --team red --speed 5       # slower
./tabletop.py --team red --manual        # Enter releases each inject; no clock pressure
./tabletop.py --list                     # inject times and titles (facilitator)
```

Twelve injects arrive between 07:55 and 11:40 scenario time (UTC). For each one
the team records **a decision, an owner and a time**. In timed mode the scenario
clock keeps running while you argue: if you are slow, injects pile up, which is
exactly what happens on the day.

At any decision prompt (and between injects):

| Command | What it does |
|---|---|
| `/aware HH:MM` | records when Ceres became aware, with a reason; starts the clocks |
| `/clock` | shows the scenario time and how long is left on each clock |
| `/note TEXT` | adds a note without making a decision |
| `/defer REASON` | defers the inject — deliberately, with a reason and an owner |
| `/quit` | stops and writes everything so far |

**What it refuses:** an empty owner, or one that is not an owner (`team`, `IT`,
`we`, `everyone`, `management`); a decision timed before the inject arrived; an
aware moment in the future or without a reason; a `/defer` without a reason.

Output, in `work/tabletop-<team>-<stamp>/`:

- `decisions.csv` — one row per decision, note, deferral and aware moment,
  in scenario time (UTC), with minutes-to-decide;
- `summary.md` — the aware moment, the regulatory clocks it started (EU
  baseline: NIS2 art. 23 24 h / 72 h / one month; GDPR art. 33 72 h; art. 34
  without undue delay; insurer 48 h per the policy), the decisions, who owned
  them, injects left without a decision, and destructive actions logged without
  preservation.

**Running it in a Teams breakout room.** One person shares the screen and runs
the script: the **scribe**. Pick an **incident manager** who is not the scribe.
The scribe writes down what was *decided*, not what was *said*. Everyone else
argues. If the room cannot agree, the incident manager decides — and that is
also a decision, with an owner.

> The Portuguese procedure for NIS2 notifications (DL 125/2025, Regulamento
> CNCS n.º 756/2026, the CNCS electronic platform) operationalises the EU
> baseline. The deadlines in this folder are the EU baseline: check current
> CNCS guidance before you put a Portuguese deadline in a real playbook.

---

## Tools

Python 3.9+ (standard library), bash, `sha256sum`, `less`. `sqlite3` to read
the CSVs (`column -s, -t` breaks on the quoted commas in them, see Exercise 1);
`jq` to read `injects.json` (after the exercise, not before).

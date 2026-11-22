# Session 1 — Exercises

**The situation.** Wednesday 11 March 2026. At 07:55 UTC a shift supervisor in
the Carregado warehouse opens a helpdesk ticket: the delivery schedule will not
open. By 08:20 the helpdesk has seen files ending in `.crs3` on three shares of
the file server, FS01, and a text file called `LEIA-ME_CRS3.txt` in every folder.

You are the people Ceres has. Tonight you triage what the monitoring had been
saying since Tuesday morning, rate the incident, write the playbook Ceres did not
have, and run the morning as a tabletop.

Everything is in `evidence/`. Everything you produce goes in `work/` (git-ignored).
All times you write are **UTC**, and every time says **which clock** it came from.

| # | Exercise | Tools | Time in class | Graded |
|---|---|---|---|---|
| 0 | Setup and chain of custody | `check-lab.sh`, `sha256sum` | 5 min | |
| 1 | The first ten minutes: what do you have, and what can you not see? | `column`, `less` | 15 min | |
| 2 | Triage the alert queue | `triage.py` | 35 min | **A** |
| 3 | How bad is it? A severity matrix for Ceres | `severity.py` | 15 min | **B** |
| 4 | The playbook Ceres should have had | `playbook.sh` | 30 min + home | **C** |
| 5 | Tabletop: the morning, with a clock | `tabletop.py` | 35 min | **D** |
| 6 | Debrief and reflection | your editor | 10 min + home | **D** |

---

## 0 · Setup and chain of custody

```bash
cd ir-forensics-labs
./check-lab.sh
cd session-01-ir-methodology
(cd evidence && sha256sum -c SHA256SUMS)
mkdir -p work
sha256sum evidence/* > work/received.sha256
```

Every line must say `OK`. If one does not, stop and tell the trainer: you would
be working on something other than what everyone else has.

---

## 1 · The first ten minutes: what do you have, and what can you not see?

Before triaging anything, know your ground. Read `../CASE.md`, then:

```bash
sqlite3 -line :memory: ".import --csv evidence/asset-inventory.csv t" "select * from t" | less
sqlite3 -line :memory: ".import --csv evidence/helpdesk-tickets.csv t" "select * from t" | less
less evidence/contacts.md
```

`sqlite3` reads the CSV properly and prints one record per block. Do not use
`column -s, -t` on these files: several fields contain commas inside quotes,
and `column` splits them anyway, shifting every column after it — on exactly
the server rows you need. To compare a few columns side by side, select them:
`sqlite3 -box :memory: ".import --csv evidence/asset-inventory.csv t" "select hostname, criticality from t"`.

Answer in a few lines each (not graded, but you need them for exercises 2 and 4):

1. Who is the incident manager? Who deputises for them? Is there anything
   about the deputy, or about the out-of-hours arrangements, that worries you?
2. Which hosts have EDR, and in what mode? Which logs from FS01 reach the SIEM,
   and which do not? Which Tier 1 server sends nothing at all?
3. Write the list of **what Ceres cannot see**. You will need it when you ask,
   in exercise 2, why some things are *not* in the queue.
4. Which business process depends on `\\FS01\Logistica`, and from what time of
   day does it hurt?

---

## 2 · Triage the alert queue — graded (A)

At 08:31 the IT manager asks: *"What did the SIEM and the EDR say since yesterday
morning, and what did we do about it?"* The answer is: nobody looked. You look now.

```bash
./triage.py hosts
./triage.py list
./triage.py list --host WS-FIN-07 --clock
./triage.py show ALR-0010 ALR-0011
```

**Decide every one of the 40 alerts** with `./triage.py decide`. Anything
medium or above gets its own decision and its own reason (the script refuses
to bulk-close them). Use `--related` to link
alerts to each other and to tickets (e.g. `--related ALR-0010,HD-4471`).

Then answer, in `work/triage-memo.md` (one page at most):

1. **The missed signals.** List the alerts you escalated, in true time order. For each
   one: alert id, **true UTC time** and how you got it, host, and one line on what it means.
   Which is the *earliest* alert that, on its own, should have made someone pick
   up the phone? Defend the choice.
2. **The clock.** `./triage.py list --clock` shows a difference for some host. How
   big is it, which alerts does it affect, and what is your evidence? Which alert
   in the queue *explains* it? Re-export with `--skew` only if you can justify the number.
3. **Two alerts that look bad and are not.** One is about a periodic connection,
   one is about a remote session. For each: why it looks malicious, which evidence
   (ticket, inventory, the alert itself) makes it benign, and what would have
   made you change your mind.
4. **What is not there.** Ransomware usually leaves traces that are missing
   from this queue. Name two things you would expect to see and do not, and
   explain why they are absent (use your answer to exercise 1, question 3).
5. **Why nobody acted.** Give three causes, each backed by something in the
   evidence. "People were careless" is not a cause.

```bash
./triage.py status
./triage.py export -o work/triage-log.csv
```

**Hand in:** `work/triage-log.csv` (all 40 decided) and `work/triage-memo.md`.

---

## 3 · How bad is it? A severity matrix for Ceres — graded (B)

```bash
./severity.py grid
./severity.py rate --at "2026-03-11 08:31"
./severity.py matrix -o work/severity-matrix.md
```

1. Rate the incident with `rate` **as of 08:31**, answering only with what was
   known at 08:31 (use `?` honestly). Paste the output into the section
   "Ratings of this incident" of your matrix file.
2. Fill `work/severity-matrix.md` for Ceres: what each priority triggers, the
   impact and urgency definitions **in Ceres terms** (deliveries, payroll, the
   file server, the backups), and how unknowns count.
3. At least **six worked examples**, each with a time:
   - the incident at 08:31, and again at 10:30 (after inject I09 in the tabletop —
     a leak threat with Finance and HR data). Did the priority change? Should it?
   - at least two alerts from the queue, rated **as they would have been at the
     time they fired**;
   - at least one P4 — and no more than half of all your examples may be P1.

```bash
./severity.py check work/severity-matrix.md     # must say "it says something"
```

**Hand in:** `work/severity-matrix.md`.

---

## 4 · The playbook Ceres should have had — graded (C)

Write the playbook **"Ransomware on a file server"** for Ceres. Not a generic
one: names, hosts, shares, business owners, the backup arrangements, the
insurer, the regulators, the 10:00 trucks.

```bash
cd work
../playbook.sh sections
../playbook.sh new "ransomware on a file server"
#   ...edit playbook-ransomware-on-a-file-server.md in your editor...
../playbook.sh check playbook-ransomware-on-a-file-server.md
```

Requirements, beyond what `check` verifies:

- **Containment:** at least five options for FS01 and its surroundings, each with
  business cost, evidence impact, whether the adversary learns, who authorises,
  reversible or not. Include "do nothing yet" and "pull the power" — and say
  honestly what each one costs.
- **Evidence preservation:** what is captured, in which order, *before* which
  containment step. Say what you would do if the capture takes longer than the
  business can wait, and who decides.
- **Decision rights:** who may isolate FS01, who may shut down the whole site, who
  may talk to the threat actor, who decides about payment — with deputies out of
  hours. Remember exercise 1, question 1.
- **Clocks:** the aware moment defined *in words*, and every clock with its owner:
  the CNCS notifications under the Portuguese regime (RJC, DL 125/2025: initial
  ≤ 24 h, update ≤ 72 h when needed, end of impact ≤ 24 h after it ends, final
  report 30 working days later; Session 2 goes through them in detail), GDPR art. 33 (72 h) and art. 34 (without undue delay), insurer (48 h).
- **Recovery:** from what? The answer at Ceres is not "from backup" — read the
  inventory.
- **Closure and lessons learned:** criteria a third party could check.

`check` must end with `it answers the questions`. That is the minimum, not the grade.

**Hand in:** `work/playbook-ransomware-on-a-file-server.md`.

---

## 5 · Tabletop: the morning, with a clock — graded (D)

In breakout rooms of 3–5 people. Agree roles **before** starting: incident
manager, scribe (shares the screen and types), and everyone else as the people
the injects talk to (DPO, CFO, Logistics, comms). Use your playbook draft.

```bash
./tabletop.py --team <room-name>                # 8x, about 30 minutes
# or, if your room needs it:
./tabletop.py --team <room-name> --speed 5
```

Rules of the room:

- One decision per inject at least. A deferral is a decision: `/defer REASON`.
- Record the **aware** moment with `/aware HH:MM` when you decide it, with the reason.
- Every decision has an owner who is a role or a person. The script will refuse `team`.
- Do not read `evidence/injects.json` before the exercise.

The script writes `work/tabletop-<team>-<stamp>/decisions.csv` and `summary.md`.
Everyone in the room hands in the same two files.

---

## 6 · Debrief and reflection — graded (D)

After the plenary debrief, write `work/reflection.md` (one page, individual):

1. **Your aware moment.** The time your team recorded, and the earliest and
   latest times you could defend. Why is 07:55 hard to defend? Compute the NIS2
   and GDPR deadlines for your chosen moment.
2. **Three decisions you would change**, now that you have seen the whole morning.
   For each: the inject, what you decided, what you would decide now, and what
   it would have cost the business.
3. **The FS01 dilemma.** Inject I07 asked to wipe FS01 and restore from tape.
   What would that have destroyed, and what would have had to happen first?
4. **What your playbook was missing** when the tabletop ran — and what you
   changed in it afterwards (the version you hand in should be the improved one).

---

## Deliverable (Session 1 — 15 % of the course grade)

**Due: Thursday 26 November 2026, 18:00** (before Session 2 starts).
Submit one archive, `S1-<student-number>.zip`, through the course Teams
assignment, containing:

```
work/received.sha256
work/triage-log.csv                       (A)
work/triage-memo.md                       (A)
work/severity-matrix.md                   (B)
work/playbook-ransomware-on-a-file-server.md   (C)
work/tabletop-<team>-<stamp>/decisions.csv     (D, team)
work/tabletop-<team>-<stamp>/summary.md        (D, team)
work/reflection.md                        (D, individual)
```

Everything is individual except the tabletop log, which is shared by the room
(name your teammates at the top of `reflection.md`).

### Rubric (20 points)

| Part | Points | Full marks when… |
|---|---|---|
| **A — Triage** | 5 | All 40 decided with checkable reasons (1). The early signals identified in true UTC with the clock stated and the offset evidenced (2). Both benign look-alikes correctly closed with evidence (1). What is missing, and why nobody acted, backed by the evidence (1). |
| **B — Severity** | 3 | `check` passes (1). Definitions in Ceres terms, unknowns handled explicitly (1). Examples include 08:31 and 10:30 with a reasoned change (or reasoned no-change), and are not all P1 (1). |
| **C — Playbook** | 7 | `check` passes (1). Containment options with real business costs and evidence impact, including "do nothing" and "pull the power" (2). Decision rights and out-of-hours deputies that would actually work at Ceres (1). Evidence preservation ordered and placed before containment (1). Clocks correct (EU baseline, aware defined, insurer, PT detail flagged) with owners (1). Recovery and closure that reflect Ceres' real backup situation (1). |
| **D — Tabletop + reflection** | 5 | Decision log complete: every inject decided or deferred with an owner, aware moment recorded (2). Reflection: aware moment defended with earliest/latest bounds and computed deadlines (1); three changed decisions with business cost (1); the FS01 dilemma answered with what would be destroyed and the order of operations (1). |

Late submissions lose 2 points per started day. A playbook that passes
`check` but could belong to any company gets at most half of C.

---

## Go further (not graded)

- **Detections.** Pick two alerts that fired but nobody acted on. Write, in plain
  words, what you would change so that next time somebody *does* act: the rule,
  the severity, the routing, the on-call. Which one change gives most value?
- **Truncated evidence.** ALR-0010 shows the start of an encoded PowerShell command,
  truncated by the console. Decode what is there (`base64 -d`, then read it as
  UTF-16LE: `iconv -f UTF-16LE -t UTF-8`; iconv will complain about an incomplete
  character, which is itself a clue). What can you learn from a fragment, and what
  must you *not* conclude from it?
- **Two playbooks that collide.** Write the trigger section of a second playbook,
  "compromised privileged account". At which inject of the tabletop should Ceres
  have switched to — or added — that playbook?
- **Run it again** with `--speed 12`. What broke first: the decisions, the owners,
  or the log?

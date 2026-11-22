# Session 2 — Exercises

**The situation.** You are an analyst at **Faroleiro DFIR**, the incident
response firm on the insurer's panel. Ceres Alimentar engaged you on Wednesday
11 March 2026 at 15:30 UTC. Tonight you advise Ceres on what it must say, to
whom, by when — and you receive the first exhibit, collected from WS-FIN-07
before you arrived.

`evidence/response-log.csv` runs to **Tuesday 17 March, 12:00 UTC**, so that
you can see how the first week went. Each exercise says the moment you are
working as of; use only what was known by then.

Everything is fictional — company, people, domains, addresses. Nothing in
`evidence/` goes to VirusTotal, a search engine or any other public service.

> **A note on dates.** The case is dated March 2026. The Portuguese regime we
> use tonight — the *Regime Jurídico da Cibersegurança* (RJC), approved in the
> annex to Decree-Law 125/2025 — has applied since **3 April 2026**, and
> *Regulamento* CNCS n.º 756/2026 since June. Tonight we apply the regime in
> force **now** to the case calendar, as if the same incident happened this
> week. You learn the rules you will actually use; the dates stay those of the
> evidence.

## Before you start

```bash
cd ir-forensics-labs/session-02-communication-and-collection
(cd evidence && sha256sum -c SHA256SUMS)     # every line must say OK
mkdir -p work                                # git-ignored; everything you produce goes here
echo "$(date -u +%FT%TZ)  START session 2 — $(whoami)@$(hostname)" > work/my-notes.txt
```

Keep `work/my-notes.txt` going all evening: one line per thing you do or
decide, in UTC, as you do it.

| # | Exercise | Block | Tools | Time | Graded |
|---|---|---|---|---|---|
| 1 | Mark up the press release | 1 | a red pen | 12 min | → P9 |
| 2 | Four inboxes | 1 | `stakeholder-questions.md` | 8 min | — |
| 3 | In scope, and significant? | 2 | the RJC articles on the slides | 6 min | → P2 |
| 4 | When did Ceres conclude? | 3 | `response-log.csv` | 5 min | → P1 |
| 5 | The Portuguese clocks | 3 | `clocks.py` | 10 min | → P1 |
| 6 | Watch: live response and its footprint | 3 | `live-response.sh` (demo) | 7 min | — |
| 7 | Receive exhibit EXH-WSFIN07-01 | 3 | `sha256sum`, `custody.py` | 15 min | — |
| 8 | The communication pack | home | `templates/`, `clocks.py` | homework | **Deliverable** |

The WS-FIN-07 triage package in `evidence/WS-FIN-07_triage/` is **analysed in
Session 3**. Tonight you only receive it: verify it and record its custody.

---

## Block 1 — Incident communication

### 1 · Mark up the press release (→ P9)

As of **Wednesday 11 March, 17:20 UTC**. `evidence/draft-press-release.md` is
Marketing's draft. It is bad on purpose, in many ways.

```bash
cp evidence/draft-press-release.md work/press-markup.md
```

1. Under each problem, add a line:
   `> PROBLEM: … · WHY IT MATTERS: … · WHO IS HURT: …`. Aim for at least ten.
   Check every claim against `response-log.csv` as it stood at 17:20.
   Think about: facts vs. hypotheses, people, regulators, the insurer, the
   attacker reading it, promises.
2. Which entry in the response log does the draft break by its last line?
3. At home: using `templates/press-holding-statement.md`, write the statement
   you would approve tonight, and the prepared answers to the five questions
   in its table.

### 2 · Four inboxes

`evidence/stakeholder-questions.md` holds messages from the CFO, the workers'
committee, a journalist and the insurer. Work as of the moment each arrived.

For each: **who** answers, **by when**, through **which channel**, and the
**first two sentences**. Then:

1. The CFO asks whether one notification can be "copied" to the other
   authority. Answer him with the article that settles it.
2. "Is this Marta's fault?" — write the exact sentence you would say on the phone.
3. The insurer's four requests: which can Ceres satisfy on Thursday 12 March,
   and with which document?

---

## Block 2 — NIS2 in Portugal

### 3 · In scope, and significant? (→ P2)

Use the RJC excerpts on the slides and `../CASE.md`.

1. Which category of entity is Ceres, and what does that change for the
   sanction if it fails to notify (art. 61.º)?
2. Apply the five parameters of **art. 40.º n.º 3** to the Ceres incident as
   known on **Wednesday 11 March, 12:00 UTC**: one line each, with a number or
   "unknown". Which parameter carries the decision?
3. What else must Ceres consider before deciding (art. 40.º n.º 4)? Where would
   you look it up today?
4. Would the 2-hour rule of art. 41.º n.º 2 have applied? What would that have
   meant for the notifications?

---

## Block 3 — Clocks and collection

### 4 · When did Ceres conclude? (→ P1)

```bash
sqlite3 -box :memory: '.import --csv evidence/response-log.csv log' \
  "SELECT seq, event_utc, logged_utc, actor, type, substr(entry,1,70) AS entry FROM log" | less -S
```

1. Find three candidate moments: the first symptom, the first person who saw
   the cause, and the formal declaration. Write each in UTC with its log entry.
2. The RJC clock starts when the entity **concludes that there is, or may come
   to be, a significant incident** (art. 42.º n.º 1). Which moment do you
   choose? Two sentences for it, one against the earliest.
3. Is the GDPR art. 33 "awareness" necessarily the same moment? Find the entry
   from which Ceres knew that personal data were involved.
4. Compare `event_utc` and `logged_utc`. Which entries were written after the
   fact? Why does it matter when the insurer asks for "the date and time of
   discovery", and the CNCS for art. 42.º n.º 2 b)?

### 5 · The Portuguese clocks (→ P1)

```bash
./clocks.py --help
./clocks.py --aware "2026-03-11 08:31"                    # read the refusal
./clocks.py --aware "2026-03-11 08:31Z" --basis confirmed  # and this one
./clocks.py --aware "<your choice>Z" --alt "<an alternative>Z"
```

**As of Friday 13 March, 18:00 UTC** — find the submission times in the log
yourself:

```bash
./clocks.py --aware "<your choice>Z" --now "2026-03-13 18:00Z" \
            --submitted pt-initial=<from the log> --submitted insurer=<from the log>
```

**As of Tuesday 17 March, 12:00 UTC** — the impact has ended:

```bash
./clocks.py --aware "<your choice>Z" --impact-end "<from the log>Z" --now "2026-03-17 12:00Z" \
            --submitted pt-initial=… --submitted pt-update=… --submitted gdpr-33=… \
            --submitted gdpr-34=… --submitted pt-end=… --submitted insurer=…
./clocks.py … --markdown > work/clocks.md                  # for your deliverable
```

1. What was late, by how much, and what does the log say caused it? What
   would have prevented each?
2. Three deadlines fall on the same day. Which day of the week, and who must be
   reachable then?
3. On what date is the *relatório final* due? Which holiday moved it, and by how
   much would it move if the end-of-impact notification had gone on Monday
   evening instead of Tuesday morning? Which date does the Directive give, and
   why is it different?
4. Which rows have no deadline in hours? For each, write when Ceres actually
   acted (if it did) and whether you can defend it.
5. Which deadline in the output is a contract, not a law?

### 6 · Watch: live response and its footprint

The trainer runs `live-response.sh` on a lab VM. Watch for, and note in
`work/my-notes.txt`:

1. What it refuses to do, and why.
2. What it collects first, and why that comes before the processes.
3. Where the collector appears in its own evidence, and what `footprint.txt`
   admits it changed.
4. One thing it changed that `footprint.txt` does **not** list.

(Order of volatility, live vs dead acquisition and the artefact maps are in the
Blue Team module, Sessions 7 and 8. To run it yourself, see *Go further*.)

### 7 · Receive exhibit EXH-WSFIN07-01

As of **Wednesday 11 March, 16:20 UTC**: the exhibit is handed to you. Read
`evidence/README.md`, then `evidence/WS-FIN-07_triage/collection-notes.txt`.

```bash
T=evidence/WS-FIN-07_triage
(cd $T && sha256sum -c MANIFEST.sha256)
sha256sum $T/MANIFEST.sha256          # compare with the value in collection-notes.txt
./custody.py new --help
```

Build the custody record **from the collector's notes and the response log
only**: the collection entry, every transfer up to and including the one to
you, then your recorded verification.

```bash
./custody.py new --case INC-2026-007 --exhibit EXH-WSFIN07-01 ... -o work/custody-EXH-WSFIN07-01.json
./custody.py transfer work/custody-EXH-WSFIN07-01.json --from "…" --to "…" --when …Z --why "…"
./custody.py verify work/custody-EXH-WSFIN07-01.json --record --by "Your Name (Faroleiro DFIR)"
./custody.py show work/custody-EXH-WSFIN07-01.json --text work/custody-EXH-WSFIN07-01.txt
```

1. `verify` reports one file that is present but not in the manifest. Which, and
   is it a problem? Write the note you would add.
2. Your record shows two different times for every entry. What are they, and
   what does that say about this record?
3. What gaps in the collection does the collector record? Which one would you
   raise first with Ceres, and how does it affect what the final report to the
   CNCS can say?
4. The insurer (exercise 2) asked for this record. What would you send, and
   what would you add to it first?

---

## 8 · The communication pack (homework → deliverable)

Write the messages Ceres should have sent, each **dated as if sent at the
moment it should have been sent** (say which moment and why at the top), with
**only what was known by then**. Use `templates/`.

Rules: facts and hypotheses in separate sentences; UTC with `Z` everywhere a
regulator reads; every legal statement cites its article; no field left with a
guess — "unknown at the time of writing" is an acceptable answer, invention is
not. Where a field depends on the CNCS taxonomy, say which category you would
choose and that the current *instrução técnica* must be checked.

---

## Deliverable — Session 2 (20 % of the course grade)

**Due: Monday 30 November 2026, 18:00** (before Session 3 starts). Submit one
`.zip` named `S2-<student-number>.zip` through the course Teams assignment,
containing:

| | File | What | Points |
|---|---|---|---|
| P1 | `clocks.md` | `clocks.py --markdown` as of Tue 17 Mar 12:00, plus ≤ 200 words: your awareness moment against the alternatives, and what was late and why | 3 |
| P2 | `cncs-1-initial.md` | *Notificação inicial* (art. 42.º n.º 2 a)–d)), with the art. 40.º n.º 3 significance reasoning | 3 |
| P3 | `cncs-2-update.md` | The 72 h update (art. 42.º n.º 3), with why it is necessary | 2 |
| P4 | `cncs-3-end-of-impact.md` | End-of-impact notification (art. 43.º n.º 2 a)–c)) | 2 |
| P5 | `cncs-4-final-report-outline.md` | Outline of the *relatório final* (art. 44.º n.º 2 a)–e)) with its due date and how you computed it | 2 |
| P6 | `cnpd-art33.md` | GDPR art. 33 notification to the CNPD, as of its deadline | 3 |
| P7 | `employees-art34.md` | GDPR art. 34 communication to employees, plus three lines on its timing | 2 |
| P8 | `customers-art48.md` | RJC art. 48.º notice to customers | 1 |
| P9 | `press-markup.md` | ≥ 10 problems in the draft + your holding statement with the five prepared answers | 2 |
| | | **Total** | **20** |

### Rubric

| Criterion | Full marks | Partial | None |
|---|---|---|---|
| **P1 Clocks** (3) | Awareness moment chosen and argued against the alternatives (art. 42.º n.º 1 wording); all deadlines correct in UTC and Lisbon, incl. the final report in *dias úteis*; every late item with its cause and a fix; weekend and summer time noted | Correct table, weak argument; or one deadline wrong | Clock started at the wrong moment, or no zones |
| **P2 Initial** (3) | All art. 42.º n.º 2 fields; significance argued with the five parameters; facts and hypotheses separated; only what was known before the 24 h; other notifications (art. 40.º n.º 5) mentioned | A field missing, or anachronistic facts | Missing, or states what the evidence contradicts |
| **P3 Update** (2) | Revised fields + initial assessment (severity, impact, indicators if available); says why it is necessary | Repeats the initial notification | Missing |
| **P4 End of impact** (2) | Impact-end moment with its evidence; measures; impact at that moment incl. time to full recovery; links to the final-report clock | Fields present, impact end not justified | Missing |
| **P5 Final report outline** (2) | All art. 44.º n.º 2 headings with sources and owners; correct due date in *dias úteis* from the end-of-impact notification | Outline right, date wrong (or vice versa) | Missing |
| **P6 CNPD** (3) | Art. 33(3) content; categories and approximate numbers; special-category data identified; consequences; measures; phased if needed; the CNCS notification is not offered as a substitute | Content present but speculative or legalistic | Missing, or merged with the CNCS one |
| **P7 Employees** (2) | Plain language, concrete advice, DPO contact; timing decision justified against "without undue delay" | Correct but legalese, or no timing argument | Missing |
| **P8 Customers** (1) | Art. 48.º: what affects them, measures they can take (bank-detail fraud), free contact, plain language | — | Missing, or key accounts only |
| **P9 Press** (2) | ≥ 10 problems with why and who is hurt; statement follows one voice, facts only, no blame, no IOCs, no ransom, no promised dates | 6–9 problems, or a statement that repeats a problem | < 6 problems |

Late submissions lose 2 points per started day, unless agreed beforehand.

---

## Go further (optional)

### A · Live response on your own VM

You need output media that is **not** the disk you are examining. A
file-backed image mounted on `/mnt/case` stands in for a USB disk:

```bash
truncate -s 256M ~/case.img && /usr/sbin/mkfs.ext4 -q -L CASE ~/case.img
sudo mkdir -p /mnt/case && sudo mount -o loop ~/case.img /mnt/case && sudo chown "$USER": /mnt/case
./live-response.sh plan
./live-response.sh -o /tmp/out                        # read the refusal
./live-response.sh -o /mnt/case --case LAB-02 --examiner "Your Name" --ntp pool.ntp.org
C=$(ls -d /mnt/case/collection-* | tail -1)
(cd "$C" && sha256sum -c SHA256SUMS)
less "$C/00-clock.txt" "$C/footprint.txt" "$C/manifest.csv"
```

1. What is your VM's clock offset from the reference, and what does the sign mean?
2. Find the collector in `02-processes.txt`. Which other files mention it?
3. Run it again with `sudo`. What appears only in the root run — and what did
   the root run add to the system's logs?
4. Record the collection with `custody.py new … --manifest "$C/SHA256SUMS"`,
   append one byte to a collected file, and run `verify`. Can you "fix" it?

### B · The interim report

Suppose FS01 could not be restored and the significant impact were still going
on in late April. Using art. 44.º n.º 3 and n.º 4: who decides whether an
interim report is due, how often, and with what content? Draft its headings.

### C · The Directive vs the RJC

Write a half-page note for a colleague who works for a group with entities in
Portugal and Spain: which steps and deadlines differ between the NIS2
Directive's art. 23 and the RJC, and what one shared playbook must therefore
say. (For Spain, cite only what you can find in the official text.)

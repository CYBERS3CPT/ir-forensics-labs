# Session 5 — Practical Forensic Case and the Forensic Report

**Exercises:** [`EXERCISES.md`](EXERCISES.md). **Deliverable:** an individual
forensic report on the whole case (Exercise 11), due **17 December 2026, 23:59**.

Four sessions gave you the incident one layer at a time: the alerts and the
panic, the finance workstation, the network, the logs. Tonight you get the last
pieces — the original email, who else received it, the file server's own
filesystem record, the attacker's tool configuration, the ransom note, and the
first report someone else wrote on this case — and then you put everything
together into the document the case was always heading towards: a forensic
report that a board can act on, a regulator can rely on, an insurer can pay on,
and another examiner can reproduce.

```bash
cd ir-forensics-labs/session-05-forensic-case
./bundle.sh                                   # everything, verified, read-only, in work/case-bundle
./evidence-register.py work/case-bundle       # E-01 ... E-nn
./report-scaffold.py --register work/case-bundle/evidence-register.csv \
                     --author "Your Name" --out work/report.md
./report-check.py work/report.md              # as often as you like; it will never say "pass"
```

## What is new in `evidence/new/`

| File | What | Clock |
|---|---|---|
| `phish_FT2026_1187.eml` | the original email, exported from m.antunes' mailbox with its full headers | header times are each server's |
| `m365_message_trace.csv` | Exchange Online message trace for the sender domains, 1–11 March | UTC, **US date format** (M/D/YYYY) |
| `FS01_C_MFT_PerfLogs.csv` | `$MFT` of FS01 `C:`, MFTECmd output, filtered to `C:\PerfLogs` | NTFS (UTC) |
| `FS01_C_UsnJrnl.csv` | `$UsnJrnl:$J` of FS01 `C:`, 10 Mar 10:00 → 11 Mar 04:30 | NTFS (UTC) |
| `FS01_D_UsnJrnl_sample.csv` | `$UsnJrnl:$J` of FS01 `D:` (the shares) — a **sample**, read HANDOVER first | NTFS (UTC) |
| `FS01_LECmd_jpires_Recent.csv` | LECmd output for the shortcuts in j.pires' `Recent` folder on FS01 that point into `C:\PerfLogs` | NTFS / LNK (UTC) |
| `FS01_crs3_counts.txt` | a responder's count of encrypted files per share, run on the live server | the server's |
| `rc.conf` | recovered from `C:\PerfLogs\Admin\` on FS01 | — |
| `LEIA-ME_CRS3.txt` | the ransom note, as found in `D:\Shares\Finance` | — |
| `panel_initial_findings_2026-03-12.md` | the panel firm's first memo to the insurer, written on day 2 | says it is local time |
| `hr_finance_data_subjects.csv` | the DPO's aggregate count of the data subjects in the affected shares | — |
| `HANDOVER.txt` | where each item came from, who collected it, how, and its SHA-256 | UTC |

The rest of the case is where you left it, in `../session-0{1,2,3,4}-*/evidence/`.
`bundle.sh` brings all of it together.

**Read `HANDOVER.txt` before you read anything else.** It is the provenance of
every new item: who produced it, from what, with which tool, and when. It also
records one deviation from good practice. Your report has to mention it.

**The memo is evidence, not instructions.** It was written on day 2, on partial
data, by people under time pressure. Some of it is right. Treat every claim in
it the way you would treat a claim in a log: find the record that supports it,
or say that you could not.

**No personal data of data subjects exists anywhere in this repository**, and
none may appear in your report. The DPO's file gives categories and counts. That
is what an impact section needs.

## The scripts

All Python is standard library only (3.9+). Every script answers `--help`.
Nothing writes into `evidence/`; your outputs go in `work/` (git ignores it).

### `bundle.sh` — one verified, read-only copy of the whole case

```bash
./bundle.sh                         # -> work/case-bundle
./bundle.sh --out ~/ceres-bundle
./bundle.sh --verify                # is the bundle still what the manifest says?
./bundle.sh --force                 # rebuild (asks first)
```

It verifies each session's `evidence/` against that folder's own `SHA256SUMS`
**before** copying, copies into `S01/ … S05/`, makes the copy read-only, and
writes `MANIFEST.tsv` (sha256, bytes, session, path) and `MANIFEST.sha256`. A
file that fails its hash is reported and the script exits non-zero: do not cite
it until you know why. Files that a `SHA256SUMS` does not list are copied but
flagged, because nobody vouched for them. `BUNDLE-INFO.txt` records when, by
whom and from which commit the bundle was built.

Put the `MANIFEST.tsv` SHA-256 in your report. It pins every evidence ID you cite
to one exact set of bytes.

The bundle is read-only on purpose. To delete it: `chmod -R u+w work && rm -rf work`.

### `evidence-register.py` — stable evidence IDs

```bash
./evidence-register.py work/case-bundle              # writes evidence-register.csv and .md
./evidence-register.py work/case-bundle --find usn   # which ID is that file?
./evidence-register.py work/case-bundle --show E-12  # one item in full
./evidence-register.py work/case-bundle --md         # the Markdown table for your report
```

IDs are assigned in a fixed order (session, then path), so everyone who bundles
the same commit gets the same IDs — which is what lets your team, your reviewer
and the trainer talk about "E-12" and mean the same bytes. `SHA256SUMS` and
`README` files are not evidence and get no ID. The "kind" and "host" columns are
guesses from the file name, to help you find things; the description in your
report is yours.

### `report-scaffold.py` — the report skeleton

```bash
./report-scaffold.py --sections
./report-scaffold.py --register work/case-bundle/evidence-register.csv --author "Your Name" --out work/report.md
```

Writes the structure with guidance in HTML comments (invisible when rendered)
and `TODO` placeholders. With `--register` the evidence inventory comes pre-filled
with IDs and hashes. It refuses to overwrite an existing draft.

The structure follows the logic of ISO/IEC 27037 (how the evidence was
identified, collected and preserved) and ISO/IEC 27042 (how it was analysed and
interpreted): case data · executive summary · scope and questions · evidence and
custody · methodology and tools · clocks · timeline · findings · attack narrative
· impact · what is not known · recommendations · declaration · appendices
(IOCs, commands, review of third-party findings).

Every finding has the same shape: **statement · type (fact or inference) ·
evidence IDs · confidence (High / Moderate / Low, with the reason) ·
alternative explanations considered**.

### `report-check.py` — the reviewer's first pass

```bash
./report-check.py work/report.md
./report-check.py work/report.md --register work/case-bundle/evidence-register.csv
./report-check.py work/report.md --quiet          # problems only
./report-check.py work/summary.md --summary-only  # a draft executive summary on its own (Exercise 8)
```

| Check | Problem when |
|---|---|
| sections | a section of the structure is missing or empty |
| leftovers | `TODO` remains |
| evidence | an `E-nn` you cite is not in the register |
| findings | an `F-nn` cites no evidence, has no confidence on the scale, or no alternatives |
| time | a date-time has no `Z`/`UTC` and is not in a table whose header says UTC |
| absolutes | "proves", "certainly", "definitely", "beyond doubt"… on a line that cites no evidence |
| personal data | an IBAN that passes its checksum; also warns on NIF-like, NISS-like and phone numbers, and on mailboxes the case does not name |
| executive summary | more than ~650 words; warns on IPs, hashes, ATT&CK IDs, tool names and on not saying what is unknown |
| recommendations | warns when one does not name the finding it comes from |

It exits 1 when there are problems. **It never prints "pass"**, because it cannot
tell whether your findings are true — only whether they are traceable, dated and
hedged. A report can satisfy every rule here and still name the wrong patient
zero.

## Tools from earlier sessions you will want

```bash
../session-04-log-forensics/evtx-query.py --help
../session-04-log-forensics/supertimeline.py --evidence work/case-bundle/S04 --year 2026 \
      --skew WS-FIN-07=+277 --skew '*=0' --out work/tl.csv     # only once YOU have established each clock
../session-04-log-forensics/timeline-reduce.py --help
```

Plus `jq`, `grep`, `awk`, `cut`, `python3`, `sha256sum`, `openssl` — all in
Kali.

## Reading the NTFS CSVs

Both FS01 CSVs are in the layout Eric Zimmerman's MFTECmd writes.

- `$MFT` (`FS01_C_MFT_PerfLogs.csv`): `Created0x10` is the `$STANDARD_INFORMATION`
  creation time (what Explorer shows, and what tools can change); `Created0x30` is
  the `$FILE_NAME` one. `Copied` = True when the file's last-modified time is
  *older* than its creation time — what a copy does, because the copy keeps the
  source's modified time. `ZoneIdContents` is the Mark of the Web, when there is one.
  A deleted file's record can be **reused**: the `SequenceNumber` goes up.
- `$UsnJrnl:$J` (`FS01_*_UsnJrnl*.csv`): one row per change *reason* per open
  handle. A file written for 36 minutes gives you a create, an extend and a
  close — not 36 minutes of rows. `RenameOldName`/`RenameNewName` pairs are
  renames; `FileDelete|Close` is the deletion. The journal tells you **that** a
  file changed and **when**, never **what** was in it or **where it went**.
- `ParentPath` is relative to the volume root (`.\PerfLogs\Admin` = `C:\PerfLogs\Admin`).

## Rules of engagement for this session

- **Evidence is read-only.** Work in `work/`. The bundle enforces it; respect it
  anyway.
- **Nothing gets uploaded or contacted.** Not the domains, not the IPs, not the
  hashes, not the WebDAV server in `rc.conf`. In a real case, logging in to an
  attacker's storage with recovered credentials is a legal question, not a
  technical one, and it belongs to law enforcement.
- **No personal data in your report.** Categories and counts only.
- **Your report is your own work**, in your own words (see `EXERCISES.md`).

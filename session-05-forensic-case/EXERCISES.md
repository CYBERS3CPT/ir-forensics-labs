# Session 5 — Exercises

The last evening. Everything the investigation has is now on the table, and the
question changes from *"what does this artefact say?"* to *"what can I put my
name to, and how sure am I?"*

You work in **teams** during the session (breakout rooms, 3–4 people) and then
**alone** on the graded report, which is due a week later.

| # | Exercise | Block | Tools | Time |
|---|---|---|---|---|
| 1 | One bundle, one set of IDs | 1 | `bundle.sh`, `evidence-register.py` | 10 min |
| 2 | The email, header by header | 1 | `grep`, `python3` | 15 min |
| 3 | Who else got it, and who clicked | 1 | `awk`, `grep`, `cut` | 15 min |
| 4 | What FS01's filesystem remembers | 2 | `$MFT`, `$UsnJrnl`, LNK CSVs, `evtx-query.py` | 15 min |
| 5 | The attacker's configuration file | 2 | `cat -A`, your judgement | 5 min |
| 6 | How much left the building | 2 | `awk`, Zeek `conn.log` | 10 min |
| 7 | Review the panel firm's memo | 2 | everything above | 15 min |
| 8 | The executive summary, rewritten | 3 | a text editor, `report-check.py` | 10 min |
| 9 | Team reconstruction | 3 | `report-scaffold.py`, `supertimeline.py`, `report-check.py` | 20 min |
| 10 | Peer review | 3 | `report-check.py`, the checklist below | 10 min |
| **11** | **The forensic report (graded, individual)** | home | all of it | — |

Exercises 1–10 are not graded on their own: they are the raw material of
Exercise 11, and the in-class versions of the skills it assesses. Keep your
notes — every command you run tonight belongs in your report's Appendix B.

## Before you start

```bash
cd ir-forensics-labs/session-05-forensic-case
git pull                                       # the evidence of every session must be current
mkdir -p work
echo "$(date -u +%FT%TZ)  START  session 5" >> work/notes.txt
```

Ground rules, the same as every week and more so tonight:

- **Work on the bundle**, never on `evidence/`. The bundle is read-only and hashed;
  that is what makes an evidence ID mean something.
- **UTC, and the clock it came from**, for every time you write down.
- **Every claim carries an evidence ID.** If you cannot point to one, it is a
  hypothesis — write it as one.
- **No personal data of data subjects** in anything you write. Categories and counts.

---

## 1 · One bundle, one set of IDs

```bash
./bundle.sh
cat work/case-bundle/BUNDLE-INFO.txt
./evidence-register.py work/case-bundle
./bundle.sh --verify
B=work/case-bundle            # used in every command below
```

1. Which sessions' evidence verified against their own `SHA256SUMS`? If any
   failed or was missing, stop and fix that first (`git status`, `git pull`).
   Did `bundle.sh` flag any file as copied but not covered by a `SHA256SUMS`? If
   it did, how would you describe that item in your report — and if it did not,
   what would you have had to write? Why does the word "unverified" matter to a
   reader?
2. Write the SHA-256 of `MANIFEST.tsv` in your notes. What does that one hash
   commit you to?
3. Which evidence IDs did the eleven-plus new items in `S05/new/` get? Read
   `S05/new/HANDOVER.txt`: who produced each new item, from what, with which tool?
   One item was produced in a way that departs from good practice. Which, and
   how do you report it without pretending it did not happen?
4. Try to change a file in the bundle (`echo x >> $B/S05/new/rc.conf`). What
   happens, and why is that the behaviour you want?

---

## 2 · The email, header by header

```bash
grep -nE '^(Received|Authentication-Results|Received-SPF|From|Reply-To|Return-Path|To|Subject|Date|Message-ID|X-Mailer|X-Forefront-Antispam-Report):' \
     $B/S05/new/phish_FT2026_1187.eml
python3 - "$B/S05/new/phish_FT2026_1187.eml" <<'EOF'
import email, email.policy, re, sys
m = email.message_from_bytes(open(sys.argv[1], "rb").read(), policy=email.policy.default)
for h in ("From", "Reply-To", "To", "Subject", "Date", "Message-ID"):
    print(f"{h:11} {m[h]}")
for part in m.walk():
    if part.get_content_type() in ("text/plain", "text/html"):
        for u in sorted(set(re.findall(r'https?://[^\s"<>]+', part.get_content()))):
            print(f"link        {u}   ({part.get_content_type()})")
    if part.get_content_type() == "text/html":
        for href, text in re.findall(r'<a [^>]*href="([^"]+)"[^>]*>(.*?)</a>', part.get_content(), re.S):
            print(f"anchor      shows '{text}'  ->  {href}")
    if part.get_filename():
        print(f"attachment  {part.get_filename()}")
print("attachments:", sum(1 for p in m.walk() if p.get_filename()))
EOF
```

1. Read the `Received:` headers **from the bottom up**. Where was the message
   first written, by what software, and from which public IP did it enter the
   mail service? Have you seen that IP before in this case? Where?
2. SPF, DKIM and DMARC all say `pass`. Write two sentences: what does that
   establish, and what does it **not** establish? (Your report's executive
   summary will need the second sentence in plain language.)
3. Compare the display name, the `From` domain and the `Reply-To`. Find the real
   supplier's sending domain (Exercise 3 will show it to you). What, precisely,
   is impersonated?
4. The HTML link says one thing and points to another. What does the reader see,
   and what does the browser fetch? Is there an attachment?
5. `Date:` versus the top `Received:`. Which clock wrote each? Does the difference
   matter for your timeline, and which one goes in it?

---

## 3 · Who else got it, and who clicked

```bash
cut -d, -f1-5,7 $B/S05/new/m365_message_trace.csv
awk -F, 'NR>1 && $2 ~ /ceres-fornecedores/ {print $1, $3, $5}' $B/S05/new/m365_message_trace.csv
awk -F, 'NR>1 && $2 ~ /agrotamega/ {print $1, $2, $3, $7}' $B/S05/new/m365_message_trace.csv
grep -E '203\.0\.113\.45|ceres-fornecedores' $B/S03/fw01-egress.csv
grep -h 'ceres-fornecedores' $B/S03/zeek/dns.log $B/S03/zeek/http.log | cut -f1-9
```

1. How many people received the email? What happened to each copy (`Status`)?
   One recipient is not a person. What does a click from a shared mailbox tell
   you — and not tell you — about who clicked?
2. The trace's `Received` column is `3/10/2026 8:12:04 AM`. Is that 3 October
   or 10 March, and is it UTC? How do you **know**, rather than guess? (The
   handover sheet and the other rows help.)
3. Which internal hosts ever connected to the phishing server? Answer from the
   firewall **and** from Zeek. Do the two sources agree?
4. "Only m.antunes clicked." Rewrite that sentence so it says exactly what the
   evidence supports. Which ways of opening the link would **not** appear in
   either source? (Think about where the people on the list could have been, and
   on what device.) This is a limitation; write it as one.
5. Five copies were delivered to inboxes, one of them the CFO's, and nothing in
   the evidence says any was removed. Which recommendation follows, and which
   finding does it come from?

---

## 4 · What FS01's filesystem remembers

```bash
python3 - $B/S05/new/FS01_C_MFT_PerfLogs.csv <<'EOF'
import csv, sys
for r in csv.DictReader(open(sys.argv[1], encoding="utf-8")):
    print(f"{r['EntryNumber']:>6}/{r['SequenceNumber']:<2} {r['FileName']:9} size={r['FileSize']:>9} "
          f"created={r['Created0x10'][:19]} modified={r['LastModified0x10'][:19]} copied={r['Copied']} "
          f"zone={r['ZoneIdContents'] or '-'}")
EOF
grep -E 'PerfLogs|Recent|Security\.evtx|SYSTEM\.LOG1|System Volume' $B/S05/new/FS01_C_UsnJrnl.csv | cut -d, -f1,3,4,9,10
cut -d, -f1,5,6,7,8,21,22 $B/S05/new/FS01_LECmd_jpires_Recent.csv
../session-04-log-forensics/evtx-query.py $B/S04/windows --host FS01 --eid 11 --grep 'PerfLogs'
```

1. When was `C:\PerfLogs\Admin` created, and when was each tool written into it?
   Do the NTFS times agree with Sysmon's FileCreate events? To the second?
2. `7za.exe` was last **modified** in 2024 and `rc.conf` on 9 March 2026. Does that
   mean they were on FS01 then? What does `Copied = True` tell you, and what does
   the empty `ZoneIdContents` add? What, if anything, does rc.conf's date tell you
   about the attacker's preparation — and how confident can you be?
3. `fin.7z` is not in the `$MFT` excerpt. Why not? Follow entry **88219** through
   the journal and the LNK file, and explain the sequence numbers.
4. When was `fin.7z` deleted, and how (Recycle Bin or not)? Which source tells you,
   and which source would you expect to and does not?
5. Three entries on the night of 10–11 March corroborate events you know from the
   Session 4 logs. Which, and why does a second, independent source raise your
   confidence even though you already "knew"?
6. `crs.exe`: when did it arrive on FS01, according to NTFS? Look for the matching
   Sysmon FileCreate. If you cannot find one, how do you report a fact with a
   single source?
7. Now the shares: `$B/S05/new/FS01_D_UsnJrnl_sample.csv`. Read the HANDOVER entry
   for it first. First and last encrypted file, and the time of each? What can you
   **not** do with a sample, and where do you get the count instead?

```bash
grep -m3 RenameNewName $B/S05/new/FS01_D_UsnJrnl_sample.csv | cut -d, -f1,7,9
grep RenameNewName $B/S05/new/FS01_D_UsnJrnl_sample.csv | tail -2 | cut -d, -f1,7,9
grep -c 'LEIA-ME_CRS3.txt.*FileCreate|Close' $B/S05/new/FS01_D_UsnJrnl_sample.csv
cat $B/S05/new/FS01_crs3_counts.txt
sha256sum $B/S01/ransom-note.txt $B/S05/new/LEIA-ME_CRS3.txt
```

---

## 5 · The attacker's configuration file

```bash
cat -A $B/S05/new/rc.conf
../session-04-log-forensics/evtx-query.py $B/S04/windows --host FS01 --eid 1 --grep 'rcl\.exe'
```

1. What does `rc.conf` tell you about where the data went: protocol, server,
   account, and (with the command line in Sysmon) the remote folder?
2. The `pass` line is "obscured". Is that encryption? (See *Go further*.)
3. You now hold what looks like the credentials of the attacker's storage account.
   What do you do with them — and what do you **not** do? Who decides?

---

## 6 · How much left the building

```bash
awk -F, '$10=="192.0.2.77" {print $1, $2, $7, $12}' $B/S03/fw01-egress.csv
awk -F, '$10=="192.0.2.77" {s+=$12} END {printf "%d bytes = %.2f GB\n", s, s/1e9}' $B/S03/fw01-egress.csv
grep -v '^#' $B/S03/zeek/conn.log | \
  awk -F'\t' '$5=="192.0.2.77" {n++; s+=$10} END {printf "%d connections, %d orig_bytes = %.2f GB\n", n, s, s/1e9}'
```

1. You now have up to four numbers for the same thing: the archive's size (from
   the LNK, Exercise 4), Zeek's bytes, the firewall's bytes and the actor's claim
   (Session 1). Put them in a table. Why do they differ, and are the differences
   explained? Which number goes in the executive summary, and in what words?
2. How many connections carried the data, and what does that tell you about the
   tool? One of them ended early. Does that change your total?
3. Which shares went into the archive, according to the process that built it?
   Which data categories does that put in scope (`hr_finance_data_subjects.csv`)?

---

## 7 · Review the panel firm's memo

```bash
cat $B/S05/new/panel_initial_findings_2026-03-12.md
grep HD-4471 $B/S01/helpdesk-tickets.csv
../session-04-log-forensics/evtx-query.py $B/S04/windows --host FS01 --channel TS-LSM --eid 21,25
awk -F, '$10=="192.0.2.77" && $2>="2026-03-10T13:10" && $2<"2026-03-10T13:35" {s+=$12} END {print s}' $B/S03/fw01-egress.csv
```

The memo went to the insurer on 12 March and copied the CFO. People have already
made decisions on it.

1. Find the **two** substantive errors. For each: what the memo says, what the
   evidence says (with IDs), and how the error arose — what the author looked at,
   and what they did not.
2. For each error, what decision could it have caused? (Re-imaging the wrong
   machine is the cheap one. Read section 2 of the memo again for the expensive one.)
3. What did the memo get right? List at least four claims you can confirm, each
   with an evidence ID. A fair review says so.
4. One more weakness that is not an "error" but would not survive a review of a
   final report: the last line.
5. Write it as a table — memo claim / your assessment / evidence — ready to paste
   into Appendix C of your report.

---

## 8 · The executive summary, rewritten

This is a real-looking first draft. Rewrite it for the board in **at most 250
words**. Then run your version through `report-check.py`: paste it under a
`## 1. Executive summary` heading in a scratch file, and check only that.

```bash
./report-check.py work/summary.md --summary-only
```

> On 10/03 at 08:41 the user m.antunes on WS-FIN-07 (10.20.30.47) clicked a
> phishing link and executed FT2026_1187.pdf.lnk, which ran powershell -enc and
> rundll32 upd.dll,Start, establishing C2 to 203.0.113.66 (T1071.001). The
> attacker dumped LSASS with comsvcs.dll, which proves j.pires is the insider who
> enabled the attack, and moved laterally via RDP to FS01, where rclone
> exfiltrated less than 500 MB to 192.0.2.77. Encryption certainly affected every
> file on the network. HR data was probably not taken. All systems are now clean.

1. List what is wrong before you rewrite: jargon, unsupported absolutes, a factual
   error, an unfair statement about a person, missing time zone, and two things a
   board needs that are not there at all.
2. Swap with someone in your room. Can they tell, from your version alone, what
   the company must decide this week?

---

## 9 · Team reconstruction (breakout rooms)

Each room produces one shared draft. Roles: **scribe** (owns the file), **clock
keeper** (owns section 5 and every UTC conversion), **devil's advocate** (owns the
"alternative explanations" line of every finding and section 10).

```bash
./report-scaffold.py --register $B/evidence-register.csv --author "Team N" --out work/team-report.md
../session-04-log-forensics/supertimeline.py --evidence $B/S04 --year 2026 \
      --skew WS-FIN-07=+277 --skew '*=0' --since '2026-03-10 08:00' --until '2026-03-11 04:00' \
      --out work/tl.csv
./report-check.py work/team-report.md
```

Do not run `supertimeline.py` until your clock keeper can show the room the
evidence for every `--skew` value. The `+277` above is the course's; your report
must show where it comes from.

In 20 minutes, aim for:

1. Section 5 (clocks) complete.
2. Section 6: a timeline of at least 15 rows from the phishing email to the last
   RDP disconnect, every row with an evidence ID, benign events marked as benign.
3. Findings **F-01 to F-06**, one per question in section 2, in the finding format.
4. `report-check.py` run, and its problems either fixed or listed.

---

## 10 · Peer review

Swap drafts with another room (the trainer pairs them). Run `report-check.py`
on theirs, then answer, in writing, in their file under a `## Review` heading:

1. Pick their strongest finding. Could you reproduce it from the evidence ID and
   the command alone? If not, what is missing?
2. Pick their weakest finding. What is the best alternative explanation they did
   not consider?
3. Find one sentence that would not survive cross-examination. Rewrite it.
4. Does their timeline say which clock each row came from, or only that it is UTC?
5. Is there anything in their draft that a data subject would not want to read
   about themselves in it?

---

## 11 · The forensic report — graded, individual

**Due: Thursday 17 December 2026, 23:59.** Weight: **25 %** of the course grade
(the largest single deliverable).

Write the forensic report on INC-2026-007 for Ceres Alimentar, as the panel
firm's examiner, on all the evidence in the bundle.

```bash
./report-scaffold.py --register work/case-bundle/evidence-register.csv --author "Your Name" --out work/report.md
# ... write ...
./report-check.py work/report.md
```

### What to hand in

Submit one archive, `S5-<student-number>.zip`, through the course Teams assignment, containing:

1. `report.md` (Markdown) **and** a PDF of it. 6 to 12 pages is the expected size;
   longer is not better. The executive summary is one page.
2. Your `BUNDLE-INFO.txt` and the SHA-256 of your `MANIFEST.tsv` (also quoted in section 3).
3. The output of your final `./report-check.py report.md` run, pasted at the end
   of Appendix B. If it still lists problems, say why you disagree with each.

### What the report must answer

The six questions in section 2 of the scaffold: initial access and patient zero;
what the attacker did, in order, on which hosts; whether data was taken, what,
how much, when and where; which categories of personal data and how many data
subjects; who else received the email and whether anyone else acted on it; and
whether the panel firm's initial findings are correct.

### Rubric (100 points)

| Criterion | Points | What earns them |
|---|---|---|
| **Accuracy of findings** | 30 | The six questions answered correctly. The traps in the case handled (clocks, cleared logs, benign look-alikes, partial views). The memo's errors identified and corrected. |
| **Evidence and reasoning** | 25 | Every finding cites evidence IDs and the record within them; fact and inference kept apart; confidence on the stated scale with a reason; corroboration across independent sources where it exists; negative results reported. |
| **Timeline** | 15 | UTC, the clock of every source stated and corrected with evidence; complete from the email to the last disconnect; benign events shown as benign; each row traceable. |
| **Clarity and executive summary** | 15 | A one-page summary a board can act on, with no jargon and no overstatement, that says what is not known. The rest is readable by a technical reviewer without asking you anything. |
| **Limitations and alternatives** | 10 | Specific limits (what, why, which findings they affect, what would close them); real alternative explanations, honestly weighed. |
| **Recommendations** | 5 | Specific, prioritised, each tied to a finding. |

**Penalties:** personal data of a data subject in the report (−10 per
occurrence, and it would be a data breach of its own in real life); an evidence ID
that does not exist in your register (−2 each); a claim about a named person that
the evidence does not support (−5).

### What excellent looks like

- An executive summary that the CFO could read aloud to the board, that does not
  contain a single IP address, and that still tells them what was taken, how sure
  we are, and what they must decide.
- A clocks section that shows the measurement, not just the offset.
- Findings that would survive a hostile reader: every one reproducible from its
  evidence ID and the command in Appendix B, every absolute replaced by what the
  evidence actually supports.
- At least one finding where you explain why the obvious reading is wrong.
- A "what is not known" section that a successor examiner could use as a work plan.
- Fairness: to the people in the case, and to the authors of the memo.

### Academic integrity

The report is **individual and in your own words**. In class you worked in teams,
and facts found together — times, evidence IDs, the timeline rows — are shared
material that everyone may use. The analysis, the reasoning, the structure and
every sentence of the report must be yours. Do not submit text written by anyone
or anything else; reports that share wording beyond quoted evidence will be
discussed with their authors. Quote evidence exactly, and mark it as a quotation.

---

## Go further

1. **Obscured is not encrypted.** rclone's "obscure" is AES-256-CTR with a key
   that is published in rclone's own source code (`fs/config/obscure/obscure.go`)
   and a random IV stored in front of the ciphertext. Reveal the password without
   rclone, with Python and `openssl`. Then write one paragraph on why you still
   must not use it.

   ```bash
   p=$(sed -n 's/^pass = //p' $B/S05/new/rc.conf | tr -d '\r')
   python3 -c "import base64,sys; s=sys.argv[1]; b=base64.urlsafe_b64decode(s+'='*(-len(s)%4)); print(b[:16].hex(), b[16:].hex())" "$p"
   # first value = IV, second = ciphertext
   KEY=9c935b48730a554d6bfd7c63c886a92bd390198eb8128afbf4de162b8b95f638
   echo <ciphertext-hex> | xxd -r -p | openssl enc -d -aes-256-ctr -K $KEY -iv <iv-hex>; echo
   ```

2. **Encryption rate.** From the D: journal sample and the counts, estimate files
   per minute per share. Is the order of the shares visible? What would you need
   to say when the encryption of a given folder started, to the second?
3. **The Message-ID and the X-Mailer.** What do they reveal about the sending
   infrastructure, and how would you use them in a threat-intelligence request
   to a mail provider (without uploading anything)?
4. **Put the NTFS events in the super timeline.** Convert the FS01 `$J` rows you
   rely on into the `supertimeline.py` CSV columns and merge them. Do they sit
   where you expect next to the Sysmon events?
5. **A Sigma rule for the shortcut.** Write a detection for an interactive user
   creating a LNK in `Recent` that points into `C:\PerfLogs`. What would its false
   positives be on a file server?

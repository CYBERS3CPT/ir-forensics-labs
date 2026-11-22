# Session 4 — Exercises

You are the panel firm's analysts. You have the hosts (Session 3) and the
network (Session 3). Now you have the logs of the four machines involved, and
one question: **where did this start, and how did it get from there to the
backups and the encryption?**

Everything you hand in is in **UTC**, says **which clock** each time came from,
and carries an **evidence reference** for every claim: `FILE.jsonl#EventRecordID`
for Windows, `HOST/var/log/FILE:LINE` for text logs, `HOST/var/log/wtmp@OFFSET`
for wtmp/btmp.

```bash
cd ir-forensics-labs/session-04-log-forensics
./verify.sh
```

Exercises marked **[D]** feed the deliverable (Exercise 12). Keep your notes in
`work/notes.md` as you go: the deliverable is mostly those notes, cleaned up.

> **jq tip.** `@tsv` escapes backslashes (`CERES\\j.pires`). When you want them
> as Windows prints them, use `join("\t")` instead.

---

## Block 1 — Windows logs: what each one answers

### Exercise 1 — Inventory before analysis

**Goal:** know what you have, and what you do not, before reading a single event.

1. `./verify.sh`, then `./evtx-query.py --stats`.
2. For each file: first and last event, and the Event IDs present.
3. Look hard at `FS01_Security.jsonl`. When does it start? How many events?
   What is the first event, and what is its `EventRecordID`?
   ```bash
   head -1 evidence/windows/FS01_Security.jsonl | jq '.Event.System | {EventRecordID, EventID, t: .TimeCreated["#attributes"].SystemTime}'
   ```
4. What does a first record ID in the millions tell you about the log before it?
5. Which logs from FS01 cover the period the Security log no longer does?

**Hand in:** a table *source → time span → what it can answer → what it cannot*,
and three sentences on FS01's Security log.

### Exercise 2 — jq warm-up (ten one-liners)

**Goal:** be able to answer a question about raw events with nothing but `jq`.
Run each, and write one line on what the output tells you.

```bash
W=evidence/windows
# 1. Event IDs in a file
jq -r '.Event.System.EventID' $W/FS01_Sysmon.jsonl | sort -n | uniq -c
# 2. The log clear, and who did it (UserData, not EventData!)
jq -c 'select(.Event.System.EventID==1102) | .Event.UserData.LogFileCleared' $W/FS01_Security.jsonl
# 3. Logon types on the workstation
jq -r 'select(.Event.System.EventID==4624) | .Event.EventData.LogonType' $W/WS-FIN-07_Security.jsonl | sort -n | uniq -c
# 4. Rare parent -> child pairs float to the top
jq -r 'select(.Event.System.EventID==1) | [(.Event.EventData.ParentImage|split("\\")|last), (.Event.EventData.Image|split("\\")|last)] | join(" -> ")' $W/WS-FIN-07_Sysmon.jsonl | sort | uniq -c | sort -n | head -15
# 5. Decode every encoded PowerShell command line (UTF-16LE!)
jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.CommandLine|test("-enc";"i"))) | .Event.EventData.CommandLine | split(" ") | last' $W/WS-FIN-07_Sysmon.jsonl | while read -r b; do echo "$b" | base64 -d | iconv -f UTF-16LE -t UTF-8; echo; done
# 6. DNS names asked for, rarest first
jq -r 'select(.Event.System.EventID==22) | .Event.EventData.QueryName' $W/WS-FIN-07_Sysmon.jsonl | sort | uniq -c | sort -n | head
# 7. Kerberos TGTs that are NOT AES256
jq -r 'select(.Event.System.EventID==4768) | [.Event.EventData.TargetUserName, .Event.EventData.TicketEncryptionType, .Event.EventData.IpAddress] | join("\t")' $W/DC01_Security.jsonl | sort | uniq -c | sort -n | awk '$3!="0x12"'
# 8. RDP sessions on the file server: who, from where
jq -r '[.Event.System.TimeCreated["#attributes"].SystemTime, .Event.System.EventID, .Event.UserData.EventXML.User, .Event.UserData.EventXML.Address] | join("\t")' $W/FS01_TerminalServices-LocalSessionManager.jsonl
# 9. Services installed (and the SID that installed them)
jq -c 'select(.Event.System.EventID==7045) | {t: .Event.System.TimeCreated["#attributes"].SystemTime, sid: .Event.System.Security["#attributes"].UserID, name: .Event.EventData.ServiceName, path: .Event.EventData.ImagePath}' $W/FS01_System.jsonl
# 10. Every connection to an RDP port, on every host that logged it
jq -r 'select(.Event.System.EventID==3 and .Event.EventData.DestinationPort==3389) | [.Event.System.Computer, .Event.EventData.UtcTime, .Event.EventData.SourceIp, (.Event.EventData.SourcePort|tostring), .Event.EventData.Initiated] | join("\t")' $W/*_Sysmon.jsonl | sort -t$'\t' -k4
```

**Hand in:** the ten one-line answers. Keep #4, #5, #7, #8 and #10 open: you
will need them again.

### Exercise 3 — Patient zero: the first process tree [D]

**Goal:** prove how code first ran on WS-FIN-07, as a chain of processes.

1. Start from the oddest pair in jq #4 and from the decoded command in jq #5.
2. Build the chain from the browser download to the persistent implant, one
   event per link. Pivot on `ProcessGuid` → `ParentProcessGuid`, not on names:
   ```bash
   ./evtx-query.py --host WS-FIN-07 --where ProcessGuid='{...}' --fields Time,EventID,RecordID,Summary
   ./evtx-query.py --host WS-FIN-07 --where ParentProcessGuid='{...}'
   ```
3. Add the non-process events that belong to the chain: the file created by the
   browser (and its `Zone.Identifier`), the DLL written to disk, the DLL loaded,
   the first connection to the internet, the registry value that brings it back.
4. Compare the 4104 script block with the Sysmon command line. Which log told
   you what the script *did*, and which only that it ran?

**Hand in:** the chain as a table (host time, EID, record ID, what), and the
vector in one sentence.

### Exercise 4 — The 10:20 RDP: attacker or helpdesk? [D]

**Goal:** decide, with evidence, whether j.pires' logon on WS-FIN-07 is
lateral movement.

1. `./evtx-query.py --host WS-FIN-07 --eid 4624,4634,4647,4672 --where TargetUserName=j.pires`
   (and `--where SubjectUserName=j.pires` for the 4672).
2. Where did it come from? Which machine is that address (`../CASE.md`)? What did
   that session run (Sysmon, same `LogonId`)? How long did it last?
3. Cross-check with DC01: which service ticket was issued, to which client?
4. Session 1 gave you the helpdesk queue
   (`../session-01-ir-methodology/evidence/helpdesk-tickets.csv`). Does anything there match?
5. Benign or not — why does this logon matter for what happens later today?

**Hand in:** verdict + four pieces of evidence + one sentence on why it matters.

---

## Block 2 — Credentials, clocks, lateral movement

### Exercise 5 — The credential theft, and the file that is gone [D]

**Goal:** show the LSASS dump happened although `lsass.dmp` no longer exists.

1. `./sigma-lite.py --rule lsass` and `./sigma-lite.py --rule comsvcs`. Triage
   every hit of the first rule: which are expected, which are not, and why?
2. For the one that matters: the process that opened LSASS, the access mask,
   the file it wrote, the process that deleted it and when.
3. That process ran at High integrity. The implant ran at Medium. What happened
   in between? (Look at the processes just before it, and at Sysmon 12/13.)
4. Which account's credentials were in LSASS at that moment, and since when?

**Hand in:** the sequence with record IDs, the ATT&CK techniques, and which
credentials were exposed.

### Exercise 6 — Measure the clock [D]

**Goal:** establish, from evidence, the offset of each Windows host's clock.

1. A TCP connection has the same source address, source port, destination
   address and port at both ends. Find connections logged by **two** hosts
   (jq #10 is a start).
2. For each pair, compute *initiator's time − receiver's time*. Is it constant?
3. Which host do you trust, and why? (Domain members sync to the DC; look for
   other events that both a DC and a workstation recorded about the same action.)
4. Linux: what does `_collection/timedatectl.txt` say? Is that enough?
5. State each offset as *HOST was N s ahead/behind true time*, with the method
   and the evidence. Then:
   ```bash
   ./evtx-query.py --skew HOST=+N ...           # check a few events with both clocks
   ```

**Hand in:** a clock table (host, offset, method, evidence IDs). From here on,
every time in your work is corrected UTC.

### Exercise 7 — How did the attacker become j.pires? [D]

**Goal:** show which credential reached FS01, how it was used, and what the DC saw.

1. On WS-FIN-07, after the dump: `./evtx-query.py --host WS-FIN-07 --eid 4624 --where 'LogonType~^(9|10)$'`.
   What is logon type 9, what is `seclogo`, what is `TargetOutboundUserName`?
2. On DC01, j.pires' authentications that day, by source and encryption:
   ```bash
   ./evtx-query.py --host DC01 --where 'TargetUserName~^j\.pires' --since '2026-03-10 07:00' --until '2026-03-11 04:00'
   ```
   What is different about the ones from WS-FIN-07? Is the RC4 rule's other
   account (`./sigma-lite.py --rule rc4`) a problem, and how would you tune it?
3. Which program on WS-FIN-07 opened the RDP connection, with which options,
   and from which logon session?
4. On FS01 the Security log was cleared. Show the RDP session anyway: logon,
   disconnect, reconnect, last disconnect — and the inbound connection.
5. Is any 4624 for that session left on FS01? Why (not)? Which post-clear
   Security event still names the client machine?

**Hand in:** the credential path *dump → hash → TGT → RDP*, with record IDs,
and the ATT&CK IDs.

### Exercise 8 — FS01: staging, exfiltration, sabotage [D]

**Goal:** everything the session on FS01 did, from Sysmon and System alone.

1. `./evtx-query.py --host FS01 --eid 1,3,11,22 --where 'User~j.pires|SYSTEM' --since '2026-03-10 11:30' --until '2026-03-11 04:00'`
   — then drop the noise (`--where 'Image!~...'`).
2. How did the tools arrive — all of them, the encryptor included (which process
   wrote each, and when)? Was there a download?
3. Archive and transfer: command lines, destination, start and end times.
   What does `OriginalFileName` say about `rcl.exe`?
4. The night: the service (7045 + 7036 + Sysmon), the shadow copies, the
   backup catalog, the log clear. How was the Security log cleared, and does the
   1102 agree with Sysmon on who and when?
5. The encryption: which process wrote the ransom notes, and why is it not the
   one you expected? (Think about how `\\FS01` paths are written.)
6. What left FS01 for another internal host in the night?

**Hand in:** a timeline of FS01 (corrected UTC, record IDs, ATT&CK).

---

## Block 3 — Linux, detections, the supertimeline

### Exercise 9 — SRV-BKP01: the backups [D]

**Goal:** reconstruct the session on the backup server and see through the cleanup.

1. ```bash
   B=evidence/linux/SRV-BKP01
   ./linux-auth.py --year 2026 $B/var/log/auth.log.1 $B/var/log/auth.log
   ./wtmp-read.py $B/var/log/wtmp
   ./wtmp-read.py $B/var/log/btmp --raw
   grep -n 'Mar 11 0[12]:' $B/var/log/syslog
   ```
2. Who tried what, from where, in what order? Which account got in, by which
   method, and is that method normal for this account (look at the other days)?
3. What did the account do with sudo? Where are the commands typed in the root
   shell recorded — and where are they **not**?
4. Read `$B/home/bkpadmin/.bash_history`, `$B/root/.bash_history` and
   `$B/_collection/stat.txt`. bkpadmin was logged in 02:10–02:17: are that
   session's commands in its history? Why not? What does the mtime say?
   Why did root's history survive?
5. What stopped the backups, what deleted them, what removed the scheduled
   check, and when — with a log line or file time for each.
6. Join the two ends: which FS01 events match the SSH attempts here, port by port?

**Hand in:** the SRV-BKP01 timeline, the anti-forensics you found, and how you
saw past each one.

### Exercise 10 — What would the detections have said? [D]

**Goal:** judge the rules, then write the ones that were missing.

1. `./sigma-lite.py --summary`, then each rule in full. Classify every hit as
   true positive / false positive, with a reason.
2. One rule has candidate events and zero hits. Which, and why? Which other
   rule caught the same thing from another log?
3. For each step of the attack, which rule fired first, and how long after the
   step? Which steps had no rule at all?
4. Write **three** new rules (Sigma YAML, in `work/my-rules/`) for steps that
   no rule caught, or caught late. Candidates: an auto-elevate binary spawning a
   shell; logon type 9 with `seclogo`; `wevtutil cl`; an SSH client on a server.
   Run them: `./sigma-lite.py --rules work/my-rules/`. Each must hit the attack
   and you must say what it hits besides.

**Hand in:** the triage table and your three rules with their output.

### Exercise 11 — The supertimeline [D]

**Goal:** one CSV, one clock, every source — then forty lines that tell the story.

1. ```bash
   ./supertimeline.py --year 2026 --out work/supertimeline.csv
   ```
   Read why it refuses. Then give it your clock decisions from Exercise 6.
   If it refuses again, read that message too.
2. Reduce it: `./timeline-reduce.py work/supertimeline.csv --peaks`, then an
   anchor and a window per phase, `--exclude` for known-good noise (printer
   telemetry, EDR, cron, the beacon once you have proven it).
3. Pick **at most 40 lines** that carry the attack from the first click to the
   last disconnect, and annotate each (why this line, what it proves).

**Hand in:** the 40-line annotated excerpt, `supertimeline.provenance.txt`, and
the `.filter.txt` of every reduction you used.

### Exercise 12 — DELIVERABLE: attack flow reconstruction

**Graded — 20 % of the course grade. Due Wednesday 9 December 2026, 23:59 (Lisbon = UTC).**
Submit one archive, `S4-<student-number>.zip`, through the course Teams assignment.

```bash
cp hops-template.csv work/hops.csv            # write one row per step
./attack-flow.py work/hops.csv --year 2026 --skew ... --md work/attack-flow.md
```

Hand in one PDF (or Markdown) report, plus `hops.csv`, `attack-flow.md`, your
supertimeline excerpt, the provenance/filter files and `work/my-rules/`:

1. **Origin** — patient zero, the initial vector, the first evidence of
   execution (Exercises 3, 4).
2. **Path** — every hop host → host with corrected UTC times and the evidence
   ID for each (`attack-flow.py` must report **0 to fix**).
3. **Credentials** — which accounts were used, how each was obtained, how each
   was used; and what you cannot prove (say so).
4. **Clocks** — your clock table and how you measured it.
5. **ATT&CK mapping** — technique per step, tactics covered.
6. **Anti-forensics** — everything the attacker did to hide, and how you saw
   past each one (which surviving source, which inference).
7. **Supertimeline excerpt** — ≤ 40 annotated lines + provenance.
8. **Three detections** that would have caught this earlier — rule, logsource,
   which step, how early, expected false positives.

| Criterion | Points |
|---|---|
| Origin and vector, with evidence | 2 |
| Path: hops, corrected UTC, evidence IDs, validates with `attack-flow.py` | 4 |
| Credentials: which, how obtained, how used, limits stated | 3 |
| Clock: offsets measured, method and evidence | 2 |
| Anti-forensics: found and seen past (at least three) | 3 |
| ATT&CK mapping, correct and specific (sub-techniques) | 2 |
| Supertimeline excerpt: ≤ 40 lines, annotated, provenance included | 2 |
| Three detections: valid rules, run, hits and false positives discussed | 2 |
| **Total** | **20** |

Deductions: any timestamp without its clock stated (−1, once); a legitimate
activity reported as malicious without addressing the evidence against it (−2);
a claim with no evidence ID (−0.5 each, up to −3).

---

## Go further

- **Beacon vs. printer from Sysmon alone.** For every destination of
  `WS-FIN-07` Sysmon EID 3, compute the intervals between connections
  (`jq` → `python3`): median, spread, first and last. Which two are periodic,
  and which one has jitter? Does it match what you found in Session 3?
- **Baseline the RC4 rule.** Rewrite `win_security_kerberos_rc4_tgt.yml` so the
  scanner account stops firing without hiding a user account that suddenly
  asks for RC4. What did you key on, and what can an attacker still do?
- **Record-ID gaps.** Within a single log, are the `EventRecordID`s contiguous?
  What would a gap mean, and how is that different from a clear?
- **Real tools.** If you have Windows `.evtx` files of your own (a lab VM),
  convert them with `evtx_dump -o jsonl` and run `sigma-lite.py` and
  `evtx-query.py` on them. Then run Chainsaw or Hayabusa with the full Sigma
  ruleset on the same files and compare.
- **One more rule, Linux side.** sigma-lite only reads Windows. Write, in plain
  `grep`/`awk`, the detection that would have alerted on SRV-BKP01 at 02:10.
  Why did nothing alert there that night (Session 1 has the answer)?

# Session 3 — Exercises

**The situation.** Thursday 12 March 2026, morning. You are the analysts from
**Faroleiro DFIR**, the insurer's panel firm. Yesterday at 16:20 UTC Ceres
handed you exhibit **EXH-WSFIN07-01**: a KAPE triage collection of WS-FIN-07,
the workstation the RDP sessions on FS01 came from. Nobody has read it yet.
This morning Ceres' IT team adds what the network kept: a 45-minute packet
capture of WS-FIN-07 from Tuesday morning, the Zeek logs and the firewall log
for Tuesday 07:00 to Wednesday 12:00.

Management wants answers by tonight: what happened on the first workstation,
how did it get in, where does it talk, is it still talking, did data leave
(from where, how much, when), and what are we unable to see.

The host comes first. What it tells you sets the questions the network has to
answer — starting with one: *is the file the host has the same one the network
delivered?*

Everything is fictional. Nothing in `evidence/` (here or in Session 2's folder)
goes to VirusTotal, a search engine, a passive-DNS site or any other public
service.

## Before you start

```bash
cd ir-forensics-labs/session-03-network-forensics
(cd evidence && sha256sum -c SHA256SUMS)       # every line must say OK
mkdir -p work                                  # git-ignored; what you produce goes here
echo "$(date -u +%FT%TZ)  START session 3 — $(whoami)@$(hostname)" > work/my-notes.txt
T=../session-02-communication-and-collection/evidence/WS-FIN-07_triage   # the host exhibit
P=evidence/ws-fin-07_2026-03-10_0835-0920.pcap # the capture
export TZ=UTC                                  # capinfos, tshark dates and Suricata print LOCAL time otherwise
```

Run the last three lines again in every new terminal. Without `TZ=UTC`, a VM
set to another time zone shifts `capinfos` and Suricata times by hours, and
nothing warns you.

The host exhibit stays where it is, in the Session 2 folder (Session 5 uses it
too). You only read it: nothing under `evidence/` — either folder — is ever
edited.

Keep `work/my-notes.txt` going: one line per finding, with the UTC time, the
clock it came from, the source (Prefetch / Edge / pcap / conn.log / fw01 …) and
the command or uid that shows it. The report at the end is mostly copied from
that file.

| # | Exercise | Tools | Time | Graded |
|---|---|---|---|---|
| | **Block 1 — The first workstation: what the host says** | | | |
| 1 | Receive the exhibit; which clock? | `sha256sum`, `grep` | 8 min | → D |
| 2 | The browser | `sqlite3`, `artefacts.py history` | 8 min | → D |
| 3 | What ran | CSVs, `artefacts.py decode-ps` | 12 min | → D |
| 4 | One timeline, one clock | `artefacts.py timeline` | 7 min | → D |
| | **Block 2 — The wire: sources, the download, DNS, TLS** | | | |
| 5 | Receive the network evidence | `sha256sum`, `capinfos`, README | 6 min | → D |
| 6 | The download: is it the same file? | tshark, `carve.sh` | 10 min | **D** |
| 7 | DNS: the first thing the implant asked | tshark, `zcut.py` | 5 min | → D |
| 8 | TLS without decryption | `pcap-triage.sh --section tls`, tshark | 10 min | **D** |
| | **Block 3 — Beacons, exfiltration, detection** | | | |
| 9 | Beacon hunting | `beacon-hunt.py` | 12 min | **D** |
| 10 | Exfiltration | `exfil.py` (Zeek and firewall) | 12 min | **D** |
| 11 | Detection: Suricata, offline | `rules/local.rules`, `suricata-offline.sh` | 8 min | **D** |
| | **At home** | | | |
| 12 | What else rode the channel? | `exfil.py`, `zcut.py` | 15 min | **D** |
| 13 | Clock skew: network against host | pcap, the exhibit | 15 min | **D** |
| 14 | Blind spots | README, your head | 10 min | **D** |
| 15 | The findings report | your editor | homework | **D** |

---

## Block 1 — The first workstation: what the host says

The artefact map (Prefetch, Amcache, Shimcache, LNK, registry, browser
history, `$MFT`/`$J`) and the forensic principles behind it were taught in the
Blue Team module, **Sessions 7 and 8**. Tonight you use them; go back to those
slides if a name below is new. Read `$T/../README.md` (the exhibit's README) and
`$T/collection-notes.txt` before anything else.

The `mout/` CSVs use the column names of Eric Zimmerman's tools exactly, so what
you learn here works on real KAPE output. They are excerpts: a real `$MFT`
export has a row for every file on the disk. Event logs are not in the exhibit
(Session 4).

### 1 · Receive the exhibit; which clock?

```bash
(cd $T && sha256sum -c MANIFEST.sha256)
sha256sum $T/MANIFEST.sha256          # compare with the value in collection-notes.txt
grep -n -i -E 'clock|w32tm|ahead|reference' $T/collection-notes.txt
head -3 $T/kape/ConsoleLog.txt
grep -i -E 'W32Time|TimeZone' $T/mout/Registry/*.csv
```

1. Does the package verify? Which file is present but not in the manifest, and
   why is that not a problem?
2. By how much is WS-FIN-07's clock wrong, in which direction, and what is the
   evidence? Give the number to the second.
3. Corroborate it from a **second, independent** place in the package: when
   does KAPE say it started, and when does the collector say she started it?
4. Find a plausible **cause** in the registry output: when did WS-FIN-07 last
   synchronise, and against what? The notes write that date `02/03/2026` —
   which date is it, and how do you know?
5. Which timestamps in this package are **not** on WS-FIN-07's clock at all?

Write the offset in your notes now. Every host time you quote tonight is
corrected with it, and says so.

### 2 · The browser

```bash
H="$T/tout/C/Users/m.antunes/AppData/Local/Microsoft/Edge/User Data/Default/History"
sha256sum "$H"
sqlite3 -readonly "file:$H?immutable=1" '.tables'
sqlite3 -readonly "file:$H?immutable=1" \
  "SELECT id, target_path, start_time, received_bytes, referrer, opened FROM downloads;"
./artefacts.py webkit <a start_time value>
./artefacts.py history "$H"
sha256sum "$H"                        # unchanged?
```

1. Convert one `start_time` **by hand** (microseconds since 1601-01-01 UTC),
   check it against `artefacts.py`, then put it on the **true** clock.
2. Where is the ZIP's URL — and where is it *not*? Why? What does the empty
   `referrer` suggest about where the link was clicked?
3. How big is the ZIP, according to the browser? Write it down: the network
   will have an opinion about that number in exercise 6.
4. Was the ZIP opened from the browser? When (true UTC)?
5. What did Marta do in the browser in the minutes after the download? What
   does that suggest about what she thought had happened?
6. Why `-readonly` *and* `immutable=1`?

### 3 · What ran

```bash
grep -i -E 'powershell|rundll32|whoami|nltest|net1?\.exe|mstsc|w32tm|kape' \
  $T/mout/ProgramExecution/*_PECmd_Output.csv | cut -d, -f2,10,11
grep -i rundll32 $T/mout/ProgramExecution/*_PECmd_Output.csv \
  | grep -o -E 'RUNDLL32\.EXE-[0-9A-F]+\.pf|[^\\]+\.(DLL|DMP)' \
  | awk '/\.pf$/{printf "\n%s:", $0; next} {printf " %s", $0} END{print ""}'
grep -i '\.pdf\.lnk' $T/mout/FileFolderAccess/*_LECmd_Output.csv
./artefacts.py decode-ps '<the base64 after -enc>'
grep -i -E 'Run|Terminal Server|UserAssist' $T/mout/Registry/*.csv
grep -i -E 'upd\.dll|lsass|FT2026' $T/mout/FileSystem/*.csv | cut -c1-220
```

1. There are **three** `RUNDLL32.EXE-*.pf` files. Why three? What did each
   invocation load, and which one is benign?
2. The shortcut: what does it really run, and with what icon? What does the
   decoded command do, step by step? What do `MachineID`, `MachineMACAddress`
   and `TrackerCreatedOn` tell you, and about **which** machine?
3. Persistence: find it in the registry output. Why does every value under that
   key show the **same** `LastWriteTimestamp`, and which of them are legitimate?
4. Credential theft: what was created, where, by what, and when was it deleted?
   Which artefact gives you the deletion time?
5. What on this host links it to the RDP sessions on FS01? What does each
   artefact prove, and what does it **not** prove?
6. Two programs in the Prefetch output were run **by the collector**. Which,
   and how do you show it?
7. Shimcache lists `mstsc.exe` with a 2025 time. Does that mean it ran in 2025?

Questions 5–7 can be finished at home if the clock beats you.

### 4 · One timeline, one clock

```bash
./artefacts.py timeline $T | head -4                             # read the header lines
./artefacts.py timeline $T --skew WS-FIN-07=+<seconds> \
    --from "2026-03-10 08:30" --to "2026-03-10 12:00" --csv work/ws-fin-07-timeline.csv
./artefacts.py timeline $T --skew WS-FIN-07=+<seconds> --from "2026-03-10 08:30" --to "2026-03-10 12:00" | less -S
./artefacts.py timeline $T --grep 'lnk-maker' --wide
```

1. Write the ten events that matter on 10 March, in **true** UTC, each with the
   artefact(s) that support it. At least two of them must be supported by two
   independent artefacts.
2. One event in the morning is legitimate and will look suspicious to anyone
   who reads only this host. Which, and what would you need to confirm it is
   benign? (You will not find the answer on this host.)
3. Which rows did `--skew` deliberately **not** correct, and why is that right?
4. **The hand-off.** Write down, from the host only: the ZIP's name and size,
   the shortcut's name, size and SHA-1 (look in `$T/kape/CopyLog.csv`), and the
   domain the PowerShell line downloads from. The rest of the evening asks the
   network about them. First question: *is the file the host has the same one
   the network delivered?*

---

## Block 2 — The wire: sources, the download, DNS and TLS

### 5 · Receive the network evidence

1. You verified `SHA256SUMS` at the start. Write the SHA-256 of the pcap in
   your notes **before** you open it.
2. `capinfos $P` — first packet, last packet, number of packets, link type.
3. Read *Where the sensors sit* in the README. In three lines each, write what
   **(a)** the pcap, **(b)** the Zeek logs and **(c)** the firewall log can and
   cannot tell you. Think about: time window, which hosts, payload or metadata,
   timestamp resolution, what "bytes" means in each.

*Hand in (→ D):* the hashes (pcap and exhibit manifest), the capture window,
the three-source table.

### 6 · The download: is it the same file? (graded)

```bash
./pcap-triage.sh $P --section http
tshark -r $P -q -z follow,tcp,ascii,<stream> | head -30
./carve.sh $P work/carved && cat work/carved/MANIFEST.txt
awk -F, 'NR==1 || $10=="<server_ip>"' evidence/fw01-egress.csv
```

1. The suspicious plaintext HTTP request: full URL, server IP, time of the
   request (UTC, capture clock), User-Agent.
2. *Follow → TCP Stream* on it (Wireshark, or the `tshark -z follow` line).
   What does the server say the file is called, how big, what type? What is the
   server's `Date:` header, and what does it tell you about the server's clock?
3. Carve it. Record the SHA-256 of the archive **and** the SHA-256 and SHA-1 of
   the file inside it. Never open or extract the carved file.
4. **Answer the hand-off question from exercise 4.** Compare the archive and its
   member with what the host recorded (size, name, SHA-1). Same file? Which
   comparisons are strong and which are weak, and why does the host have no
   hash of the ZIP itself?
5. Scope: did any other internal host ever connect to that server between
   Tuesday 07:00 and Wednesday 12:00?

*Hand in (→ D):* URL, IP, time, User-Agent, both hashes, the host match, scope.

### 7 · DNS: the first thing the implant asked

The domain comes from the PowerShell line you decoded in exercise 3.

```bash
tshark -r $P -Y 'dns.qry.name == "<domain>"' \
    -T fields -e frame.time_utc -e ip.src -e ip.dst -e dns.qry.type -e dns.a -e dns.resp.ttl
python3 zcut.py -d evidence/zeek/dns.log ts id.orig_h id.resp_h query answers TTLs \
  | grep '<domain>' | awk '{print $2, $3}' | sort | uniq -c
```

1. When was it **first** asked, by whom, of which server, and what were the
   answer and TTL? How many seconds until the first TCP SYN to the answer IP?
2. Over the whole window, one of the clients asking for that name is not a
   workstation. Is it infected? Explain, using the README's sensor diagram.

### 8 · TLS without decryption (graded)

```bash
./pcap-triage.sh $P --section tls
tshark -r $P -Y 'tls.handshake.type == 11 && ip.src == <c2_ip>' -V \
  | grep -A3 -E 'issuer|subject|notBefore|notAfter' | head -40
```

1. For the C2 domain there are **two** different client fingerprints (JA4).
   Which program produced each, and how do you know? (Hint: compare them with
   the other SNIs in the list; think about the PowerShell line and `rundll32`
   from exercise 3.)
2. Edge's connections have a different JA3 almost every time, yet the same JA4.
   Why? Which of the two would you put in a detection, and why?
3. The certificate (TLS 1.2 sends it in clear): subject, issuer, validity.
   Compare with the certificate the printer-vendor server sends. What is unusual
   about the C2 certificate, and how does its start date compare with the
   timeline you built in exercise 4?

*Hand in (→ D):* SNI, IP, JA3 and JA4 of each program, certificate facts.

---

## Block 3 — Beacons, exfiltration, detection

### 9 · Beacon hunting (graded)

```bash
python3 beacon-hunt.py evidence/zeek/conn.log | tee work/beacons.txt
python3 beacon-hunt.py evidence/zeek/conn.log --explain <c2_ip>
python3 zcut.py -d evidence/zeek/conn.log ts id.orig_h id.resp_h conn_state | awk '$3=="<c2_ip>"' | tail -3
grep '10.20.30.47' evidence/fw01-egress.csv | tail -5
python3 beacon-hunt.py evidence/zeek/conn.log --verdict          # read the refusal
```

1. The top of the list is **not** the C2. What is it, and why is it ranked
   first? Write the paragraph that explains to a manager why it is
   *periodic but explainable*: use at least three numbers from the output
   (jitter, size regularity, number of hosts, start time) and one fact from
   outside the log. (Look again at the HKLM Run values in exercise 3.)
2. For the C2: median interval, jitter, first seen, last seen, number of
   connections. Compare the first contact with the `upd.dll` rows of your host
   timeline. The histogram has a handful of intervals far below the median —
   what are they? (Look at the first and last connections.)
3. *Is it still talking?* The last three connections to the C2 in `conn.log`
   and the last firewall lines for WS-FIN-07: what happened, at what time, and
   in what order were the containment steps done? Does "not seen after" mean
   the implant is gone? (Exercise 3, question 3.)
4. Read the `--verdict` refusal. Do you agree?

*Hand in (→ D):* the benign-beacon paragraph; C2 table (domain, IP, port,
first/last seen, count, median, jitter, how it ended).

### 10 · Exfiltration (graded)

```bash
python3 exfil.py evidence/zeek/conn.log
python3 exfil.py evidence/zeek/conn.log --by host
python3 exfil.py evidence/zeek/conn.log --dst <ip> --claim 2.1GB
python3 exfil.py evidence/fw01-egress.csv --dst <ip>
python3 zcut.py -d evidence/zeek/dns.log ts id.orig_h id.resp_h query answers | grep '<exfil_domain>'
```

1. Which internal host sent the most data to the internet, to which IP and
   name, between which times? What kind of host is it, and should it be
   talking to the internet at all? (Firewall rule names are in the CSV.)
2. Detail the destination: how many connections, how many in parallel, which
   one ended differently, and what started right after it?
3. The actor's leak-site post claims **2.1 GB**. Reconcile the numbers. You
   must address: GB vs GiB; TLS and HTTP framing; the connection that was reset
   and what followed it. Is the claim consistent with the evidence?
4. The firewall's total is different from Zeek's. By how much, and why? Which
   number goes in the report, and how do you word it?
5. Which name did that host resolve before the transfer, and who appears as
   the client in `dns.log`? Explain.
6. A colleague exported from the firewall only the sessions that **ended**
   between 13:10 and 13:35 and concluded "less than 500 MB left". Show why
   that is wrong. (`exfil.py --hourly` helps; so does thinking about when a
   session is logged.)

### 11 · Detection: Suricata, offline (graded)

1. Open `rules/local.rules`. Rule 1 is complete; read it. Complete rules 2 and 3
   (replace `__SNI__` and `__URI__`) with values from your findings.
2. Run:
   ```bash
   ./suricata-offline.sh $P
   E=$(ls -d out/suricata-* | tail -1)/eve.json     # the latest run only
   jq -c 'select(.event_type=="alert") | {timestamp, src_ip, dest_ip, sid: .alert.signature_id, sni: .tls.sni, url: .http.url}' \
     "$E" | sort -u -t, -k4,4 | head
   ```
   The script refuses to run while placeholders remain. When it runs, record
   how many alerts each rule produced, the first and last alert time, and one
   `eve.json` alert line per rule.
3. The SNI rule fires on two different programs. Which two? Is that a problem?
4. Name one way the attacker could evade each of your two rules tomorrow, and
   which evidence source would still see them.

---

## At home — finish what the report needs

### 12 · What else rode the channel? (graded, in the C2 section)

A beacon that only says "nothing to do" is small. Find the C2 connections that
are not:

```bash
python3 exfil.py evidence/zeek/conn.log | sed -n '/flagged/,$p'
python3 zcut.py -d evidence/zeek/conn.log ts uid id.resp_h orig_bytes resp_bytes duration \
  | awk '$3=="<c2_ip>" && ($4 > 2000 || $5 > 2000)'
```

For each: time, direction (who sent more), size, duration. Put them on your
host timeline from exercise 4 (true UTC). What could each one be? Write
*observations* and *hypotheses* separately — the network shows volume, not
content. One of them ends less than a minute before something you found on the
host in exercise 3, question 4.

### 13 · Clock skew: network against host (graded, in the host section)

In exercise 1 you took the offset from the collector's notes. Now measure it
against an independent clock: the capture is on true UTC.

1. Pair two events that appear both on the network and on the host. Good pairs:
   the ZIP download (HTTP response time in the pcap vs Edge's download
   `start_time`), and the start of `upd.dll` (Prefetch run time vs the first
   implant beacon in the pcap). Compute the offset for each pair.
2. A third measurement is *inside the pcap*: the implant's ClientHello carries
   a legacy `gmt_unix_time` in the first four bytes of its random — the host's
   clock, in seconds.
   ```bash
   TZ=UTC tshark -r $P -Y 'tls.handshake.type == 1 && ip.dst == <c2_ip>' \
     -T fields -e frame.time_utc -e tls.handshake.random_time | head -5
   ```
   Why is this field meaningless for the other TLS clients in the capture
   (look at the values) but meaningful here?
3. State the offset, its precision (why your pairs disagree by up to a second)
   and the direction of the correction. Does it agree with exercise 1?

### 14 · Blind spots (graded)

Write the limitations paragraph of your report. At minimum: the FS01 →
SRV-BKP01 activity on Wednesday night (Session 1 told you the backups were
destroyed — can you see how here?), the RDP sessions to FS01 that exercise 3
found the start of, what FS01 asked its DNS server, anything after Wednesday
12:00, the content of every TLS session, and what the host exhibit does not
contain (memory, event logs). For each: *not visible because …* and *where else
to look*.

---

## 15 · Deliverable — Session 3 (20 % of the course grade)

**Due: Thursday 3 December 2026, 18:00** (before Session 4 starts). Submit one
archive, `S3-<student-number>.zip`, through the course Teams assignment,
containing:

- your **findings report** (PDF or Markdown), host and network together;
- your completed `rules/local.rules` and the alert excerpt from exercise 11;
- your host timeline `ws-fin-07-timeline.csv` from exercise 4.

Structure (three to six pages, excluding the appendix):

1. **Sources and integrity** — the exhibit (ID, manifest SHA-256) and the three
   network sources (SHA-256, time windows), what each can and cannot see,
   which clock each uses.
2. **WS-FIN-07 host findings — one page.**
   - *Clock statement:* the offset, its direction, the evidence (collector's
     notes, a second source in the package, at least one network pair from
     exercise 13), its cause, and how every time in the report was corrected.
   - *Findings:* 6–10 dated findings in true UTC with `Z` — the download, how
     the shortcut ran, `upd.dll`, persistence, discovery, credential theft and
     its deletion, the link to FS01 — each with its artefact(s) and a confidence
     word (confirmed / likely / possible); at least two corroborated by two
     independent artefacts.
   - *Not attacker activity:* what you saw and excluded, and why (benign,
     collector footprint).
3. **Initial access** — URL, server IP, time (UTC, capture clock), User-Agent,
   archive hash, inner-file hashes, match with the host evidence, scope (who
   else).
4. **Command and control** — domain, IP, port, first and last contact,
   connection count, interval and jitter (and how you computed them),
   fingerprints (JA3/JA4), certificate, how the channel ended. The connections
   that carried more than a heartbeat (exercise 12), placed on the host
   timeline.
5. **The benign beacon** — what it is and the evidence that it is benign.
6. **Exfiltration** — source host, destination (IP and name), start and end,
   volume (bytes, GB and GiB), number of streams, the reset and retry,
   reconciliation with the 2.1 GB claim, corroboration by the firewall.
7. **Blind spots** — exercise 14.
8. **IOC table** — type, value, first seen, last seen (UTC), source, context.
   Host and network indicators of the attack only. Benign infrastructure does
   not go in an IOC table (say so in section 5 instead).
9. **Detection** — your two rules and their alert counts on the capture.

Every finding: one sentence of fact, the UTC time and which clock, the evidence
(file + filter/command, uid or tcp.stream, artefact and row), and your
confidence. Facts and interpretations in separate sentences.

### Rubric (20 points)

| Criterion | Points |
|---|---|
| **Host findings (WS-FIN-07):** clock offset with evidence from the package **and** from a network pair, direction, precision, applied consistently (2); key events correct in true UTC, each with artefacts, at least two corroborated (2); benign and collector activity excluded with reasons, limits stated (1) | 5 |
| Initial access: URL, IP, time, User-Agent, both hashes, host match argued, scope | 2 |
| C2: domain, IP, first/last, count, interval and jitter with method, fingerprints and certificate, how it ended, the non-heartbeat connections | 3 |
| Benign beacon correctly identified and argued with numbers + one external fact | 2 |
| Exfiltration: source, destination, times, volume in bytes/GB/GiB, streams and retry, claim reconciled, firewall corroboration | 3 |
| IOC table: complete, typed, timed, sourced, no benign entries | 2 |
| Suricata: both rules fire on the capture, alert evidence attached, evasion/false-positive discussion | 2 |
| Blind spots and writing: limitations stated, UTC throughout, every finding reproducible from a command | 1 |
| **Total** | **20** |

The course pass mark is 9.5/20 overall, across all five deliverables. A report
that calls the printer telemetry malicious, or quotes WS-FIN-07 host times as
UTC without correction, loses the points for that section regardless of the
rest. Late submissions lose 2 points per started day, unless agreed beforehand.

---

## Go further (optional)

- **Six questions of the capture**: `./pcap-triage.sh $P | tee work/triage.txt`
  runs all six sections (integrity, protocols, talkers, DNS, HTTP, TLS). For
  each, write one line: *the thing I would look at next, and why* — and at least
  one line about something you decided is **not** interesting.
- **One uid, every log**: `python3 zcut.py --uid <uid> evidence/zeek/` with the
  uid of the download in `http.log`, then of a C2 connection in `ssl.log`.
  Follow `resp_fuids` to `files.log` (does Zeek's SHA-256 of the archive match
  your carve?) and `cert_chain_fps` to `x509.log` (`--uid` also accepts a
  certificate fingerprint).
- **Size is metadata**: in the first connection to the C2 (the download of
  `upd.dll`), list the encrypted records:
  `tshark -r $P -Y 'tcp.stream == <n> && tls.record.content_type == 23' -T fields -e frame.time_utc -e ip.src -e tls.record.length`.
  With TLS 1.2 AES-GCM each record carries 24 bytes of overhead. How many
  plaintext bytes did the server send, and does that agree with the size of
  `upd.dll` in the host's `$MFT` (allow for HTTP response headers)?
- **Run Zeek yourself** (Docker, see README) over the capture and diff your
  `conn.log` against the one in `evidence/zeek/` for the same 45 minutes. Which
  fields differ and why?
- **Rule 4** in `rules/local.rules`: a rule on the certificate (subject equals
  issuer, and equals the SNI). Make it fire on the C2 and not on the printer
  vendor. Then explain why it would be noisy on a real network.
- **Beacons from the firewall**: the firewall log has 1-second resolution.
  Recompute the C2 interval statistics from `fw01-egress.csv` only. What
  changes, and is the conclusion still the same?
- **DNS TTL**: the C2 name was re-asked on a schedule. From the TTL in the
  answers and the times of the queries, show that the re-queries are cache
  expiry, not a second program.
- **What a sensor 10 metres away would have seen**: if the Zeek sensor had been
  placed *outside* FW01 (after NAT), which of your findings would you still be
  able to make? Which host would you no longer be able to name?

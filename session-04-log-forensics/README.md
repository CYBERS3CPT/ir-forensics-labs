# Session 4 — Log Forensics: Origin and Path of the Attack

**Exercises:** [`EXERCISES.md`](EXERCISES.md). **Deliverable:** the attack flow
(Exercise 12), due **9 December 2026, 23:59**.

Session 3 gave you the host artefacts of the finance workstation and the
network: the beacon, and 2.31 GB leaving the file server. Tonight the
logs answer the questions neither the host nor the wire could: **who logged on where, with which
credentials, in what order** — from the first click to the last log the
attacker cleared.

```bash
cd ir-forensics-labs/session-04-log-forensics
./verify.sh                       # hashes, tools, what you have
./evtx-query.py --stats           # every Windows log: hosts, Event IDs, time span
```

## What is in `evidence/`

| Path | What | Clock |
|---|---|---|
| `windows/WS-FIN-07_Sysmon.jsonl` | the finance workstation: process, network, file, registry, DNS events | the host's |
| `windows/WS-FIN-07_Security.jsonl` | logons, privileges, locks | the host's |
| `windows/WS-FIN-07_PowerShell.jsonl` | script block logging (4104) | the host's |
| `windows/FS01_Sysmon.jsonl` | the file server, Sysmon (forwarded to the SIEM) | the host's |
| `windows/FS01_Security.jsonl` | the file server's Security log, **as exported** | the host's |
| `windows/FS01_System.jsonl` | services (7045, 7036) and the rest of System | the host's |
| `windows/FS01_TerminalServices-LocalSessionManager.jsonl` | RDP sessions: logon, disconnect, reconnect | the host's |
| `windows/DC01_Security.jsonl` | the domain controller: Kerberos and NTLM | the host's |
| `linux/SRV-BKP01/` | the backup server, as collected: `var/log`, shell histories, cron, `etc`, and `_collection/` (what the collector ran and saw) | the host's |

Every timestamp is the clock of the machine that wrote it. Whether each of
those clocks was right is **your** finding, with evidence — not something this
table can tell you.

The Windows logs are JSON Lines in the shape `evtx_dump -o jsonl` produces from
an `.evtx` file (one event per line, `Event.System` + `Event.EventData` or
`Event.UserData`). That is what you get in a real case after
`evtx_dump -o jsonl Security.evtx > Security.jsonl`, and it is what `jq` and
every script here read.

`wtmp` and `btmp` are real binary files (glibc x86_64 `struct utmp`, 384 bytes a
record). Kali's `last` cannot read them any more; `wtmp-read.py` can.

## The scripts

All Python is standard library only (3.9+). Every script answers `--help`.
Nothing writes into `evidence/`; your outputs go in `work/` (git ignores it).

### `evtx-query.py` — filter the event logs

```bash
./evtx-query.py --stats
./evtx-query.py --eid 4624 --where LogonType=10
./evtx-query.py --host FS01 --eid 1 --where 'CommandLine~(?i)vssadmin|wbadmin'
./evtx-query.py --eid 4768 --count-by TargetUserName,TicketEncryptionType
./evtx-query.py --host DC01 --since '2026-03-10 11:00' --until '2026-03-10 12:00'
./evtx-query.py --eid 1 --fields Time,Host,User,ParentImage,Image,CommandLine --csv > work/procs.csv
```

`--where` takes `FIELD=VALUE` (exact, case-insensitive), `FIELD!=VALUE`,
`FIELD~REGEX` and `FIELD!~REGEX`, and can be repeated. Field names are the
Windows ones (`TargetUserName`, `LogonType`, `Image`, `ParentProcessGuid`...),
plus `Time Host Channel EventID RecordID`.

**Clocks.** `--skew HOST=+N` says "this host's clock was N seconds ahead";
the table then prints the corrected time **and** the host's own time side by
side. Without `--skew`, nothing is corrected — and the footer says so, because
leaving a clock uncorrected is also a decision.

### `jq` — when you want the raw event

The scripts are a convenience. `jq` is what you will have on any machine.
`EXERCISES.md` has a dozen one-liners; the pattern is always:

```bash
jq -c 'select(.Event.System.EventID==1102)' evidence/windows/FS01_Security.jsonl
jq -r 'select(.Event.System.EventID==4624) | .Event.EventData.LogonType' FILE | sort | uniq -c
```

### `sigma-lite.py` — what would a detection have said?

```bash
./sigma-lite.py --list
./sigma-lite.py --summary
./sigma-lite.py --rule lsass
./sigma-lite.py --rules work/my-rules/          # your own rules
```

Twelve rules in `rules/`, written in Sigma's YAML format (title, logsource,
detection, condition, level, ATT&CK tags). The script reads them with a small
standard-library YAML reader and applies them to the events, so you see every
hit — and every false positive — instead of a SIEM alert count.

Two things it does on purpose:

- **A rule with no data is BLIND, not clean.** If nothing you loaded matches the
  rule's logsource, it says so. A rule with candidate events and zero hits says
  that too. Neither means "nothing happened".
- **Known false positives are printed with the hits.** Several rules fire on
  legitimate activity in this evidence. Triage is part of the exercise.

Real Sigma rules convert to SIEM queries with `sigma-cli`/pySigma; the rules
here are valid Sigma, so they will.

### `linux-auth.py` — auth.log in one page

```bash
./linux-auth.py --year 2026 evidence/linux/SRV-BKP01/var/log/auth.log.1 evidence/linux/SRV-BKP01/var/log/auth.log
./linux-auth.py --year 2026 evidence/linux/SRV-BKP01/var/log/auth.log --sessions
./linux-auth.py --year 2026 evidence/linux/SRV-BKP01/var/log/auth.log --csv > work/auth.csv
```

Failures by account and source, successful logins by method (password or key),
SSH sessions with durations, sudo commands, and root shells.

`--year` is required because syslog lines have no year. A `sudo -i` is shown as
a **root shell**: sudo logs the shell it started, not what was typed inside it —
for that, go to the shell histories and syslog.

### `wtmp-read.py` — logins from the binary files

```bash
./wtmp-read.py evidence/linux/SRV-BKP01/var/log/wtmp            # sessions, like last
./wtmp-read.py evidence/linux/SRV-BKP01/var/log/btmp --raw      # failed logins, with byte offsets
./wtmp-read.py evidence/linux/SRV-BKP01/var/log/wtmp --csv
```

Refuses a file whose size is not a multiple of 384 bytes: a misaligned parse
prints plausible garbage. The `@offset` in `--raw` is your evidence reference.

### `supertimeline.py` — one clock for everything

```bash
./supertimeline.py --year 2026 --skew HOST=+N --skew '*=0' --out work/supertimeline.csv
./timeline-reduce.py work/supertimeline.csv --anchor '2026-03-11 02:38:30' --window 2h --out work/night.csv
```

Merges every source into one CSV sorted by **corrected** UTC, keeping the
host's own clock, the offset you applied, and an evidence reference (`file#record`
or `file:line`) on every row. It writes `<out>.provenance.txt` next to it: your
clock decisions, the counts, every filter. That file goes in your appendix.

It refuses to merge until **every host has a clock decision**: `--skew HOST=0`
(checked, correct), `--skew HOST=+N` (it was N seconds ahead), or `--skew '*=0'`
for all the remaining ones. It also cross-checks your decisions against
network connections recorded at both ends, and refuses if they contradict
each other — without telling you the answer. Measure it, then declare it.

### `timeline-reduce.py` — from dataset to finding

Same tool as in the Blue Team course: an anchor, a window, filters by user,
path, artefact type, and the filter written next to the output.

### `attack-flow.py` — the deliverable's backbone

```bash
cp hops-template.csv work/hops.csv        # one row per step of the attack
./attack-flow.py work/hops.csv --year 2026 --skew ... --md work/attack-flow.md
```

Checks that every evidence reference exists, that every time you wrote matches
the referenced event's corrected time (and tells you when you quoted a host's
own clock instead), that the ATT&CK IDs are real, and renders the Markdown
table, the hops and the tactics covered.

## Tools you might reach for in a real case

| Tool | Does | Here |
|---|---|---|
| `evtx_dump` (omerbenamram/evtx) | `.evtx` → JSON/JSONL/XML, fast | produced the format of `evidence/windows/` |
| Chainsaw, Hayabusa | Sigma rules over `.evtx`, at speed | `sigma-lite.py` is the teaching version |
| `sigma-cli` / pySigma | convert Sigma rules to SIEM queries | the rules in `rules/` convert |
| EvtxECmd (EZ Tools) | `.evtx` → CSV with maps for common events | Windows-side alternative |
| plaso / `log2timeline` + `psort` | supertimelines from whole disk images | `supertimeline.py` is the small version |
| `journalctl --file`, `utmpdump`, `last -f` | Linux journal and utmp | `wtmp-read.py` replaces the last two on Kali |

## Rules of engagement

Fictional case, fictional data: every domain is `*.example.*`, every public IP
is a documentation range. Nothing here needs to be — or should be — looked up
online. Evidence is read-only: copy, do not edit; work in `work/`.

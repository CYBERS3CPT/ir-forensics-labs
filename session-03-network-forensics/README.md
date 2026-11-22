# Session 3 — Host and Network Forensics

**Exercises:** [`EXERCISES.md`](EXERCISES.md). **Deliverable:** the findings report — WS-FIN-07 host findings plus the network findings (Exercise 15, 20 %), due **Thursday 3 December 2026, 18:00**.

Tonight starts on the first workstation and then goes to the wire.

**The host first.** Exhibit EXH-WSFIN07-01 is the KAPE triage collection the
Ceres IT team pulled from WS-FIN-07, Marta Antunes' workstation, the morning
after. Nobody has read it yet. You find the right clock before you read any
time, then what the browser downloaded, what ran, what keeps it running and
what it took — one timeline, in true UTC. The artefact map behind it (Prefetch,
Amcache, Shimcache, LNK, registry, browser history, `$MFT`/`$J`) was taught in
the Blue Team module, Sessions 7 and 8; here you use it.

**Then the network**, which answers the questions the host cannot:

- **How did it get in?** What was downloaded, from where, when — and is it the
  same file the host has?
- **Where does it talk?** Which name, which address, which protocol, how often?
- **Is it still talking?** When did it start, when did it stop, and why?
- **Did data leave?** From which host, to where, how much, between when and when?
- **What can this evidence not tell you?** Every sensor has blind spots. You
  write them down before someone else finds them.

Everything is worked from files: a triage package, a packet capture, Zeek logs
and a firewall log. Nothing in this folder talks to the network.

## The evidence

```
../session-02-communication-and-collection/evidence/WS-FIN-07_triage/
                                        exhibit EXH-WSFIN07-01: KAPE triage of WS-FIN-07 (host)
                                        read its README one level up and collection-notes.txt first
evidence/
  ws-fin-07_2026-03-10_0835-0920.pcap   full packets, WS-FIN-07 only, Tue 10 Mar 08:35–09:20 UTC
  zeek/conn.log dns.log http.log        Zeek logs, every host, Tue 10 Mar 07:00 → Wed 11 Mar 12:00 UTC
  zeek/ssl.log x509.log files.log
  fw01-egress.csv                       FW01 egress policy log, same window
  SHA256SUMS                            verify before you start:  cd evidence && sha256sum -c SHA256SUMS
```

The host exhibit stays in the Session 2 folder (Session 5 bundles it from
there) and has its own manifest: `(cd "$T" && sha256sum -c MANIFEST.sha256)`
with `T=../session-02-communication-and-collection/evidence/WS-FIN-07_triage`.
Its CSVs use the column names of Eric Zimmerman's tools exactly. It contains no
event logs (Session 4) and no memory image (none was taken).

### Where the sensors sit (read this before you conclude anything)

```
                    internet
                       │
              FW01 ────┤  egress log: every session to the internet (allow/deny, bytes, NAT)
                       │  FW01 also ROUTES between the two internal VLANs
        core switch uplink to FW01  ──SPAN──►  capture appliance + Zeek sensor
             │                    │                BPF: not (src net 10.0.0.0/8 and dst net 10.0.0.0/8) or port 53
   servers 10.20.10.0/24    workstations 10.20.30.0/24
   DC01 .10 (DNS)           WS-FIN-07 .47, WS-IT-02 .12, ...
   FS01 .20  SRV-BKP01 .30
```

- The **capture appliance** keeps a rolling 48 h of packets. When the incident
  was declared, the IT team exported the slice for host 10.20.30.47 — the only
  slice that still existed for the morning of Tuesday 10 March.
- **Zeek** runs on the same SPAN with the same filter, and its logs are kept
  longer than the packets. Logs here are sorted by `ts` for your convenience
  (a live sensor writes a connection when it *ends*, not when it starts).
- The **firewall log** is FW01's own record of egress sessions. Its timestamps
  have one-second resolution and its byte counts include packet headers.

Ask of every finding: *could this sensor have seen it?* Traffic that stays
inside one VLAN never reaches the uplink. The filter drops internal-to-internal
traffic except DNS.

### Clocks

The capture appliance, the Zeek sensor and FW01 are NTP-synchronised: their
timestamps are true UTC. Hosts are a different story: find out how far
WS-FIN-07's clock is from the truth (Exercise 1) before you quote any time it
wrote, and correct only the times that host wrote. Portugal is on WET (UTC+0) in
March, so local time equals UTC — write UTC anyway, and say which clock each
time came from.

## The scripts

All read-only, all answer `--help`, all print UTC.

| Script | What it answers |
|---|---|
| `artefacts.py` | Host side: Chrome/Edge and FILETIME conversion, PowerShell `-enc` decoding (never executed), browser history read-only, and a merged timeline of the triage package with a **clock column** and `--skew HOST=+N` correction |
| `pcap-triage.sh <pcap>` | Six questions of a capture, before the GUI: integrity, protocols, talkers, DNS, HTTP, TLS (SNI + JA3/JA4) |
| `carve.sh <pcap> [dir]` | Exports HTTP/SMB/TFTP/IMF objects, hashes them, lists ZIP members with **their** hashes (in memory, nothing extracted) |
| `zcut.py <log> [cols]` | `zeek-cut` without Zeek; `-d` for readable UTC; `--uid <uid> evidence/zeek/` pivots one connection across every log (a certificate fingerprint works too) |
| `beacon-hunt.py <conn.log>` | Ranks (src, dst, port) pairs by how regular their connection starts are: interval, jitter, size regularity, prevalence. Outputs **candidates**, never verdicts |
| `exfil.py <conn.log or fw csv>` | Upload volume: top pairs, per host, per hour, one destination in detail, and checking a claimed volume against what was observed |
| `suricata-offline.sh <pcap> [rules]` | Validates `rules/local.rules`, runs Suricata over the capture offline, summarises the alerts and what they matched |
| `rules/local.rules` | One worked rule and two for you to complete (TLS SNI, HTTP URI), plus a go-further one |

### Quick start

```bash
cd ~/ir-forensics-labs/session-03-network-forensics
export TZ=UTC        # capinfos, tshark date fields and Suricata use the local zone otherwise
(cd evidence && sha256sum -c SHA256SUMS)
T=../session-02-communication-and-collection/evidence/WS-FIN-07_triage

./artefacts.py webkit 13417605956896604                    # Edge/Chrome time -> UTC (as the host recorded it)
./artefacts.py decode-ps '<base64 after -enc>'             # decoded, never executed
./artefacts.py history "$T/tout/C/Users/m.antunes/AppData/Local/Microsoft/Edge/User Data/Default/History"
./artefacts.py timeline $T                                 # warns: no skew applied
./artefacts.py timeline $T --skew WS-FIN-07=+SECONDS --from "2026-03-10 08:30" --to "2026-03-10 12:00" --csv work/ws-fin-07-timeline.csv

./pcap-triage.sh evidence/ws-fin-07_2026-03-10_0835-0920.pcap
./pcap-triage.sh evidence/ws-fin-07_2026-03-10_0835-0920.pcap --section tls

./carve.sh evidence/ws-fin-07_2026-03-10_0835-0920.pcap

python3 zcut.py -d evidence/zeek/http.log ts uid id.orig_h host uri user_agent
python3 zcut.py --uid <uid> evidence/zeek/

python3 beacon-hunt.py evidence/zeek/conn.log
python3 beacon-hunt.py evidence/zeek/conn.log --explain <dst_ip>

python3 exfil.py evidence/zeek/conn.log
python3 exfil.py evidence/zeek/conn.log --by host
python3 exfil.py evidence/zeek/conn.log --dst <dst_ip> --claim 2.1GB
python3 exfil.py evidence/fw01-egress.csv --dst <dst_ip>

./suricata-offline.sh evidence/ws-fin-07_2026-03-10_0835-0920.pcap
```

Output the scripts write goes to `out/` (ignored by git).

### `artefacts.py` — the clock column is the point

The timeline merges Prefetch, Amcache, Shimcache, LNK, registry, `$MFT`, `$J`
and browser history into one list, and every row says **which clock wrote
it**. `--skew HOST=+N` corrects only that host's rows (host time = true time +
N). A shortcut's target times and tracker block were copied in from the
machine named in its `MachineID` (the one that held the target when the
shortcut was made: an attacker's build machine, or a file server for a
shortcut to a share), so they are labelled `lnk-maker:<MachineID>` and never
"corrected". Shimcache rows say `FILE MODIFIED (not execution)`, because that
is what they are. Databases are opened read-only and immutable
(`?mode=ro&immutable=1`): looking at a SQLite file the ordinary way can create
journal files next to it.

### Wireshark and tshark: the filters you will use tonight

| You want | Display filter |
|---|---|
| one host | `ip.addr == 10.20.30.47` |
| DNS questions / answers | `dns.flags.response == 0` / `dns.flags.response == 1 && dns.qry.name contains "example"` |
| HTTP requests | `http.request` · `http.request.method == "GET"` · `http.host contains "fatura"` |
| TLS ClientHello / SNI | `tls.handshake.type == 1` · `tls.handshake.extensions_server_name contains "telemetry"` |
| certificates (TLS 1.2) | `tls.handshake.type == 11` |
| encrypted payload records | `tls.record.content_type == 23` (look at `tls.record.length`) |
| one connection | `tcp.stream == N` (then *Follow → TCP Stream*) |
| big frames only | `frame.len > 1000` |

`tshark -r <pcap> -Y '<filter>' -T fields -e <field> -e <field>` turns any of
these into a column you can `sort | uniq -c`. Add `-t ud` to print UTC dates in
the default view, or ask for the field `frame.time_utc`. Other absolute-time
fields (e.g. `tls.handshake.random_time`) are printed in the local zone: run
with `TZ=UTC`.

## Optional: produce the Zeek logs yourself

The Zeek logs are in the repository because the Kali package is not always
installable. If you have Docker, you can run Zeek over the capture and compare
its output with what is here (the capture covers only 45 minutes of one host,
so you will get a small subset):

```bash
mkdir -p out/zeek && cp evidence/ws-fin-07_2026-03-10_0835-0920.pcap out/zeek/
cd out/zeek
docker run --rm -v "$PWD":/pcap -w /pcap zeek/zeek zeek -C -r /pcap/ws-fin-07_2026-03-10_0835-0920.pcap
ls *.log
```

`-C` tells Zeek to ignore checksums. Your uids will differ from the ones in
`evidence/zeek/` (Zeek generates them at random per run); the timestamps,
addresses and byte counts should not. This step is optional and not needed for
any exercise.

## Rules of engagement

Same as the rest of the course: nothing from this case is looked up, uploaded
or submitted to any public service (no VirusTotal, no urlscan, no passive DNS
sites). Carved objects stay non-executable in `out/`. Everything here is
fictional; the "downloaded file" is a short text placeholder.

## Tools

`tshark`/`capinfos` (Wireshark 4.x), `suricata` (7 or 8), `jq`, `sqlite3`,
`python3` ≥ 3.9 (standard library only), `file`, `sha256sum`. `./check-lab.sh` at the
repository root tells you what is missing.

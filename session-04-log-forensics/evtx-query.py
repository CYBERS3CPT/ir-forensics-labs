#!/usr/bin/env python3
"""
evtx-query.py — filter Windows event logs (evtx_dump JSONL) without drowning.

Thousands of events per host; the attack is a few dozen of them. This is the
filter: by Event ID, host, channel, time, any field, or a regex, with the
output as a readable table, CSV or the raw JSON lines.

Usage
    ./evtx-query.py --stats                                   what is in the box
    ./evtx-query.py --eid 4624 --where LogonType=10           RDP logons, all hosts
    ./evtx-query.py --host FS01 --channel sysmon --eid 1      FS01 process creations
    ./evtx-query.py --eid 1 --where 'CommandLine~(?i)vssadmin|wbadmin'
    ./evtx-query.py --eid 4768 --count-by TargetUserName,TicketEncryptionType
    ./evtx-query.py --eid 1 --fields Time,Host,User,Image,CommandLine --csv > procs.csv
    ./evtx-query.py --since '2026-03-10 11:00' --until '2026-03-10 11:45' --host DC01
    ./evtx-query.py --skew SOMEHOST=+90 ...                   correct a clock you have measured

Filters (all ANDed)
    --eid 1,3,4624         Event IDs
    --host FS01,DC01       short host names (from System.Computer)
    --channel REGEX        Sysmon | Security | System | PowerShell | TS-LSM (regex, case-insensitive)
    --where FIELD=VALUE    exact, case-insensitive. Also FIELD!=VALUE, FIELD~REGEX, FIELD!~REGEX.
                           Repeat --where for more. Fields: anything in EventData/UserData,
                           plus Time Host Channel EventID RecordID Provider UserID.
    --grep REGEX           anywhere in the event (all fields, as text)
    --since / --until      UTC. Applied to the CORRECTED time when you gave --skew for that host.

Clocks
    Every event carries the clock of the host that wrote it. If you have measured
    that a host was wrong, say so with --skew HOST=+N (+N = the host was N seconds
    AHEAD; corrected = host time - N). The table then shows both clocks. Without
    --skew nothing is corrected, and the footer reminds you that this, too, is a
    decision.

Where the files are: by default evidence/windows/ next to this script; give
files or directories as arguments to use others.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evtxlib as L  # noqa: E402

DEFAULT_FIELDS = ["Time", "Host", "Channel", "EventID", "RecordID", "Summary"]


def compile_where(items):
    out = []
    for w in items or []:
        m = re.match(r"^([A-Za-z0-9_.]+)\s*(!=|!~|=|~)(.*)$", w)
        if not m:
            sys.exit(f" fail  --where {w!r}: use FIELD=VALUE, FIELD!=VALUE, FIELD~REGEX or FIELD!~REGEX")
        f, op, v = m.groups()
        if "~" in op:
            try:
                rx = re.compile(v)
            except re.error as exc:
                sys.exit(f" fail  --where {w!r}: bad regex ({exc})")
            out.append((f, op, rx))
        else:
            out.append((f, op, v.lower()))
    return out


def matches_where(ev, conds):
    for f, op, v in conds:
        val = ev.get(f)
        sval = "" if val is None else str(val)
        if op == "=" and sval.lower() != v:
            return False
        if op == "!=" and sval.lower() == v:
            return False
        if op == "~" and not v.search(sval):
            return False
        if op == "!~" and v.search(sval):
            return False
    return True


def ev_text(ev):
    return " ".join(f"{k}={v}" for k, v in ev.items() if not k.startswith("_") and k != "Time")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="JSONL files or directories (default: evidence/windows/)")
    ap.add_argument("--eid", help="comma-separated Event IDs")
    ap.add_argument("--host", help="comma-separated short host names")
    ap.add_argument("--channel", help="regex on the channel (Sysmon, Security, System, PowerShell, TS-LSM)")
    ap.add_argument("--where", action="append", help="FIELD=VALUE | FIELD!=VALUE | FIELD~REGEX | FIELD!~REGEX (repeatable)")
    ap.add_argument("--grep", help="regex anywhere in the event")
    ap.add_argument("--since", help="UTC lower bound")
    ap.add_argument("--until", help="UTC upper bound")
    ap.add_argument("--skew", action="append", help="HOST=+SECONDS: correct a host clock you measured (repeatable)")
    ap.add_argument("--fields", help="columns to print, comma-separated (default: Time,Host,Channel,EventID,RecordID,Summary)")
    ap.add_argument("--csv", action="store_true", help="CSV instead of a table")
    ap.add_argument("--json", action="store_true", help="the matching events as flattened JSON lines")
    ap.add_argument("--count-by", help="count matches by these fields instead of listing them")
    ap.add_argument("--stats", action="store_true", help="per host/channel/EID counts and time span")
    ap.add_argument("--limit", type=int, default=0, help="stop after N matches (0 = all)")
    ap.add_argument("--width", type=int, default=160, help="truncate the Summary column (table only)")
    a = ap.parse_args()

    skew = L.parse_skew(a.skew)
    eids = {int(x) for x in a.eid.split(",")} if a.eid else None
    hosts = {x.strip().upper() for x in a.host.split(",")} if a.host else None
    chan = re.compile(a.channel, re.I) if a.channel else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    where = compile_where(a.where)
    since = L.parse_user_time(a.since) if a.since else None
    until = L.parse_user_time(a.until) if a.until else None

    hits = []
    seen_hosts = set()
    for ev in L.load(a.paths):
        if eids and ev["EventID"] not in eids:
            continue
        if hosts and ev["Host"] not in hosts:
            continue
        if chan and not (chan.search(ev["Channel"]) or chan.search(ev["ChannelFull"])):
            continue
        tt, off = L.true_time(ev, skew)
        if since and tt < since:
            continue
        if until and tt > until:
            continue
        if where and not matches_where(ev, where):
            continue
        if grep and not grep.search(ev_text(ev)):
            continue
        ev["UTC"] = tt
        ev["Offset"] = off
        hits.append(ev)
        seen_hosts.add(ev["Host"])

    hits.sort(key=lambda e: (e["UTC"], e["Host"], e["RecordID"] or 0))
    if a.limit:
        hits = hits[: a.limit]

    if a.stats:
        span = defaultdict(lambda: [None, None, Counter()])
        for e in hits:
            k = (e["Host"], e["Channel"], e["_file"])
            s = span[k]
            s[0] = e["UTC"] if s[0] is None or e["UTC"] < s[0] else s[0]
            s[1] = e["UTC"] if s[1] is None or e["UTC"] > s[1] else s[1]
            s[2][e["EventID"]] += 1
        for (h, c, f), (lo, hi, cnt) in sorted(span.items()):
            print(f"\n  {f}   {sum(cnt.values()):,} events   {L.fmt(lo, False)} .. {L.fmt(hi, False)}")
            print("    " + "  ".join(f"{eid}:{n}" for eid, n in sorted(cnt.items())))
        footer(hits, skew, seen_hosts)
        return

    if a.count_by:
        keys = [k.strip() for k in a.count_by.split(",")]
        cnt = Counter(tuple(str(e.get(k, "")) for k in keys) for e in hits)
        w = csv.writer(sys.stdout) if a.csv else None
        if w:
            w.writerow(["count"] + keys)
        for vals, n in cnt.most_common():
            if w:
                w.writerow([n, *vals])
            else:
                print(f"  {n:>7,}  " + "  ".join(vals))
        if not w:
            print(f"\n  {len(hits):,} matching events, {len(cnt):,} distinct values", file=sys.stderr)
        return

    if a.json:
        for e in hits:
            out = {k: (L.fmt(v) if hasattr(v, "strftime") else v) for k, v in e.items()}
            print(json.dumps(out, ensure_ascii=False))
        footer(hits, skew, seen_hosts)
        return

    fields = [f.strip() for f in a.fields.split(",")] if a.fields else list(DEFAULT_FIELDS)
    corrected = any(e["Offset"] for e in hits)
    if corrected and "Time" in fields and "HostClock" not in fields:
        fields.insert(fields.index("Time") + 1, "HostClock")

    def val(e, f):
        if f == "Time":
            return L.fmt(e["UTC"])
        if f == "HostClock":
            return L.fmt(e["Time"]) if e["Offset"] else ""
        if f == "Summary":
            return L.describe(e)
        v = e.get(f, "")
        return "" if v is None else (L.fmt(v) if hasattr(v, "strftime") else str(v))

    if a.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["UTC" if f == "Time" else f for f in fields])
        for e in hits:
            w.writerow([val(e, f) for f in fields])
    else:
        rows = [[val(e, f) for f in fields] for e in hits]
        head = ["UTC" if f == "Time" and corrected else f for f in fields]
        widths = [max([len(h)] + [len(r[i]) for r in rows]) if f != "Summary" else 0 for i, (h, f) in enumerate(zip(head, fields))]
        print("  " + "  ".join(h.ljust(widths[i]) if fields[i] != "Summary" else h for i, h in enumerate(head)))
        for r in rows:
            cells = []
            for i, c in enumerate(r):
                if fields[i] == "Summary" or i == len(r) - 1:
                    cells.append(c[: a.width])
                else:
                    cells.append(c.ljust(widths[i]))
            print("  " + "  ".join(cells))
    footer(hits, skew, seen_hosts, quiet=a.csv)


def footer(hits, skew, hosts, quiet=False):
    sys.stdout.flush()
    p = lambda *x: print(*x, file=sys.stderr)  # noqa: E731
    p(f"\n  {len(hits):,} event(s) from {len(hosts)} host(s): {', '.join(sorted(hosts)) or '-'}")
    corrected = sorted(h for h in hosts if L.offset_for(h, skew) not in (None, 0))
    declared0 = sorted(h for h in hosts if L.offset_for(h, skew) == 0)
    none = sorted(h for h in hosts if L.offset_for(h, skew) is None)
    if corrected:
        p("  corrected: " + ", ".join(f"{h} {L.offset_for(h, skew):+g}s" for h in corrected)
          + "   (UTC column = host clock minus the offset)")
    if declared0:
        p("  declared correct (0 s): " + ", ".join(declared0))
    if none and not quiet:
        p("  host clocks, uncorrected: " + ", ".join(none)
          + " — fine if you checked them; if you have not, that is a decision too. Write it down.")


if __name__ == "__main__":
    main()

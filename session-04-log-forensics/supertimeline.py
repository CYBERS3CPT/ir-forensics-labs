#!/usr/bin/env python3
"""
supertimeline.py — every source, every host, one clock, one CSV.

Merges the Windows event logs (evtx_dump JSONL), the Linux text logs
(auth.log*, syslog*), the binary wtmp/btmp, the restic logs and the collector's
`stat` output into one CSV sorted by corrected UTC time, with the host's own
clock and the correction kept next to it — so anyone can check your arithmetic.

Usage
    ./supertimeline.py --year 2026 --skew FS01=0 --skew DC01=0 ...      one decision per host
    ./supertimeline.py --year 2026 --skew SOMEHOST=+90 --skew '*=0'     one measured, the rest declared correct
    ./supertimeline.py ... --since '2026-03-10 08:00' --until '2026-03-11 04:00' --out work/tl.csv
    ./supertimeline.py ... --drop 'pvtelemetry|esagent'                 remove known-good noise (recorded)

Output columns
    utc         corrected time (host clock minus the declared offset)
    host_clock  the time exactly as the host wrote it
    offset_s    the correction you declared for that host
    host, source (Sysmon, Security, auth.log, wtmp ...), event (EID 4624, sshd ...),
    user, summary (one line, human readable), ref (file#record or file:line — your evidence ID)

It refuses, and says why, when
    - a host has no clock decision. A host five minutes fast writes perfectly
      well-formed, perfectly wrong timestamps; nothing in the log tells you.
      For each host: --skew HOST=0 (checked, correct) or --skew HOST=+N (it was N
      seconds AHEAD). '--skew *=0' declares every remaining host correct, and
      lists them so the decision is visible.
    - you declared a host correct and the evidence says otherwise: a network
      connection recorded at BOTH ends (same addresses and ports) with times
      that disagree by more than 2 s. It will not tell you by how much: measure
      it (evtx-query.py on both ends), then declare it.
    - --year is missing: syslog lines carry no year.

Next to the CSV it writes <out>.provenance.txt: the command, every clock
decision, the counts per source and every --drop/--keep. It goes in your
report appendix.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import re
import shlex
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evtxlib as L  # noqa: E402

UTC = timezone.utc
SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
                    r"(?P<prog>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
USERS_RX = re.compile(r"(?:for (?:invalid user )?|user |by |USER=|\(|^\s*)([a-z_][a-z0-9_.-]*)(?:\(uid=|\)| from| :|$)")


def load_wtmp_reader():
    spec = importlib.util.spec_from_file_location("wtmp_read", HERE / "wtmp-read.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def linux_rows(root: Path, year: int):
    """Yield (host_time, host, source, event, user, summary, ref) from evidence/linux/<HOST>/."""
    wt = load_wtmp_reader()
    for hdir in sorted(p for p in root.iterdir() if p.is_dir()):
        host = hdir.name.upper()
        logdir = hdir / "var" / "log"
        for f in sorted(logdir.glob("auth.log*")) + sorted(logdir.glob("syslog*")):
            if f.suffix == ".gz":
                print(f" warn  {f}: compressed, skipped (zcat it into work/ and point --linux there)", file=sys.stderr)
                continue
            src = "auth.log" if f.name.startswith("auth") else "syslog"
            with open(f, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    m = SYSLOG.match(line.rstrip("\n"))
                    if not m:
                        continue
                    hh, mm, ss = map(int, m["time"].split(":"))
                    dt = datetime(year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=UTC)
                    msg = m["msg"].strip()
                    um = re.search(r"(?:for (?:invalid user )?|user |^)([a-z_][a-z0-9_.-]*)(?:\(uid=\d+\))?(?: from| :|$|\s+by)", msg)
                    user = um.group(1) if um else ""
                    if m["prog"] == "sudo":
                        su = re.match(r"^\s*(\S+) :", msg)
                        user = su.group(1) if su else user
                    yield (dt, host, src, m["prog"], user, msg, f"linux/{hdir.name}/var/log/{f.name}:{n}")
        for name in ("wtmp", "btmp"):
            f = logdir / name
            if not f.exists():
                continue
            for r in wt.records(f):
                kind = {"USER": "login", "DEAD": "logout", "LOGIN": "failed login" if name == "btmp" else "getty",
                        "BOOT": "boot"}.get(r["type"], r["type"].lower())
                summ = f"{kind} {r['user']} on {r['line']}" + (f" from {r['host']}" if r["host"] else "")
                yield (r["time"], host, name, r["type"], r["user"], summ, f"linux/{hdir.name}/var/log/{name}@{r['offset']}")
        for f in sorted((logdir / "restic").glob("*.log")) if (logdir / "restic").exists() else []:
            with open(f, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    mm = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z (.*)$", line.strip())
                    if mm:
                        dt = datetime.strptime(mm.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
                        yield (dt, host, "restic", f.stem, "", mm.group(2), f"linux/{hdir.name}/var/log/restic/{f.name}:{n}")
        st = hdir / "_collection" / "stat.txt"
        if st.exists():
            cur = None
            with open(st, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if line.strip().startswith("File:"):
                        cur = line.split("File:", 1)[1].strip()
                    mm = re.match(r"^Modify: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d+) \+0000", line.strip())
                    if mm and cur:
                        dt = datetime.strptime(mm.group(1), "%Y-%m-%d %H:%M:%S").replace(
                            tzinfo=UTC, microsecond=int(mm.group(2)[:6].ljust(6, "0")))
                        yield (dt, host, "stat", "mtime", "", f"last modified: {cur}", f"linux/{hdir.name}/_collection/stat.txt:{n}")


def cross_check(events, skew):
    """Connections seen at both ends (Sysmon 3, same 4-tuple): per-host disagreement in seconds."""
    out_, in_ = {}, {}
    for e in events:
        if e["Channel"] != "Sysmon" or e["EventID"] != 3:
            continue
        k = (str(e.get("SourceIp")), str(e.get("SourcePort")), str(e.get("DestinationIp")), str(e.get("DestinationPort")))
        (out_ if str(e.get("Initiated")).lower() == "true" else in_)[k] = e
    diffs = defaultdict(list)
    for k, a in out_.items():
        b = in_.get(k)
        if not b or a["Host"] == b["Host"]:
            continue
        ta, _ = L.true_time(a, skew)
        tb, _ = L.true_time(b, skew)
        d = (ta - tb).total_seconds()
        diffs[(a["Host"], b["Host"])].append(d)
    return {k: statistics.median(v) for k, v in diffs.items()}, {k: len(v) for k, v in diffs.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", default=str(HERE / "evidence"), help="evidence root (windows/ and linux/<HOST>/ under it)")
    ap.add_argument("--skew", action="append", help="HOST=+SECONDS clock decision, repeatable; '*=0' for the rest")
    ap.add_argument("--year", type=int, help="year for syslog-format lines (required when Linux logs are present)")
    ap.add_argument("--since", help="UTC (corrected) lower bound")
    ap.add_argument("--until", help="UTC (corrected) upper bound")
    ap.add_argument("--hosts", help="only these hosts (comma-separated)")
    ap.add_argument("--drop", action="append", help="regex: drop rows whose summary/source/event matches (repeatable, recorded)")
    ap.add_argument("--keep", help="regex: keep only rows matching (recorded)")
    ap.add_argument("--out", default="work/supertimeline.csv", help="output CSV (default work/supertimeline.csv)")
    ap.add_argument("--force-clock", action="store_true",
                    help="write the timeline even if your clock decisions contradict the evidence (recorded as such)")
    a = ap.parse_args()

    ev_root = Path(a.evidence)
    win, lin = ev_root / "windows", ev_root / "linux"
    skew = L.parse_skew(a.skew)
    want = {h.strip().upper() for h in a.hosts.split(",")} if a.hosts else None

    events = list(L.load([str(win)])) if win.exists() else []
    lin_rows = []
    if lin.exists() and any(lin.iterdir()):
        if not a.year:
            sys.exit(" fail  --year is required: the Linux logs are syslog format, which has no year.\n"
                     "       Check the collection notes and file dates, then pass it (e.g. --year 2026).")
        lin_rows = list(linux_rows(lin, a.year))

    hosts = sorted({e["Host"] for e in events} | {r[1] for r in lin_rows})
    if want:
        hosts = [h for h in hosts if h in want]
    missing = [h for h in hosts if L.offset_for(h, skew) is None]
    if missing:
        sys.exit(" fail  no clock decision for: " + ", ".join(missing) + "\n"
                 "       A supertimeline puts every host on one clock. That only works once you have\n"
                 "       decided, for each host, whether its clock was right — and by how much it was\n"
                 "       not. Nothing in a log tells you: a host five minutes fast writes perfectly\n"
                 "       well-formed, perfectly wrong timestamps, and merged with the others it\n"
                 "       re-orders cause and effect.\n"
                 "       For each host, one of:\n"
                 "         --skew HOST=0     you checked it (NTP status, collection notes, an event that\n"
                 "                           two hosts both recorded) and it was right\n"
                 "         --skew HOST=+N    it was N seconds AHEAD (corrected = host time - N)\n"
                 "       or --skew '*=0' to declare every remaining host correct (they will be listed).\n"
                 "       Write down the evidence behind each decision: it belongs in your report.")
    via_wild = [h for h in hosts if h not in skew and "*" in skew]

    # does the evidence contradict a declared clock?
    med, cnt = cross_check(events, skew)
    bad = [(a_, b_) for (a_, b_), d in med.items() if abs(d) > 2 and a_ in hosts and b_ in hosts]
    if bad and not a.force_clock:
        lines = [f"         {x} vs {y}: {cnt[(x, y)]} connection(s) recorded at both ends disagree by more than 2 s"
                 for x, y in bad]
        sys.exit(" fail  your clock decisions contradict the evidence:\n" + "\n".join(lines) + "\n"
                 "       The same TCP connection (same addresses AND source port) cannot start at two\n"
                 "       different times. One of these clocks is off. Find the pairs (Sysmon EID 3 on the\n"
                 "       initiating host, the inbound EID 3 on the other), measure the difference,\n"
                 "       decide which host to trust and why, and declare it with --skew.\n"
                 "       (--force-clock writes the timeline anyway and records that you overrode this.)")

    since = L.parse_user_time(a.since) if a.since else None
    until = L.parse_user_time(a.until) if a.until else None
    drops = [re.compile(d, re.I) for d in (a.drop or [])]
    keep = re.compile(a.keep, re.I) if a.keep else None

    rows, per_src, dropped = [], Counter(), Counter()
    for e in events:
        if e["Host"] not in hosts:
            continue
        tt, off = L.true_time(e, skew)
        rows.append([tt, e["Time"], off or 0, e["Host"], e["Channel"], f"EID {e['EventID']}", L.user_of(e),
                     L.describe(e), f"{e['_file']}#{e['RecordID']}"])
    for dt, host, src, event, user, summ, ref in lin_rows:
        if host not in hosts:
            continue
        off = L.offset_for(host, skew) or 0
        rows.append([dt - timedelta(seconds=off), dt, off, host, src, event, user, summ, ref])

    out_rows = []
    for r in rows:
        if since and r[0] < since or until and r[0] > until:
            continue
        txt = f"{r[4]} {r[5]} {r[6]} {r[7]}"
        hit = next((d.pattern for d in drops if d.search(txt)), None)
        if hit:
            dropped[hit] += 1
            continue
        if keep and not keep.search(txt):
            dropped["(not matching --keep)"] += 1
            continue
        out_rows.append(r)
        per_src[(r[3], r[4])] += 1
    out_rows.sort(key=lambda r: (r[0], r[3]))

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["utc", "host_clock", "offset_s", "host", "source", "event", "user", "summary", "ref"])
        for r in out_rows:
            w.writerow([r[0].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", r[1].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                        f"{r[2]:+g}", *r[3:]])

    prov = out.with_suffix(".provenance.txt")
    with prov.open("w", encoding="utf-8") as fh:
        fh.write("Supertimeline provenance\n")
        fh.write(f"  produced   {datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ}\n")
        fh.write(f"  command    {shlex.join(sys.argv)}\n")
        fh.write(f"  evidence   {ev_root}\n  year       {a.year or '-'} (syslog-format lines)\n\n  Clock decisions\n")
        for h in hosts:
            o = L.offset_for(h, skew)
            how = "declared via '*'" if h in via_wild else "declared explicitly"
            fh.write(f"    {h:<12} {o:+g} s   {how}\n")
        if bad:
            fh.write("\n  !! --force-clock used: these pairs still disagree by more than 2 s:\n")
            for x, y in bad:
                fh.write(f"     {x} vs {y} ({cnt[(x, y)]} connection(s))\n")
        fh.write("\n  Rows per host/source\n")
        for (h, s), n in sorted(per_src.items()):
            fh.write(f"    {h:<12} {s:<12} {n:>7}\n")
        fh.write(f"\n  Window     {a.since or '(start)'} .. {a.until or '(end)'} (corrected UTC)\n")
        fh.write("  Dropped\n" + ("".join(f"    {n:>7}  {p}\n" for p, n in dropped.most_common()) or "    nothing\n"))
        fh.write(f"\n  Rows out   {len(out_rows)}\n\n"
                 "This file goes in the report appendix with the timeline. A merged timeline\n"
                 "whose clock decisions are not written down cannot be checked by anyone.\n")

    print(f"\n  {len(out_rows):,} rows -> {out}")
    print(f"  provenance -> {prov}")
    print("  clocks: " + ", ".join(f"{h} {L.offset_for(h, skew):+g}s" for h in hosts))
    if via_wild:
        print("  declared correct via '*': " + ", ".join(via_wild) + "  — make sure each one was checked")
    agree = [(x, y) for (x, y) in med if (x, y) not in bad]
    if agree:
        print("  cross-check: " + "; ".join(f"{x} vs {y} agree within 2 s on {cnt[(x, y)]} shared connection(s)" for x, y in agree))
    if dropped:
        print("  dropped: " + ", ".join(f"{n} by {p!r}" for p, n in dropped.most_common()))
    print()


if __name__ == "__main__":
    main()

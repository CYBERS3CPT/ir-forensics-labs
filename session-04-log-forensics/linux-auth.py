#!/usr/bin/env python3
"""
linux-auth.py — read auth.log the way an investigator does.

Who failed, from where, as whom; who got in, how (password or key), for how
long; and what they ran with sudo. One page, instead of 700 lines.

Usage
    ./linux-auth.py --year 2026 evidence/linux/SRV-BKP01/var/log/auth.log*
    ./linux-auth.py --year 2026 auth.log --since '2026-03-11 00:00'
    ./linux-auth.py --year 2026 auth.log --sessions            just the session table
    ./linux-auth.py --year 2026 auth.log --csv > auth.csv      every parsed event, for a timeline

Why --year is mandatory
    Classic syslog lines ("Mar 11 02:10:05 host sshd[2212]: ...") carry no year
    and no time zone. The year comes from you (and from the file dates); the time
    zone from the host (/etc/timezone, timedatectl). This script assumes the
    timestamps are UTC and says so; if the host was not on UTC, convert first.

What it cannot see
    - Commands typed inside a root shell (sudo -i, sudo -s, sudo su). sudo logs
      the shell it started (COMMAND=/bin/bash), not what was typed in it. Look
      for the sudo-i session lines and go to the shell history and syslog.
    - Anything that never authenticated: a scanner that drops the connection
      before the password prompt leaves "[preauth]" lines and nothing else.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

LINE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
                  r"(?P<prog>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
P = {
    "accepted": re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    "failed": re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
    "invalid": re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)"),
    "closed_pre": re.compile(r"^Connection closed by (?:(?:authenticating|invalid) user (?P<user>\S+) )?(?P<ip>[0-9a-f.:]+) port (?P<port>\d+)"),
    "disconnected": re.compile(r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"),
    "sess_open": re.compile(r"^pam_unix\((?P<svc>[a-z-]+):session\): session opened for user (?P<user>[^(\s]+)(?:\(uid=\d+\))? by (?P<by>[^(\s]*)"),
    "sess_close": re.compile(r"^pam_unix\((?P<svc>[a-z-]+):session\): session closed for user (?P<user>\S+)"),
    "sudo": re.compile(r"^\s*(?P<user>\S+) : (?:(?P<err>.*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<runas>\S+) ; COMMAND=(?P<cmd>.*)$"),
    "nego": re.compile(r"^Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+)"),
}
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse(files, year):
    out = []
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                m = LINE.match(line.rstrip("\n"))
                if not m:
                    continue
                h, mi, s = map(int, m["time"].split(":"))
                dt = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s, tzinfo=timezone.utc)
                out.append({"time": dt, "host": m["host"], "prog": m["prog"], "pid": m["pid"] or "",
                            "msg": m["msg"], "ref": f"{Path(f).name}:{n}"})
    out.sort(key=lambda e: e["time"])
    return out


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="auth.log, auth.log.1 ... (plain text; gunzip .gz first)")
    ap.add_argument("--year", type=int, help="year of the log lines (syslog does not record it) — required")
    ap.add_argument("--since", help="UTC, e.g. '2026-03-11 00:00'")
    ap.add_argument("--until", help="UTC")
    ap.add_argument("--sessions", action="store_true", help="only the session table")
    ap.add_argument("--csv", action="store_true", help="every parsed event as CSV (time,host,prog,pid,event,user,src,detail,ref)")
    a = ap.parse_args()
    if not a.year:
        sys.exit(" fail  --year is required: syslog lines have no year, and guessing it is how a timeline\n"
                 "       ends up a year out. Check the file dates and the collection notes, then pass it.")
    for f in a.files:
        if f.endswith(".gz"):
            sys.exit(f" fail  {f} is compressed: zcat it into a work file first (do not gunzip the evidence in place)")

    def bound(s):
        if not s:
            return None
        raw = s.strip().rstrip("Z").replace("T", " ")
        for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw, f).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        sys.exit(f" fail  could not read the time {s!r} — try '2026-03-11 02:00'")
    lo, hi = bound(a.since), bound(a.until)
    ev = [e for e in parse(a.files, a.year) if (not lo or e["time"] >= lo) and (not hi or e["time"] <= hi)]
    if not ev:
        sys.exit(" fail  no syslog-format lines in that range")

    fails = defaultdict(lambda: [0, None, None])
    invalid = defaultdict(int)
    ok = defaultdict(lambda: [0, None, None])
    sudo, rows = [], []
    sessions, open_by_pid, open_by_port = [], {}, {}
    rootshell = []
    for e in ev:
        msg, prog = e["msg"], e["prog"]
        row = None
        if prog == "sshd":
            if (m := P["accepted"].match(msg)):
                k = (m["user"], m["ip"], m["method"])
                c = ok[k]
                c[0] += 1
                c[1] = c[1] or e["time"]
                c[2] = e["time"]
                s = {"user": m["user"], "ip": m["ip"], "port": m["port"], "method": m["method"],
                     "start": e["time"], "end": None, "pid": e["pid"], "ref": e["ref"]}
                sessions.append(s)
                open_by_pid[e["pid"]] = s
                open_by_port[(m["ip"], m["port"])] = s
                row = ("login-ok", m["user"], m["ip"], f"{m['method']} port {m['port']}")
            elif (m := P["failed"].match(msg)):
                k = (m["user"] + (" (invalid)" if m["invalid"] else ""), m["ip"])
                c = fails[k]
                c[0] += 1
                c[1] = c[1] or e["time"]
                c[2] = e["time"]
                row = ("login-fail", m["user"], m["ip"], f"{m['method']}{' invalid user' if m['invalid'] else ''} port {m['port']}")
            elif (m := P["invalid"].match(msg)):
                invalid[(m["user"], m["ip"])] += 1
                row = ("invalid-user", m["user"], m["ip"], f"port {m['port']}")
            elif (m := P["disconnected"].match(msg)):
                s = open_by_port.pop((m["ip"], m["port"]), None)
                if s and not s["end"]:
                    s["end"] = e["time"]
                row = ("disconnect", m["user"], m["ip"], f"port {m['port']}")
            elif (m := P["sess_close"].match(msg)) and m["svc"] == "sshd":
                s = open_by_pid.pop(e["pid"], None)
                if s and not s["end"]:
                    s["end"] = e["time"]
                row = ("session-close", m["user"], "", "sshd")
            elif (m := P["closed_pre"].match(msg)) and "[preauth]" in msg or (m := P["nego"].match(msg)):
                row = ("preauth-close", (m.groupdict().get("user") or ""), m["ip"], msg[:80])
        elif prog == "sudo":
            if (m := P["sudo"].match(msg)):
                sudo.append((e["time"], m["user"], m["tty"], m["runas"], m["cmd"], m["err"] or "", e["ref"]))
                row = ("sudo", m["user"], "", f"{m['runas']}: {m['cmd']}" + (f" [{m['err']}]" if m["err"] else ""))
            elif (m := P["sess_open"].match(msg)) and m["svc"] == "sudo-i":
                rootshell.append([e["time"], None, m["by"], e["ref"]])
                row = ("root-shell-open", m["by"], "", "sudo -i")
            elif (m := P["sess_close"].match(msg)) and m["svc"] == "sudo-i":
                for r in reversed(rootshell):
                    if r[1] is None:
                        r[1] = e["time"]
                        break
                row = ("root-shell-close", m["user"], "", "sudo -i")
        elif (m := P["sess_open"].match(msg)) and m["svc"] in ("login", "cron"):
            row = (f"{m['svc']}-session", m["user"], "", "")
        if row:
            rows.append((e, row))

    if a.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["utc", "host", "prog", "pid", "event", "user", "src", "detail", "ref"])
        for e, (kind, user, src, detail) in rows:
            w.writerow([e["time"].isoformat().replace("+00:00", "Z"), e["host"], e["prog"], e["pid"], kind, user, src, detail, e["ref"]])
        return

    hosts = sorted({e["host"] for e in ev})
    print(f"\n  {len(ev):,} lines from {', '.join(hosts)}, {ts(ev[0]['time'])} .. {ts(ev[-1]['time'])} (assumed UTC, year {a.year})")

    def sess_table():
        print("\n  SSH sessions (Accepted ... -> Disconnected / session closed)")
        print(f"    {'start':<19}  {'end':<19}  {'dur':>8}  {'user':<10} {'from':<15} {'method':<9} ref")
        for s in sessions:
            dur = str(s["end"] - s["start"]) if s["end"] else "open?"
            flag = "   <- password" if s["method"] == "password" else ""
            print(f"    {ts(s['start'])}  {ts(s['end']) if s['end'] else '-':<19}  {dur:>8}  {s['user']:<10} {s['ip']:<15} {s['method']:<9} {s['ref']}{flag}")

    if a.sessions:
        sess_table()
        return

    print("\n  Failed passwords, by account and source")
    if not fails:
        print("    none")
    for (u, ip), (n, f1, f2) in sorted(fails.items(), key=lambda x: x[1][1]):
        print(f"    {n:>4} x  {u:<22} from {ip:<15} {ts(f1)} .. {ts(f2)}")
    if invalid:
        print("\n  Attempts for accounts that do not exist here")
        for (u, ip), n in invalid.items():
            print(f"    {n:>4} x  {u or '(empty)':<22} from {ip}")
    print("\n  Successful logins, by account, source and method")
    for (u, ip, meth), (n, f1, f2) in sorted(ok.items(), key=lambda x: x[1][1]):
        print(f"    {n:>4} x  {u:<12} from {ip:<15} {meth:<10} first {ts(f1)}  last {ts(f2)}")
    sess_table()
    print("\n  sudo")
    for t, u, tty, runas, cmd, err, ref in sudo:
        print(f"    {ts(t)}  {u:<10} {tty:<7} as {runas:<5} {cmd}" + (f"   [{err}]" if err else ""))
    if rootshell:
        print("\n  Root shells (sudo -i): what was typed inside is NOT in this log")
        for t1, t2, by, ref in rootshell:
            print(f"    {ts(t1)} .. {ts(t2) if t2 else '?'}  opened by {by}   ({ref})"
                  "  -> read the target's shell history and syslog for this window")
    print()


if __name__ == "__main__":
    main()

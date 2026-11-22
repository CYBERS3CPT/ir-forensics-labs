#!/usr/bin/env python3
"""exfil.py - where did the bytes go? Upload volume from a Zeek conn.log or a
firewall egress CSV.

Exfiltration is the one thing an attacker cannot make small: the data has to
cross the wire. Encryption hides WHAT left, never HOW MUCH, WHEN, FROM WHERE
and TO WHERE. This script ranks those four.

    python3 exfil.py evidence/zeek/conn.log                     top uploaders, flags
    python3 exfil.py evidence/zeek/conn.log --by host           per internal host, out vs in
    python3 exfil.py evidence/zeek/conn.log --hourly            bytes out per host per hour
    python3 exfil.py evidence/zeek/conn.log --dst 192.0.2.77    every connection to one destination
    python3 exfil.py evidence/zeek/conn.log --dst 192.0.2.77 --claim 2.1GB
    python3 exfil.py evidence/fw01-egress.csv --by host         the same questions, firewall's numbers

Units, because they will be argued about:
  - Zeek orig_bytes = TCP payload sent by the originator (no IP/TCP headers).
  - The firewall counts whole packets (headers included), so its numbers are
    a few percent larger for the same session. Neither is wrong.
  - 1 GB = 10^9 bytes; 1 GiB = 2^30 bytes = 1.074 GB. People (and ransom notes)
    mix them up. This script prints both.

Flags (observations, not verdicts):
  LONG-UPLOAD  one connection lasting >= 10 min that sent >= 20 MB
  OUTLIER      one connection that sent >= 5 MB on a channel whose typical
               (median) connection sends 100x less: a quiet channel that
               suddenly carried something
  ASYMMETRIC   a source->destination pair that sent >= 10x what it received
               and at least 10 MB in total
Standard library only. Read-only.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

INTERNAL = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def is_internal(ip: str) -> bool:
    # not ipaddress.is_private: that also matches the documentation ranges
    # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) that play "the internet" here
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in INTERNAL)


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def human(n: float) -> str:
    return f"{n / 1e9:,.3f} GB / {n / 2**30:,.3f} GiB" if n >= 1e8 else f"{n / 1e6:,.1f} MB"


def short(n: float) -> str:
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= div:
            return f"{n / div:.2f} {unit}"
    return f"{int(n)} B"


def load(path: str):
    """Normalise both sources to: ts, end, src, dst, dport, out, in, dur, state, host."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.startswith("#separator"):
            fields = None
            for line in fh:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                if not line or line.startswith("#"):
                    continue
                r = dict(zip(fields, line.split("\t")))
                f = lambda k: float(r[k]) if r.get(k, "-") not in ("-", "") else 0.0  # noqa: E731
                ts = float(r["ts"])
                rows.append(dict(ts=ts, end=ts + f("duration"), src=r["id.orig_h"], dst=r["id.resp_h"],
                                 dport=r["id.resp_p"], out=f("orig_bytes"), inb=f("resp_bytes"), dur=f("duration"),
                                 state=r.get("conn_state", "-"), host="-", uid=r["uid"]))
            src = "zeek conn.log (orig_bytes = payload)"
        else:
            rd = csv.DictReader(fh)
            need = {"start_utc", "end_utc", "src_ip", "dst_ip", "dst_port", "bytes_out", "bytes_in"}
            if not need <= set(rd.fieldnames or []):
                sys.exit(f"{path}: neither a Zeek TSV log nor a CSV with columns {sorted(need)}")
            p = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()  # noqa: E731
            for r in rd:
                if r.get("action", "allow") != "allow":
                    continue
                ts, end = p(r["start_utc"]), p(r["end_utc"])
                rows.append(dict(ts=ts, end=end, src=r["src_ip"], dst=r["dst_ip"], dport=r["dst_port"],
                                 out=float(r["bytes_out"]), inb=float(r["bytes_in"]), dur=end - ts, state="-",
                                 host=r.get("app_host", "-"), uid="-"))
            src = "firewall CSV (bytes include headers; 1 s resolution; allowed sessions only)"
    rows = [r for r in rows if is_internal(r["src"]) and not is_internal(r["dst"])]
    if not rows:
        sys.exit("no internal -> external sessions found")
    return rows, src


def parse_claim(s: str) -> float:
    m = re.fullmatch(r"\s*([\d.]+)\s*([kKmMgGtT]i?[bB])\s*", s)
    if not m:
        sys.exit("--claim: use a number and a unit, e.g. 2.1GB or 2.1GiB")
    v, u = float(m.group(1)), m.group(2).upper()
    base = 1024 if "I" in u else 1000
    return v * base ** "KMGT".index(u[0]) * base


def flags(rows):
    out = []
    med = defaultdict(list)
    for r in rows:
        med[(r["src"], r["dst"], r["dport"])].append(r["out"])
    med = {k: sorted(v)[len(v) // 2] for k, v in med.items()}
    for r in rows:
        if r["dur"] >= 600 and r["out"] >= 20e6:
            out.append(("LONG-UPLOAD", r))
        elif r["out"] >= 5e6 and r["out"] >= 100 * max(med[(r["src"], r["dst"], r["dport"])], 1):
            out.append(("OUTLIER", r))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 epilog="head -30 exfil.py explains the units and the flags.")
    ap.add_argument("log", help="Zeek conn.log or FW01 egress CSV")
    ap.add_argument("--by", choices=["pair", "host"], default="pair", help="aggregate per src->dst:port (default) or per host")
    ap.add_argument("--hourly", action="store_true", help="bytes out per source host per hour (UTC)")
    ap.add_argument("--host", help="with --hourly: only this source")
    ap.add_argument("--dst", help="detail every session to this destination IP")
    ap.add_argument("--claim", help="with --dst: compare an exfiltration claim (e.g. 2.1GB) with what was observed")
    ap.add_argument("--top", type=int, default=12)
    a = ap.parse_args()
    if a.claim and not a.dst:
        sys.exit("exfil.py: refusing --claim without --dst.\n  A claim is checked against the sessions you attribute "
                 "to the exfiltration, not against everything that left the building - otherwise every Teams call "
                 "'confirms' the ransom note.")
    rows, srcdesc = load(a.log)
    t0, t1 = min(r["ts"] for r in rows), max(r["end"] for r in rows)
    print(f"exfil  {a.log}\n  source: {srcdesc}\n  window: {utc(t0)} -> {utc(t1)} UTC, {len(rows)} outbound sessions, "
          f"{short(sum(r['out'] for r in rows))} out / {short(sum(r['inb'] for r in rows))} in\n")

    if a.dst:
        sel = sorted([r for r in rows if r["dst"] == a.dst], key=lambda r: r["ts"])
        if not sel:
            sys.exit(f"no sessions to {a.dst}")
        print(f"  {'start (UTC)':<19}  {'end (UTC)':<19}  {'src':<13} {'dport':>5} {'duration':>10} {'bytes out':>15} "
              f"{'bytes in':>12}  {'state':<5}  uid / host")
        for r in sel:
            print(f"  {utc(r['ts'])}  {utc(r['end'])}  {r['src']:<13} {r['dport']:>5} {r['dur']:>9.1f}s "
                  f"{int(r['out']):>15,} {int(r['inb']):>12,}  {r['state']:<5}  {r['uid'] if r['uid'] != '-' else r['host']}")
        tot_o, tot_i = sum(r["out"] for r in sel), sum(r["inb"] for r in sel)
        # how many were open at the same time: rclone-style parallel streams show up here
        ev = sorted([(r["ts"], 1) for r in sel] + [(r["end"], -1) for r in sel])
        cur = peak = 0
        for _, d in ev:
            cur += d
            peak = max(peak, cur)
        print(f"\n  sessions {len(sel)}   first start {utc(sel[0]['ts'])}   last end {utc(max(r['end'] for r in sel))}   "
              f"max parallel {peak}")
        print(f"  total out  {int(tot_o):,} bytes  = {human(tot_o)}")
        print(f"  total in   {int(tot_i):,} bytes  = {human(tot_i)}   ratio out/in {tot_o / max(tot_i, 1):,.0f}x")
        span = max(r["end"] for r in sel) - sel[0]["ts"]
        if span > 0:
            print(f"  average rate over the span: {tot_o / span / 1e6:.2f} MB/s ({tot_o * 8 / span / 1e6:.1f} Mbit/s)")
        resets = [r for r in sel if r["state"] in ("RSTO", "RSTR", "RSTOS0", "RSTRH")]
        if resets:
            print(f"  {len(resets)} session(s) ended in a reset: their bytes count, but did they all arrive? "
                  "Look at what started right after.")
        if a.claim:
            c = parse_claim(a.claim)
            print(f"\n  claim '{a.claim}' = {int(c):,} bytes   (as GB: {c / 1e9:.3f}  as GiB: {c / 2**30:.3f})")
            print(f"  observed out / claim = {tot_o / c:.3f}")
            print("  before you call that a contradiction, account for: GB vs GiB, compression, protocol framing,\n"
                  "  retransmitted or re-sent data, and the rounding habits of whoever wrote the note.")
        return

    if a.hourly:
        hours = defaultdict(lambda: defaultdict(float))
        for r in rows:
            if a.host and r["src"] != a.host:
                continue
            # spread each session's bytes evenly over the hours it spans
            s, e = r["ts"], max(r["end"], r["ts"] + 1)
            h = int(s // 3600) * 3600
            while h < e:
                part = (min(e, h + 3600) - max(s, h)) / (e - s)
                hours[r["src"]][h] += r["out"] * part
                h += 3600
        hs = sorted({h for d in hours.values() for h in d})
        hosts = sorted(hours, key=lambda x: -sum(hours[x].values()))[: a.top]
        print("  bytes OUT per hour (UTC), each session spread over the hours it was open; '.' = under 1 MB\n")
        print("  " + f"{'hour':<14}" + "".join(f"{x:>13}" for x in hosts))
        for h in hs:
            cells = []
            for x in hosts:
                v = hours[x].get(h, 0)
                cells.append(f"{short(v):>13}" if v >= 1e6 else f"{'.':>13}")
            print("  " + datetime.fromtimestamp(h, timezone.utc).strftime("%m-%d %H:00   ") + "".join(cells))
        return

    if a.by == "host":
        agg = defaultdict(lambda: dict(out=0.0, inb=0.0, n=0, dsts=set(), first=None, last=None))
        for r in rows:
            g = agg[r["src"]]
            g["out"] += r["out"]
            g["inb"] += r["inb"]
            g["n"] += 1
            g["dsts"].add(r["dst"])
            g["first"] = r["ts"] if g["first"] is None else min(g["first"], r["ts"])
            g["last"] = r["end"] if g["last"] is None else max(g["last"], r["end"])
        print(f"  {'host':<14} {'sessions':>8} {'bytes out':>16} {'bytes in':>14} {'out/in':>7} {'dests':>5}  first -> last (UTC)")
        for h, g in sorted(agg.items(), key=lambda kv: -kv[1]["out"])[: a.top]:
            print(f"  {h:<14} {g['n']:>8} {int(g['out']):>16,} {int(g['inb']):>14,} {g['out'] / max(g['inb'], 1):>7.2f} "
                  f"{len(g['dsts']):>5}  {utc(g['first'])} -> {utc(g['last'])}")
        print("\n  A workstation downloads more than it uploads (out/in well below 1). A host whose ratio flips is")
        print("  sending something. A SERVER with any internet upload at all deserves a sentence in your report.")
        return

    agg = defaultdict(lambda: dict(out=0.0, inb=0.0, n=0, first=None, last=None, maxdur=0.0, hosts=set()))
    for r in rows:
        g = agg[(r["src"], r["dst"], r["dport"])]
        g["out"] += r["out"]
        g["inb"] += r["inb"]
        g["n"] += 1
        g["maxdur"] = max(g["maxdur"], r["dur"])
        g["hosts"].add(r["host"])
        g["first"] = r["ts"] if g["first"] is None else min(g["first"], r["ts"])
        g["last"] = r["end"] if g["last"] is None else max(g["last"], r["end"])
    print(f"  {'source':<13} {'destination':<21} {'sess':>5} {'bytes out':>16} {'bytes in':>13} {'out/in':>8} "
          f"{'longest':>9}  {'first (UTC)':<19}  {'last (UTC)':<19}  flag")
    for (s, d, p), g in sorted(agg.items(), key=lambda kv: -kv[1]["out"])[: a.top]:
        ratio = g["out"] / max(g["inb"], 1)
        fl = "ASYMMETRIC" if (ratio >= 10 and g["out"] >= 10e6) else ""
        print(f"  {s:<13} {d + ':' + p:<21} {g['n']:>5} {int(g['out']):>16,} {int(g['inb']):>13,} {ratio:>8.1f} "
              f"{g['maxdur']:>8.0f}s  {utc(g['first'])}  {utc(g['last'])}  {fl}")
    fl = flags(rows)
    print(f"\n  flagged sessions: {len(fl)}   (LONG-UPLOAD >= 10 min and >= 20 MB; OUTLIER >= 5 MB and >= 100x the channel median)")
    for kind, r in sorted(fl, key=lambda x: x[1]["ts"]):
        print(f"    {kind:<11} {utc(r['ts'])} -> {utc(r['end'])}  {r['src']} -> {r['dst']}:{r['dport']}  "
              f"{short(r['out'])} out in {r['dur'] / 60:.1f} min  {r['uid'] if r['uid'] != '-' else r['host']}")
    print("\n  Next: --dst <ip> for the session list, --by host for the per-host picture, --hourly for when.")


if __name__ == "__main__":
    main()

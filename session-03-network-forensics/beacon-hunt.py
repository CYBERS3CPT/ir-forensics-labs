#!/usr/bin/env python3
"""beacon-hunt.py - find things that call home on a schedule, in a Zeek conn.log.

A beacon is a conversation whose start times are evenly spaced. People are not
evenly spaced; schedulers are. So the question this script asks of every
(source, destination, port) pair is: how regular are the gaps between its
connections, and for how long has it been doing it?

    python3 beacon-hunt.py evidence/zeek/conn.log
    python3 beacon-hunt.py evidence/zeek/conn.log --min-count 50 --top 15
    python3 beacon-hunt.py evidence/zeek/conn.log --explain 203.0.113.66
    python3 beacon-hunt.py evidence/zeek/conn.log --explain 198.51.100.80 --src 10.20.30.47

What it outputs is a ranked list of CANDIDATES. It never says "malicious":
periodicity is a property of software, not of intent. Windows Update, printer
drivers, mail clients and implants all keep a schedule. The script gives you
the numbers that separate them (jitter, prevalence, start time, size
regularity) and leaves the call to you, with the evidence written next to it.

Numbers, so you can defend them:
  interval   gap between consecutive connection STARTS (Zeek ts), seconds
  median     the typical interval (robust to the odd long gap)
  jitter     coefficient of variation = stdev / mean of the intervals,
             computed after dropping gaps > 3x the median (host switched off,
             lunch break, laptop lid). 0.00 = a metronome; a C2 framework set to
             "60 s +/- 20 %" lands near 0.12; a human is > 0.8
  size cv    the same coefficient for orig_bytes: agents send the same-sized
             heartbeat every time; implants vary a little; people vary a lot
  hosts      how many internal sources talk to that destination:port at all.
             Fleet software shows up on many hosts; patient zero is alone
  score      0-100, a sorting aid. Not a probability. Not a verdict.

Standard library only. Read-only.
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def read_zeek(path: str):
    """Yield dicts from a Zeek TSV log. Understands the #fields header, so it
    does not care about column order or extra columns."""
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#"):
                continue
            if fields is None:
                sys.exit(f"{path}: no #fields header - is this a Zeek TSV log? (JSON logs: convert first)")
            yield dict(zip(fields, line.split("\t")))


# Explicit list on purpose: ipaddress.is_private also says True for the
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) that
# this course uses as "the internet".
INTERNAL = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL if n.version == a.version)


def num(v: str, default=0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def cv(values):
    if len(values) < 2:
        return None
    m = statistics.mean(values)
    return statistics.pstdev(values) / m if m else None


def analyse(rows, sni_by_uid):
    """Group connections by (src, dst, dport, proto) and measure regularity."""
    groups = defaultdict(list)
    prevalence = defaultdict(set)
    for r in rows:
        key = (r["id.orig_h"], r["id.resp_h"], r["id.resp_p"], r["proto"])
        groups[key].append(r)
        prevalence[(r["id.resp_h"], r["id.resp_p"])].add(r["id.orig_h"])
    out = []
    for key, conns in groups.items():
        conns.sort(key=lambda r: num(r["ts"]))
        ts = [num(r["ts"]) for r in conns]
        iv = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]   # <0.5 s = parallel connections, not a schedule
        if len(iv) < 2:
            continue
        med = statistics.median(iv)
        kept = [x for x in iv if x <= 3 * med]
        gaps = len(iv) - len(kept)
        jit = cv(kept)
        sizes = [num(r.get("orig_bytes"), 0) for r in conns]
        scv = cv(sizes)
        snis = sorted({sni_by_uid.get(r["uid"], "") for r in conns} - {""})
        overnight = sum(1 for t in ts if datetime.fromtimestamp(t, timezone.utc).hour in (0, 1, 2, 3, 4, 5))
        out.append(dict(key=key, n=len(conns), first=ts[0], last=ts[-1], median=med, mean=statistics.mean(kept),
                        jitter=jit, size_cv=scv, gaps=gaps, sni=",".join(snis) or "-",
                        hosts=len(prevalence[(key[1], key[2])]), overnight=overnight,
                        sum_out=sum(sizes), intervals=iv, kept=kept,
                        failed=sum(1 for r in conns if r.get("conn_state") in ("S0", "REJ", "RSTR", "RSTO"))))
    return out


def score(g) -> int:
    """Sorting aid: regular + many + sustained. Deliberately NOT boosted by
    'looks bad' features, because the script does not know what bad is."""
    if g["jitter"] is None:
        return 0
    regular = max(0.0, 1.0 - min(g["jitter"], 1.0))            # 1 = metronome
    volume = min(1.0, math.log10(g["n"]) / 3.0)                  # 1000 connections -> 1
    span_h = (g["last"] - g["first"]) / 3600
    sustained = min(1.0, span_h / 12.0)                          # half a day or more -> 1
    return round(100 * (0.5 * regular + 0.25 * volume + 0.25 * sustained))


def notes(g):
    """The questions an analyst should ask of this candidate, answered with
    the numbers the script already has. Observations, not conclusions."""
    out = []
    j = g["jitter"]
    if j is not None and j < 0.01:
        out.append("metronomic (jitter < 0.01): a fixed timer. Typical of agents, updaters, drivers - and of a lazy "
                   "implant. Periodic is NOT the same as malicious: check who owns the domain and how many hosts do it.")
    elif j is not None and 0.03 <= j <= 0.45:
        out.append(f"regular but jittered (~{g['median']:.0f} s, jitter {j:.2f}): what a C2 'sleep + jitter' setting "
                   "produces. Also what some sync clients do. Look at when it STARTED.")
    if g["hosts"] > 1:
        out.append(f"{g['hosts']} internal hosts talk to this destination:port. Fleet software is the boring explanation; "
                   "rule it in or out before you count infected hosts.")
    else:
        out.append("only ONE internal host talks to this destination:port.")
    if g["size_cv"] is not None and g["size_cv"] < 0.01:
        out.append("every connection sends the same number of bytes: a fixed-format heartbeat.")
    if g["overnight"]:
        out.append(f"{g['overnight']} connections between 00:00 and 06:00 UTC: nobody was at the keyboard.")
    if g["gaps"]:
        out.append(f"{g['gaps']} long gap(s) excluded from the jitter (host off / asleep / isolated).")
    if g["failed"]:
        out.append(f"{g['failed']} connection(s) failed or were reset - look at the last ones: containment shows up here.")
    return out


def explain(g):
    print(f"\n  {g['key'][0]} -> {g['key'][1]}:{g['key'][2]}/{g['key'][3]}   SNI: {g['sni']}")
    print(f"  connections {g['n']}   first {utc(g['first'])}   last {utc(g['last'])}   "
          f"span {(g['last'] - g['first']) / 3600:.1f} h")
    k = g["kept"]
    print(f"  interval: median {g['median']:.3f} s   mean {g['mean']:.3f} s   min {min(k):.3f}   max {max(k):.3f}   "
          f"stdev {statistics.pstdev(k):.3f}   jitter {g['jitter']:.4f}")
    if g["size_cv"] is not None:
        print(f"  orig_bytes: total {int(g['sum_out']):,}   size cv {g['size_cv']:.3f}")
    print("\n  interval histogram (seconds; excluded long gaps not shown)")
    lo, hi = math.floor(min(k)), math.ceil(max(k))
    width = max(1, math.ceil((hi - lo) / 20))
    bins = defaultdict(int)
    for x in k:
        bins[int((x - lo) // width)] += 1
    top = max(bins.values())
    for b in range(0, (hi - lo) // width + 1):
        c = bins.get(b, 0)
        print(f"  {lo + b * width:>8.1f} - {lo + (b + 1) * width:<8.1f} {c:>6}  {'#' * max(0, round(50 * c / top))}")
    print("\n  what you would write down:")
    for n in notes(g):
        print(f"   - {n}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 epilog="Read the module docstring (head -40 beacon-hunt.py) for what each number means.")
    ap.add_argument("conn_log", help="Zeek conn.log (TSV)")
    ap.add_argument("--ssl", help="Zeek ssl.log to label destinations with their SNI (default: next to conn.log)")
    ap.add_argument("--min-count", type=int, default=20, help="ignore pairs with fewer connections (default 20)")
    ap.add_argument("--top", type=int, default=12, help="how many candidates to show (default 12)")
    ap.add_argument("--include-internal", action="store_true",
                    help="also score internal destinations (default: only traffic leaving the network)")
    ap.add_argument("--explain", metavar="DST_IP", help="detail and interval histogram for one destination")
    ap.add_argument("--src", metavar="SRC_IP", help="with --explain: only this source")
    ap.add_argument("--verdict", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.verdict:
        print("beacon-hunt: refusing --verdict.\n\n"
              "  Regularity is measured here; intent is not. The same numbers describe a printer driver, an\n"
              "  update agent and an implant. A verdict needs evidence this log does not contain: who owns the\n"
              "  domain, which process opened the socket (host evidence, e.g. Sysmon event 3), what started it\n"
              "  and when relative to the rest of the timeline. Collect that, then write the verdict yourself,\n"
              "  with the evidence next to it.", file=sys.stderr)
        sys.exit(2)

    ssl_path = a.ssl or os.path.join(os.path.dirname(os.path.abspath(a.conn_log)), "ssl.log")
    sni = {}
    if os.path.exists(ssl_path):
        for r in read_zeek(ssl_path):
            if r.get("server_name", "-") != "-":
                sni[r["uid"]] = r["server_name"]

    rows = [r for r in read_zeek(a.conn_log)
            if r.get("proto") in ("tcp", "udp") and (a.include_internal or not is_internal(r["id.resp_h"]))]
    if not rows:
        sys.exit("no connections to external destinations in that log")
    groups = [g for g in analyse(rows, sni) if g["n"] >= a.min_count]

    if a.explain:
        sel = [g for g in groups if g["key"][1] == a.explain and (not a.src or g["key"][0] == a.src)]
        if not sel:
            sys.exit(f"no pair with >= {a.min_count} connections to {a.explain}" + (f" from {a.src}" if a.src else ""))
        for g in sorted(sel, key=lambda g: -g["n"]):
            explain(g)
        return

    t0 = min(num(r["ts"]) for r in rows)
    t1 = max(num(r["ts"]) for r in rows)
    print(f"beacon-hunt  {a.conn_log}\n  {len(rows)} connections to external destinations, "
          f"{utc(t0)} -> {utc(t1)} UTC, {len(groups)} pairs with >= {a.min_count} connections\n")
    print(f"  {'#':>2} {'score':>5}  {'source':<13} {'destination':<21} {'conns':>5} {'median':>8} {'jitter':>7} "
          f"{'size cv':>7} {'hosts':>5}  {'first seen (UTC)':<19}  {'last seen (UTC)':<19}  SNI")
    ranked = sorted(groups, key=lambda g: (-score(g), -g["n"]))[: a.top]
    for i, g in enumerate(ranked, 1):
        s, d, p, pr = g["key"]
        jit = f"{g['jitter']:.3f}" if g["jitter"] is not None else "-"
        scv = f"{g['size_cv']:.3f}" if g["size_cv"] is not None else "-"
        print(f"  {i:>2} {score(g):>5}  {s:<13} {d + ':' + p:<21} {g['n']:>5} {g['median']:>7.1f}s {jit:>7} "
              f"{scv:>7} {g['hosts']:>5}  {utc(g['first'])}  {utc(g['last'])}  {g['sni']}")
    print("\n  label for every row above: CANDIDATE. This script does not do verdicts (try --verdict to see why).")
    print("\n  Notes on the top candidates:")
    for i, g in enumerate(ranked[:5], 1):
        s, d, p, _ = g["key"]
        print(f"\n  [{i}] {s} -> {d}:{p}  ({g['sni']})")
        for n in notes(g):
            print(f"      - {n}")
    print("\n  Next: python3 beacon-hunt.py <conn.log> --explain <dst_ip>   for the histogram of one candidate,")
    print("        then pivot on its uid in ssl.log / dns.log, and on the host side (S2 evidence) on the time.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
triage.py — work an alert queue the way you would defend it afterwards.

Every alert gets a decision, every decision gets a reason, and the log of
those decisions is a piece of evidence in its own right: on Wednesday at
09:00 somebody will ask "was this in the SIEM yesterday, and what did we do
with it?". The answer should be a file, not a memory.

Usage
    ./triage.py list                       the whole queue, oldest first
    ./triage.py list --host WS-FIN-07      one host
    ./triage.py list --min-sev medium      normalised severity >= medium
    ./triage.py list --search rundll32     free text over rule + summary
    ./triage.py list --undecided           what is still waiting for you
    ./triage.py list --clock               show event time vs SIEM ingest time
    ./triage.py hosts                      group by host: counts, worst severity, window
    ./triage.py show ALR-0011              one alert, every field
    ./triage.py decide ALR-0011 --verdict escalate --reason "..." [--analyst NAME]
    ./triage.py status                     how far along are you?
    ./triage.py export -o triage-log.csv   the decision log, UTC

Verdicts
    escalate     part of (or evidence for) an incident; goes to the incident manager
    investigate  not enough to decide; say what you need to look at next
    close        benign or false positive; the reason must say WHY, not WHAT

Refusals (on purpose)
    - no decision without a reason;
    - no "close" with a reason that is only a label ("fp", "noise", "benign");
    - no bulk close of medium/high alerts: those are closed one at a time;
    - no export while alerts are undecided, unless you say --partial.

Decisions are appended to work/triage-decisions.csv (git-ignored). Nothing
here touches the evidence file.
"""

import argparse
import csv
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_QUEUE = HERE / "evidence" / "alert-queue.csv"
DEFAULT_LOG = Path("work") / "triage-decisions.csv"
VERDICTS = ("escalate", "investigate", "close")

TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


RED, YEL, GRN, DIM, BOLD, CYA = "31", "33", "32", "2", "1", "36"


def die(msg):
    print(c(RED, " fail ") + msg, file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(c(YEL, " warn ") + msg, file=sys.stderr)


# ── severity normalisation ───────────────────────────────────────────────────
# Every product has its own scale. To sort a queue you need ONE scale, and the
# mapping is a decision you make, not a fact: a Wazuh "level 12" and an EDR
# "high" are not the same thing just because both land in the same bucket.
# Read this table, then disagree with it in your write-up if you want to.
NORM = ["info", "low", "medium", "high"]


def normalise(sev):
    s = sev.strip().lower()
    m = re.match(r"level (\d+)", s)
    if m:  # Wazuh rule levels 0-15
        n = int(m.group(1))
        return 0 if n <= 3 else 1 if n <= 7 else 2 if n <= 11 else 3
    table = {"informational": 0, "info": 0, "notice": 1, "low": 1,
             "warning": 2, "medium": 2, "high": 3, "critical": 3}
    return table.get(s, 1)


def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ── data ─────────────────────────────────────────────────────────────────────
def load_queue(path):
    if not path.exists():
        die(f"alert queue not found: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["_sev"] = normalise(r["severity_vendor"])
    return rows


LOG_FIELDS = ["alert_id", "verdict", "reason", "analyst", "decided_utc", "related"]


def load_decisions(path):
    """Append-only log: the latest line for an alert is its current decision,
    the earlier ones are its history (which is why we never rewrite the file)."""
    out = {}
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                out[r["alert_id"]] = r
    return out


def append_decision(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS, lineterminator="\n")
        if new:
            w.writeheader()
        w.writerow(row)


# ── views ────────────────────────────────────────────────────────────────────
SEV_COL = {0: DIM, 1: "0", 2: YEL, 3: RED}
VERD_COL = {"escalate": RED, "investigate": YEL, "close": GRN}


def skew_s(r):
    return int((parse_ts(r["time_utc"]) - parse_ts(r["ingested_utc"])).total_seconds())


def fmt_row(r, dec, show_clock):
    sev = NORM[r["_sev"]]
    clk = "H" if r["clock"] == "host" else " "
    d = dec.get(r["alert_id"], {}).get("verdict", "")
    line = (f"{r['alert_id']}  {r['time_utc'][:19].replace('T', ' ')} {clk} "
            f"{r['source']:<6} {r['host']:<10} {c(SEV_COL[r['_sev']], f'{sev:<6}')} ")
    if show_clock:
        line += f"{skew_s(r):>+5}s  "
    rule = r["rule"][:52]
    line += f"{rule:<52} {c(VERD_COL.get(d, DIM), d or '-')}"
    return line


def cmd_list(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    rows = q
    if a.host:
        rows = [r for r in rows if r["host"].lower() == a.host.lower()]
    if a.source:
        rows = [r for r in rows if r["source"].lower() == a.source.lower()]
    if a.min_sev:
        rows = [r for r in rows if r["_sev"] >= NORM.index(a.min_sev)]
    if a.search:
        rx = re.compile(re.escape(a.search), re.I)
        rows = [r for r in rows if rx.search(r["rule"] + " " + r["raw_summary"] + " " + r["user"])]
    if a.undecided:
        rows = [r for r in rows if r["alert_id"] not in dec]
    if a.sort == "sev":
        rows = sorted(rows, key=lambda r: (-r["_sev"], r["time_utc"]))
    elif a.sort == "host":
        rows = sorted(rows, key=lambda r: (r["host"], r["time_utc"]))
    else:
        rows = sorted(rows, key=lambda r: r["alert_id"])
    hdr = "id        time (as reported)  c source host       sev    "
    if a.clock:
        hdr += "Δingest "
    print(c(DIM, hdr + "rule" + " " * 49 + "decision"))
    for r in rows:
        print(fmt_row(r, dec, a.clock))
    print(c(DIM, f"\n{len(rows)} of {len(q)} alerts.  c=H: time written by the HOST's own clock; "
                 "blank: stamped by the SIEM / service."))
    if a.clock:
        print(c(DIM, "Δingest = reported time minus SIEM ingest time. A few seconds negative is "
                     "transport delay. Anything else is a clock you should not trust."))


def cmd_hosts(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    by = {}
    for r in q:
        by.setdefault(r["host"], []).append(r)
    print(c(DIM, f"{'host':<11}{'n':>3} {'worst':<7}{'undec':>6}  {'first (reported)':<20}"
                 f"{'last (reported)':<20}{'Δingest':>8}  sources"))
    for h, rs in sorted(by.items(), key=lambda kv: (-max(r['_sev'] for r in kv[1]), kv[0])):
        worst = max(r["_sev"] for r in rs)
        und = sum(1 for r in rs if r["alert_id"] not in dec)
        hostclk = [skew_s(r) for r in rs if r["clock"] == "host"]
        sk = f"{int(statistics.median(hostclk)):+d}s" if hostclk else "-"
        srcs = ",".join(sorted({r["source"] for r in rs}))
        print(f"{h:<11}{len(rs):>3} {c(SEV_COL[worst], f'{NORM[worst]:<7}')}{und:>6}  "
              f"{min(r['time_utc'] for r in rs)[:19].replace('T', ' '):<20}"
              f"{max(r['time_utc'] for r in rs)[:19].replace('T', ' '):<20}{sk:>8}  {srcs}")
    print(c(DIM, "\nΔingest: median of (host-reported time - SIEM ingest time) for host-clock alerts."))


def cmd_show(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    ids = {r["alert_id"]: r for r in q}
    for aid in a.ids:
        r = ids.get(aid.upper())
        if not r:
            die(f"no such alert: {aid}")
        print(c(CYA, f"── {r['alert_id']} " + "─" * 60))
        for k in ["time_utc", "clock", "ingested_utc", "source", "host", "user", "rule",
                  "severity_vendor", "raw_summary"]:
            print(f"  {k:<16} {r[k]}")
        print(f"  {'normalised':<16} {NORM[r['_sev']]}")
        if r["clock"] == "host":
            print(c(DIM, f"  {'':<16} time written by {r['host']}'s own clock "
                         f"({skew_s(r):+d} s vs SIEM ingest)"))
        d = dec.get(r["alert_id"])
        if d:
            print(f"  {'decision':<16} {c(VERD_COL[d['verdict']], d['verdict'])} — {d['reason']} "
                  f"({d['analyst']}, {d['decided_utc']})")


# A close reason that is just a label tells the next person nothing. These are
# the labels people actually type at the end of a long queue.
LABELS = {"fp", "false positive", "falsepositive", "noise", "benign", "ok", "n/a", "na",
          "nothing", "test", "known", "expected", "normal", "closed", "ignore", "dup", "duplicate"}


def reason_problem(verdict, reason):
    r = reason.strip()
    if not r:
        return "a decision without a reason is a guess with a timestamp"
    if verdict == "close":
        bare = re.sub(r"[^a-z/ ]", "", r.lower()).strip()
        if bare in LABELS:
            return (f"'{r}' is a label, not a reason. Say WHY it is benign: what evidence, "
                    "which ticket, which owner confirmed it")
        if len(r) < 20:
            return "too short to be checked by someone else. Name the evidence you relied on"
    if verdict == "investigate" and len(r) < 15:
        return "say what you will look at next, so someone else can pick it up"
    return None


def cmd_decide(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    ids = {r["alert_id"]: r for r in q}
    targets = []
    for aid in a.ids:
        r = ids.get(aid.upper())
        if not r:
            die(f"no such alert: {aid}")
        targets.append(r)
    prob = reason_problem(a.verdict, a.reason or "")
    if prob:
        die(f"refused: {prob}")
    if a.verdict == "close" and len(targets) > 1:
        loud = [r["alert_id"] for r in targets if r["_sev"] >= 2]
        if loud:
            die("refused: bulk close includes medium/high alerts (" + ", ".join(loud) + "). "
                "Close those one at a time; bulk closing is where incidents hide.")
    # A gentle nudge, not a refusal: closing an alert on a host you already
    # escalated is legitimate, but you should be able to say why it is unrelated.
    esc_hosts = {ids[k]["host"] for k, v in dec.items() if v["verdict"] == "escalate" and k in ids}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    analyst = a.analyst or os.environ.get("USER", "analyst")
    for r in targets:
        if a.verdict == "close" and r["host"] in esc_hosts and r["host"] != "-":
            warn(f"{r['alert_id']}: you escalated other alerts on {r['host']}. "
                 "Make sure the reason says why this one is unrelated.")
        prev = dec.get(r["alert_id"])
        append_decision(a.log, {"alert_id": r["alert_id"], "verdict": a.verdict,
                                "reason": a.reason.strip(), "analyst": analyst,
                                "decided_utc": now, "related": a.related or ""})
        tag = " (replaces " + prev["verdict"] + ")" if prev else ""
        print(f"{c(VERD_COL[a.verdict], a.verdict):>10}  {r['alert_id']}  {r['rule'][:60]}{tag}")
    print(c(DIM, f"logged to {a.log}"))


def cmd_status(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    n = len(q)
    done = [r for r in q if r["alert_id"] in dec]
    counts = {v: sum(1 for r in done if dec[r["alert_id"]]["verdict"] == v) for v in VERDICTS}
    print(f"{len(done)}/{n} decided  ·  " +
          "  ".join(f"{c(VERD_COL[v], v)} {counts[v]}" for v in VERDICTS))
    und_hi = [r["alert_id"] for r in q if r["alert_id"] not in dec and r["_sev"] >= 2]
    if und_hi:
        warn("undecided medium/high: " + ", ".join(und_hi))
    if n and counts["close"] == len(done) == n:
        warn("you closed everything. Either this queue is clean, or the queue is not the problem.")


def cmd_export(a):
    q, dec = load_queue(a.queue), load_decisions(a.log)
    und = [r["alert_id"] for r in q if r["alert_id"] not in dec]
    if und and not a.partial:
        die(f"refused: {len(und)} alert(s) undecided ({', '.join(und[:6])}{'...' if len(und) > 6 else ''}). "
            "A log with gaps reads as complete. Decide them, or export with --partial and say so.")
    skew = {}
    for s in a.skew or []:
        m = re.fullmatch(r"([A-Za-z0-9-]+)=([+-]?\d+)", s)
        if not m:
            die(f"--skew wants HOST=SECONDS, e.g. WS-EXAMPLE=+60 (got {s})")
        skew[m.group(1).upper()] = int(m.group(2))
    fields = ["alert_id", "time_reported_utc", "clock", "time_corrected_utc", "source", "host",
              "user", "rule", "severity_vendor", "severity_normalised", "verdict", "reason",
              "analyst", "decided_utc", "related"]
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in q:
            t = parse_ts(r["time_utc"])
            corr = ""
            if r["clock"] == "host" and r["host"].upper() in skew:
                corr = (t - timedelta(seconds=skew[r["host"].upper()])).strftime("%Y-%m-%dT%H:%M:%SZ")
            d = dec.get(r["alert_id"], {})
            w.writerow({"alert_id": r["alert_id"], "time_reported_utc": r["time_utc"],
                        "clock": r["clock"], "time_corrected_utc": corr, "source": r["source"],
                        "host": r["host"], "user": r["user"], "rule": r["rule"],
                        "severity_vendor": r["severity_vendor"],
                        "severity_normalised": NORM[r["_sev"]],
                        "verdict": d.get("verdict", "UNDECIDED"), "reason": d.get("reason", ""),
                        "analyst": d.get("analyst", ""), "decided_utc": d.get("decided_utc", ""),
                        "related": d.get("related", "")})
    print(f"wrote {out}  ({len(q) - len(und)}/{len(q)} decided"
          f"{', PARTIAL' if und else ''}{', skew corrected for ' + ','.join(skew) if skew else ''})")


def main():
    p = argparse.ArgumentParser(
        description="Triage an alert queue with a decision log you can defend.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Usage")[1])
    p.add_argument("--queue", type=Path, default=DEFAULT_QUEUE, help="alert queue CSV (default: evidence/alert-queue.csv)")
    p.add_argument("--log", type=Path, default=DEFAULT_LOG, help="decision log (default: work/triage-decisions.csv)")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("list", help="list alerts")
    s.add_argument("--host")
    s.add_argument("--source")
    s.add_argument("--min-sev", choices=NORM)
    s.add_argument("--search")
    s.add_argument("--undecided", action="store_true")
    s.add_argument("--sort", choices=["id", "sev", "host"], default="id")
    s.add_argument("--clock", action="store_true", help="show reported time minus SIEM ingest time")
    s.set_defaults(fn=cmd_list)

    s = sp.add_parser("hosts", help="group by host")
    s.set_defaults(fn=cmd_hosts)

    s = sp.add_parser("show", help="show alerts in full")
    s.add_argument("ids", nargs="+")
    s.set_defaults(fn=cmd_show)

    s = sp.add_parser("decide", help="record a decision")
    s.add_argument("ids", nargs="+")
    s.add_argument("--verdict", required=True, choices=VERDICTS)
    s.add_argument("--reason", required=True)
    s.add_argument("--analyst")
    s.add_argument("--related", help="related alert or ticket ids, e.g. ALR-0010,HD-4471")
    s.set_defaults(fn=cmd_decide)

    s = sp.add_parser("status", help="progress")
    s.set_defaults(fn=cmd_status)

    s = sp.add_parser("export", help="write the decision log")
    s.add_argument("-o", "--output", default="work/triage-log.csv")
    s.add_argument("--partial", action="store_true", help="allow undecided alerts (marked UNDECIDED)")
    s.add_argument("--skew", action="append", metavar="HOST=SECONDS",
                   help="host clock offset to subtract from host-clock times (repeatable)")
    s.set_defaults(fn=cmd_export)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
tabletop.py — run the Wednesday morning at Ceres as a timed tabletop exercise.

Injects (evidence/injects.json) arrive on a scenario clock that runs faster
than real time. Each inject asks the team for a DECISION, an OWNER and a
TIME. Everything is written to a decision log in scenario time (UTC), plus a
summary with the regulatory clocks that your "aware" moment started.

Usage
    ./tabletop.py --team blue                  timed: scenario runs 8x real time (default)
    ./tabletop.py --team blue --speed 5        slower: 5 scenario minutes per real minute
    ./tabletop.py --team blue --manual         no clock pressure: Enter releases the next inject
    ./tabletop.py --list                       inject titles and times only (for the facilitator)

At any decision prompt you can type:
    /aware HH:MM      record the moment Ceres became aware (starts the clocks)
    /note TEXT        add a note to the log without making a decision
    /defer REASON     consciously defer this inject (it is logged, with the reason)
    /clock            show the scenario time and the clocks running
    /quit             stop, and write the log and summary so far

Breakout rooms (Teams): one person shares the screen and types — the scribe.
Everyone else argues. The scribe writes down what was decided, not what was
said. Output goes to work/tabletop-<team>-<UTC stamp>/.
"""

import argparse
import csv
import json
import os
import re
import select
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_INJECTS = HERE / "evidence" / "injects.json"
UTC = timezone.utc

TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


RED, YEL, GRN, DIM, BOLD, CYA = "31", "33", "32", "2", "1", "36"


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hhmm(dt):
    return dt.strftime("%H:%M")


# ── the scenario clock ───────────────────────────────────────────────────────
class Clock:
    """Scenario time = start + (real elapsed) x speed + any jumps forward.
    In manual mode the clock only moves when an inject is released."""

    def __init__(self, start, speed, manual):
        self.start, self.speed, self.manual = start, speed, manual
        self.t0 = time.monotonic()
        self.jump = timedelta(0)
        self.manual_now = start

    def now(self):
        if self.manual:
            return self.manual_now
        real = timedelta(seconds=(time.monotonic() - self.t0) * self.speed)
        return (self.start + real + self.jump).replace(microsecond=0)

    def advance_to(self, t):
        if self.manual:
            self.manual_now = max(self.manual_now, t)
        elif t > self.now():
            self.jump += t - self.now()


# ── clocks that matter (EU baseline; check current CNCS guidance for PT detail)
def reg_clocks(aware):
    nis2_notif = aware + timedelta(hours=72)
    return [
        ("Insurer written notice (policy)", aware + timedelta(hours=48)),
        ("NIS2 early warning (art. 23(4)(a))", aware + timedelta(hours=24)),
        ("NIS2 incident notification (art. 23(4)(b))", nis2_notif),
        ("NIS2 final report (art. 23(4)(d), ~1 month after notification)", nis2_notif + timedelta(days=30)),
        ("GDPR art. 33 notification to CNPD", aware + timedelta(hours=72)),
        ("GDPR art. 34 data subjects", None),
    ]


# Owners that are not owners. A decision owned by everyone is owned by no one.
VAGUE_OWNERS = {"team", "the team", "we", "us", "all", "everyone", "it", "the it", "it team",
                "management", "board", "someone", "tbd", "n/a", "na", "?", "-"}

# Words that, in a decision taken before anything was preserved, usually mean
# the evidence is gone. A heuristic for the debrief, not a grade.
DESTRUCTIVE = re.compile(r"\b(wipe|reimage|re-image|format|rebuild|reinstall|restore|power off|"
                         r"pull the (power|plug|cable)|shut ?down|delete)\b", re.I)
PRESERVE = re.compile(r"\b(image|imaging|memory|ram|snapshot|preserv|capture|collect|acquir|hash|"
                      r"triage collection|kape|forensic)\w*", re.I)


def read_line(prompt):
    try:
        return input(prompt)
    except EOFError:
        return None


def wait_or_enter(seconds):
    """Wait up to `seconds` real seconds. Returns the line typed (possibly
    empty) if the user hit Enter, or None if the time simply ran out."""
    if seconds <= 0:
        return None
    try:
        r, _, _ = select.select([sys.stdin], [], [], seconds)
    except (ValueError, OSError):
        time.sleep(seconds)
        return None
    if r:
        return sys.stdin.readline()
    return None


def parse_time_override(s, ref):
    """'09:12' -> same day as ref. Returns None if not a time."""
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", s.strip())
    if not m:
        return None
    return ref.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0)


class Session:
    def __init__(self, a, data):
        self.a, self.data = a, data
        self.injects = data["injects"]
        start = parse_iso(data["scenario_start_utc"])
        self.clock = Clock(start, a.speed, a.manual)
        self.rows = []
        self.aware = None
        self.aware_why = ""
        self.preserved_first = None  # did a preservation decision come before a destructive one?
        self.flags = []
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        team = re.sub(r"[^A-Za-z0-9_-]", "", a.team) or "team"
        self.out = Path(a.out) if a.out else Path("work") / f"tabletop-{team}-{stamp}"

    # -- logging ------------------------------------------------------------
    def log(self, inj, kind, decision, owner, when, released):
        self.rows.append({
            "team": self.a.team, "inject_id": inj["id"] if inj else "-",
            "inject_time_utc": inj["time_utc"] if inj else "",
            "inject_title": inj["title"] if inj else "",
            "released_scenario_utc": iso(released) if released else "",
            "kind": kind, "decision": decision, "owner": owner,
            "decision_time_utc": iso(when),
            "minutes_to_decide": (f"{(when - released).total_seconds() / 60:.0f}"
                                  if released and kind in ("decision", "deferred") else ""),
            "wall_clock_utc": iso(datetime.now(UTC).replace(microsecond=0)),
        })
        if kind == "decision":
            if DESTRUCTIVE.search(decision) and not PRESERVE.search(decision):
                if self.preserved_first:
                    why = "was the preservation you decided earlier actually DONE (and verified) by then?"
                else:
                    why = "no preservation decision was logged before it. What evidence did this destroy?"
                self.flags.append(f"{inj['id']} at {hhmm(when)}: '{decision[:70]}' — destructive action; {why}")
            if PRESERVE.search(decision) and self.preserved_first is None:
                self.preserved_first = True

    # -- one inject ---------------------------------------------------------
    def show(self, inj, queued):
        print()
        print(c(CYA, "═" * 72))
        print(c(BOLD, f" {inj['time_utc'][11:16]} UTC  ·  {inj['id']}  ·  {inj['title']}"))
        print(c(DIM, f" from: {inj['from']}  ·  via: {inj['channel']}"
                     + (f"  ·  {queued} more waiting" if queued else "")))
        print(c(CYA, "─" * 72))
        for para in inj["text"].split("\n"):
            print(" " + para)
        print()
        print(c(YEL, " ▶ " + inj["prompt"]))
        print(c(CYA, "═" * 72))

    def handle(self, inj, released, queued):
        self.show(inj, queued)
        while True:
            line = read_line(c(BOLD, f" [{hhmm(self.clock.now())}] decision> "))
            if line is None:
                return "eof"
            line = line.strip()
            if not line:
                print(c(DIM, "   a decision, or /defer REASON, or /note, /aware HH:MM, /clock, /quit"))
                continue
            if line.startswith("/"):
                r = self.command(line, inj, released)
                if r in ("quit", "deferred"):
                    return r
                continue
            decision = line
            owner = self.ask_owner()
            if owner is None:
                return "eof"
            when = self.ask_when(released)
            if when is None:
                return "eof"
            self.log(inj, "decision", decision, owner, when, released)
            more = read_line(c(DIM, "   another decision on this inject? [y/N] "))
            if more is None or more.strip().lower() not in ("y", "yes"):
                return "ok"

    def ask_owner(self):
        while True:
            o = read_line("   owner (a named role or person)> ")
            if o is None:
                return None
            o = o.strip()
            if not o:
                print(c(RED, "   refused: a decision without an owner does not get done."))
                continue
            if o.startswith("/") or len(o) < 2:
                print(c(RED, f"   refused: '{o}' is not an owner. Commands go at the decision prompt."))
                continue
            if o.lower() in VAGUE_OWNERS:
                print(c(RED, f"   refused: '{o}' is not an owner. A decision owned by everyone is owned "
                             "by no one. Name the role (e.g. incident manager, DPO, CFO) or the person."))
                continue
            return o

    def ask_when(self, released):
        now = self.clock.now()
        while True:
            s = read_line(f"   time (UTC) [{hhmm(now)}]> ")
            if s is None:
                return None
            s = s.strip()
            if not s:
                return max(now, released)
            t = parse_time_override(s, now)
            if t is None:
                print("   HH:MM, or Enter for the current scenario time")
                continue
            # Compare by the minute: an inject that arrived at 07:55:40 can be decided "at 07:55".
            if t < released.replace(second=0):
                print(c(RED, f"   refused: {hhmm(t)} is before this inject arrived ({hhmm(released)}). "
                             "You cannot decide on something before you knew about it."))
                continue
            t = max(t, released)
            if self.a.manual and t > now:
                # Manual mode: the team's own clock moves the scenario forward.
                self.clock.advance_to(t)
            elif t > now + timedelta(minutes=1):
                print(c(YEL, f"   note: {hhmm(t)} is in the future — logged as a planned time."))
            return t

    def command(self, line, inj, released):
        cmd, _, arg = line.partition(" ")
        cmd = cmd.lower()
        if cmd == "/quit":
            return "quit"
        if cmd == "/clock":
            self.print_clocks()
            return None
        if cmd == "/note":
            if not arg.strip():
                print("   /note TEXT")
                return None
            self.log(inj, "note", arg.strip(), "", self.clock.now(), released)
            print(c(DIM, "   noted"))
            return None
        if cmd == "/defer":
            if inj is None:
                print("   /defer applies to an inject; there is none open right now.")
                return None
            if len(arg.strip()) < 10:
                print(c(RED, "   refused: deferring is a decision too — give the reason (and until when)."))
                return None
            owner = self.ask_owner()
            if owner is None:
                return "quit"
            self.log(inj, "deferred", arg.strip(), owner, self.clock.now(), released)
            return "deferred"
        if cmd == "/aware":
            t = parse_time_override(arg, self.clock.now()) if arg.strip() else self.clock.now()
            if t is None:
                print("   /aware HH:MM")
                return None
            if t > self.clock.now():
                print(c(RED, "   refused: you cannot have become aware in the future."))
                return None
            why = read_line("   why this moment (one line)> ")
            if why is None or len(why.strip()) < 10:
                print(c(RED, "   refused: the aware moment needs a reason; a regulator will ask for it."))
                return None
            self.aware, self.aware_why = t, why.strip()
            self.log(inj, "aware", why.strip(), "", t, released)
            print(c(GRN, f"   aware = {iso(t)}. Clocks started:"))
            self.print_clocks()
            return None
        print(f"   unknown command {cmd}")
        return None

    def print_clocks(self):
        now = self.clock.now()
        print(c(DIM, f"   scenario time {iso(now)}"))
        if not self.aware:
            print(c(YEL, "   no aware moment recorded — no clock is running (which does not stop them)."))
            return
        for name, dl in reg_clocks(self.aware):
            if dl is None:
                print(f"   {name:<62} without undue delay")
            else:
                left = dl - now
                print(f"   {name:<62} {iso(dl)}  ({left.total_seconds() / 3600:5.1f} h left)")

    # -- run ------------------------------------------------------------------
    def run(self):
        self.banner()
        pending = list(self.injects)
        status = "ok"
        while pending and status not in ("quit", "eof"):
            nxt = parse_iso(pending[0]["time_utc"])
            now = self.clock.now()
            if now < nxt:
                if self.a.manual:
                    r = read_line(c(DIM, f"\n [{hhmm(now)}] Enter to release the next inject ({hhmm(nxt)}), "
                                         "or /quit > "))
                    if r is None or r.strip() == "/quit":
                        break
                    if r.strip().startswith("/"):
                        # Between injects the team can still record the aware moment, a note, or look at the clocks.
                        if self.command(r.strip(), None, now) == "quit":
                            break
                        continue
                    self.clock.advance_to(nxt)
                else:
                    real = (nxt - now).total_seconds() / self.a.speed
                    print(c(DIM, f"\n [{hhmm(now)}] next inject at {hhmm(nxt)} (in {real:.0f} s real time). "
                                 "Enter to skip ahead, or a /command."), flush=True)
                    typed = wait_or_enter(real)
                    if typed is None:
                        continue
                    if typed == "":  # end of input
                        status = "eof"
                        break
                    if typed.strip().startswith("/"):
                        # Between injects the clock keeps running, but the team can still
                        # record the aware moment, a note, or look at the clocks.
                        if self.command(typed.strip(), None, self.clock.now()) == "quit":
                            break
                        continue
                    self.clock.advance_to(nxt)
                continue
            # Everything due is released at once — if you are slow, they pile up,
            # which is exactly what happens on the day.
            due = [i for i in pending if parse_iso(i["time_utc"]) <= now]
            inj = due[0]
            pending.remove(inj)
            released = max(parse_iso(inj["time_utc"]), now)
            status = self.handle(inj, released, len(due) - 1)
        self.finish(status)

    def banner(self):
        d = self.data
        print(c(BOLD, f"Tabletop — {d['case']} — {d.get('incident', '')}"))
        print(c(DIM, f"team {self.a.team} · scenario {d['scenario_start_utc']} → {d['scenario_end_utc']} · "
                     + ("manual (Enter releases injects)" if self.a.manual
                        else f"speed {self.a.speed:g}x (1 real minute = {self.a.speed:g} scenario minutes)")))
        print(c(DIM, d.get("clock_note", "")))
        print(c(DIM, "Commands: /aware HH:MM  /note TEXT  /defer REASON  /clock  /quit"))

    def finish(self, status):
        if self.aware is None and sys.stdin and not sys.stdin.closed and status != "eof":
            print()
            s = read_line("When did Ceres become aware (HH:MM UTC, Enter to leave it unrecorded)? ")
            if s and parse_time_override(s, self.clock.now()):
                why = read_line("Why that moment (one line)? ") or ""
                self.aware = parse_time_override(s, self.clock.now())
                self.aware_why = why.strip()
                self.log(None, "aware", self.aware_why, "", self.aware, None)
        self.write()

    def write(self):
        self.out.mkdir(parents=True, exist_ok=True)
        f = self.out / "decisions.csv"
        fields = ["team", "inject_id", "inject_time_utc", "inject_title", "released_scenario_utc", "kind",
                  "decision", "owner", "decision_time_utc", "minutes_to_decide", "wall_clock_utc"]
        with f.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            w.writerows(self.rows)
        (self.out / "summary.md").write_text(self.summary(), encoding="utf-8")
        print()
        print(c(GRN, f"  ok wrote {f}"))
        print(c(GRN, f"  ok wrote {self.out / 'summary.md'}"))

    def summary(self):
        decided = {r["inject_id"] for r in self.rows if r["kind"] in ("decision", "deferred")}
        missed = [i for i in self.injects if i["id"] not in decided]
        owners = {}
        for r in self.rows:
            if r["kind"] == "decision":
                owners[r["owner"]] = owners.get(r["owner"], 0) + 1
        L = [f"# Tabletop summary — team {self.a.team}", "",
             f"Case: {self.data['case']} ({self.data.get('incident', '')}). Scenario times are UTC.",
             f"Mode: {'manual' if self.a.manual else f'timed, {self.a.speed:g}x'}. "
             f"Generated {iso(datetime.now(UTC).replace(microsecond=0))}.", "",
             "## Aware moment", ""]
        if self.aware:
            L += [f"- **{iso(self.aware)}** — {self.aware_why}", "", "| Clock | Deadline (UTC) |", "|---|---|"]
            for name, dl in reg_clocks(self.aware):
                L.append(f"| {name} | {iso(dl) if dl else 'without undue delay'} |")
            L += ["", "*EU baseline (NIS2 art. 23, GDPR arts. 33/34). Check current CNCS guidance for the "
                      "Portuguese procedure. The insurer clock is the policy's.*"]
        else:
            L += ["- **Not recorded.** Your regulatory clocks never started on paper — they started anyway."]
        L += ["", "## Decisions", "", "| Inject | Arrived | Decided | Min | Owner | Decision |", "|---|---|---|---|---|---|"]
        for r in self.rows:
            if r["kind"] in ("decision", "deferred"):
                dec = r["decision"].replace("|", "/")
                if r["kind"] == "deferred":
                    dec = "DEFERRED: " + dec
                L.append(f"| {r['inject_id']} | {r['released_scenario_utc'][11:16]} | "
                         f"{r['decision_time_utc'][11:16]} | {r['minutes_to_decide']} | {r['owner']} | {dec} |")
        L += ["", "## Owners", ""]
        for o, n in sorted(owners.items(), key=lambda kv: -kv[1]):
            L.append(f"- {o}: {n}")
        if owners and max(owners.values()) > 0.6 * sum(owners.values()) and sum(owners.values()) >= 5:
            L.append("- One owner took most decisions. Is that the incident manager doing everything, "
                     "or a team that never delegated?")
        L += ["", "## For the debrief", ""]
        if missed:
            L.append("- Injects with no decision: " + ", ".join(f"{i['id']} ({i['title']})" for i in missed))
        L += [f"- {x}" for x in self.flags]
        if not missed and not self.flags:
            L.append("- Nothing flagged automatically. The interesting mistakes are never the automatic ones.")
        L += ["", "Questions to answer in writing:", "",
              "1. Which decision would you change, now that you know what came later? Why?",
              "2. Which decision had no clear owner in your organisation chart, and who should own it?",
              "3. What did you need that you did not have (a contact, a document, an authority)?", ""]
        return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description="Timed tabletop exercise with a decision log.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Usage")[1])
    p.add_argument("--team", default="team", help="team name (goes in the log and the output folder)")
    p.add_argument("--injects", type=Path, default=DEFAULT_INJECTS)
    p.add_argument("--speed", type=float, default=8.0, help="scenario minutes per real minute (default 8)")
    p.add_argument("--manual", action="store_true", help="release each inject with Enter; no clock pressure")
    p.add_argument("--out", help="output folder (default work/tabletop-<team>-<stamp>)")
    p.add_argument("--list", action="store_true", help="print inject times and titles, then exit")
    a = p.parse_args()
    if a.speed <= 0:
        p.error("--speed must be positive")
    data = json.loads(a.injects.read_text(encoding="utf-8"))
    if a.list:
        for i in data["injects"]:
            print(f"{i['time_utc'][11:16]}  {i['id']}  {i['title']}  ({i['from']}, {i['channel']})")
        return
    Session(a, data).run()


if __name__ == "__main__":
    main()

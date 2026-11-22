#!/usr/bin/env python3
"""clocks.py — notification deadlines for a significant incident in Portugal.

Computes, from the moment the entity became AWARE (concluded that there is, or
may be, a significant incident) and, later, from the moment the significant
impact ENDED, the deadlines of:

  Portugal — Regime Jurídico da Cibersegurança (RJC, annex to DL 125/2025), to the CNCS via MyCiber
    art. 42.º n.º 1   notificação inicial                          aware + 24 h
    art. 42.º n.º 3   update of the initial notification ("when necessary")   aware + 72 h
    art. 43.º         notificação do fim de impacto significativo  impact end + 24 h
    art. 44.º n.º 1   relatório final                              30 dias úteis after the
                                                                   end-of-impact NOTIFICATION
  GDPR (to the CNPD and to the people affected)
    art. 33           breach notification                          aware + 72 h ("where feasible")
    art. 34           communication to data subjects (high risk)   without undue delay
  RJC art. 48.º       communication to recipients of the service   without undue delay
  Insurer             written notice                               per policy (default 48 h)
  EU baseline — Directive (EU) 2022/2555 art. 23(4), for comparison
    (a) early warning 24 h · (b) incident notification 72 h · (d) final report one
    month after (b)

Times are printed in UTC and in Europe/Lisbon, with the weekday: 72 hours from a
Wednesday morning is a Saturday morning, and Portugal moves to summer time at the
end of March.

Working days ("dias úteis"): Monday to Friday, minus the Portuguese NATIONAL
holidays listed in PT_HOLIDAYS below. Counting starts on the day after the
end-of-impact notification, and the deadline is the end of the 30th working day,
Lisbon time. Municipal holidays are not in the list, and counting conventions are
a legal question: confirm both with counsel before you rely on the date.

Examples:
  ./clocks.py --aware "2026-03-11 08:31Z"
  ./clocks.py --aware "2026-03-11 08:31Z" --alt "2026-03-11 08:20Z"
  ./clocks.py --aware "2026-03-11 08:31Z" --impact-end "2026-03-16 17:00Z"
  ./clocks.py --aware "2026-03-11 08:31Z" --impact-end "2026-03-16 17:00Z" \\
              --now "2026-03-17 12:00Z" --submitted pt-initial=2026-03-12T08:52Z
  ./clocks.py --aware "2026-03-11 08:31Z" --impact-end "..." --markdown > work/clocks.md

What it refuses, and why:
  * a timestamp with no time zone. "08:31" on which clock? Add Z, an offset, or
    --input-tz. Portugal is UTC+0 in winter and UTC+1 in summer; guessing is how
    deadlines are missed by exactly one hour.
  * --basis confirmed. The RJC clock starts when the entity concludes that a
    significant incident exists OR MAY COME TO EXIST (art. 42.º n.º 1), not when
    the investigation is finished.

Format, procedure and taxonomy of the notifications are set by a CNCS
"instrução técnica" (RJC art. 41.º n.º 4): check the current one on the CNCS
site. This script computes dates; it is not legal advice.

Standard library only. Python 3.9+ (zoneinfo; on systems without tz data the
Lisbon column is left empty and the end of the working day is taken in UTC).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime, time, timedelta, timezone

UTC = timezone.utc

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # Python < 3.9
    ZoneInfo = None
    ZoneInfoNotFoundError = Exception

# Portuguese national holidays (Código do Trabalho list: 1 Jan, Good Friday,
# Easter Sunday, 25 Apr, 1 May, Corpus Christi, 10 Jun, 15 Aug, 5 Oct, 1 Nov,
# 1 Dec, 8 Dec, 25 Dec). Carnival is not a national holiday. Municipal holidays
# (e.g. the entity's own municipality) are NOT here. Extend the list if you need
# other years: the script refuses to count through a year it does not know.
PT_HOLIDAYS = {
    2025: ["2025-01-01", "2025-04-18", "2025-04-20", "2025-04-25", "2025-05-01", "2025-06-10",
           "2025-06-19", "2025-08-15", "2025-10-05", "2025-11-01", "2025-12-01", "2025-12-08",
           "2025-12-25"],
    2026: ["2026-01-01", "2026-04-03", "2026-04-05", "2026-04-25", "2026-05-01", "2026-06-04",
           "2026-06-10", "2026-08-15", "2026-10-05", "2026-11-01", "2026-12-01", "2026-12-08",
           "2026-12-25"],
    2027: ["2027-01-01", "2027-03-26", "2027-03-28", "2027-04-25", "2027-05-01", "2027-05-27",
           "2027-06-10", "2027-08-15", "2027-10-05", "2027-11-01", "2027-12-01", "2027-12-08",
           "2027-12-25"],
}
HOLIDAYS = {date.fromisoformat(d) for ds in PT_HOLIDAYS.values() for d in ds}

WORKING_DAYS_FINAL = 30          # RJC art. 44.º n.º 1
TWO_HOURS = timedelta(hours=2)   # RJC art. 41.º n.º 2


def get_tz(name: str):
    if ZoneInfo is None:
        return None
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return None


TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_ts(s: str, input_tz: str | None) -> datetime:
    m = TS_RE.match(s.strip())
    if not m:
        raise ValueError(f"cannot read '{s}': use 'YYYY-MM-DD HH:MM[:SS]Z' (or an offset like +01:00)")
    day, clock, zone = m.groups()
    if len(clock) == 5:
        clock += ":00"
    dt = datetime.strptime(f"{day} {clock}", "%Y-%m-%d %H:%M:%S")
    if zone == "Z":
        return dt.replace(tzinfo=UTC)
    if zone:
        zone = zone.replace(":", "")
        sign = 1 if zone[0] == "+" else -1
        off = timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5])) * sign
        return dt.replace(tzinfo=timezone(off)).astimezone(UTC)
    if input_tz:
        tz = get_tz(input_tz)
        if tz is None:
            raise ValueError(f"unknown time zone '{input_tz}' (is tzdata installed?)")
        return dt.replace(tzinfo=tz).astimezone(UTC)
    raise ValueError(
        f"'{s}' has no time zone. Which clock is that?\n"
        "       Add Z for UTC (e.g. '2026-03-11 08:31Z'), an offset (+01:00),\n"
        "       or say --input-tz Europe/Lisbon. A deadline computed from a guessed\n"
        "       zone is wrong by exactly the hour nobody checks.")


def add_months(dt: datetime, n: int) -> datetime:
    """Calendar month, clamped (31 Jan + 1 month = 28/29 Feb). 'One month' in EU
    law is a calendar month, not 30 days."""
    y, m = divmod(dt.month - 1 + n, 12)
    y, m = dt.year + y, m + 1
    for d in (dt.day, 30, 29, 28):
        try:
            return dt.replace(year=y, month=m, day=d)
        except ValueError:
            continue
    raise ValueError("unreachable")


def add_working_days(start: date, n: int) -> tuple[date, list[date]]:
    """The n-th Portuguese working day AFTER `start` (start itself is not counted).
    Also returns the holidays that fell on weekdays inside the window, so the
    output can show the reader which ones moved the date."""
    d, counted, skipped = start, 0, []
    while counted < n:
        d += timedelta(days=1)
        if d.year not in PT_HOLIDAYS:
            raise ValueError(f"no holiday list for {d.year}: add it to PT_HOLIDAYS before counting through it")
        if d.weekday() >= 5:
            continue
        if d in HOLIDAYS:
            skipped.append(d)
            continue
        counted += 1
    return d, skipped


def end_of_day(d: date, tz) -> datetime:
    """23:59:59 local time on that date, as UTC. Without tz data: 23:59:59Z."""
    if tz is None:
        return datetime.combine(d, time(23, 59, 59), tzinfo=UTC)
    return datetime.combine(d, time(23, 59, 59), tzinfo=tz).astimezone(UTC)


def human(td: timedelta) -> str:
    s = int(td.total_seconds())
    sign = "-" if s < 0 else ""
    s = abs(s)
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    return sign + (f"{d}d " if d else "") + f"{h}h{m:02d}m"


# Every row: key, section, obligation, basis, recipient.
OBLIGATIONS = [
    ("pt-initial", "PT", "Notificação inicial", "RJC art. 42.º n.º 1", "CNCS (MyCiber)"),
    ("pt-update", "PT", "Update of the initial notification", "RJC art. 42.º n.º 3 (when necessary)", "CNCS (MyCiber)"),
    ("pt-end", "PT", "Notificação do fim de impacto significativo", "RJC art. 43.º n.º 1", "CNCS (MyCiber)"),
    ("pt-final", "PT", "Relatório final", "RJC art. 44.º n.º 1 (30 dias úteis)", "CNCS (MyCiber)"),
    ("gdpr-33", "GDPR", "Personal data breach notification", "GDPR art. 33", "CNPD"),
    ("gdpr-34", "GDPR", "Communication to data subjects", "GDPR art. 34 (if high risk)", "the people affected"),
    ("pt-48", "OTHER", "Communication to recipients of the service", "RJC art. 48.º", "customers"),
    ("insurer", "OTHER", "Insurer written notice", "policy clause", "insurer (contract, not law)"),
    ("eu-early", "EU", "Early warning", "Dir. 2022/2555 art. 23(4)(a)", "CSIRT / authority"),
    ("eu-notification", "EU", "Incident notification", "art. 23(4)(b)", "CSIRT / authority"),
    ("eu-final", "EU", "Final report", "art. 23(4)(d): 1 month after (b)", "CSIRT / authority"),
]
KEYS = [o[0] for o in OBLIGATIONS]
SECTIONS = [
    ("PT", "Portugal — RJC (annex to DL 125/2025), to the CNCS"),
    ("GDPR", "Personal data — GDPR"),
    ("OTHER", "Other recipients"),
    ("EU", "EU baseline — NIS2 Directive art. 23, for comparison only"),
]


def compute(aware, impact_end, detected, submitted, insurer_hours, now, tz):
    """Return one dict per obligation: deadline (or None), a note, and a status."""
    rows = []
    two_hour_rule = impact_end is not None and impact_end - detected <= TWO_HOURS
    for key, section, name, basis, to in OBLIGATIONS:
        dl, note = None, ""
        if key == "pt-initial":
            dl = aware + timedelta(hours=24)
            if two_hour_rule:
                dl, note = None, "not required: resolved within 2 h of detection (art. 41.º n.º 2)"
        elif key == "pt-update":
            dl = aware + timedelta(hours=72)
            note = "only when necessary — decide and record why"
            if two_hour_rule:
                dl, note = None, "not required: resolved within 2 h of detection (art. 41.º n.º 2)"
        elif key == "pt-end":
            if impact_end is None:
                note = "give --impact-end when the significant impact ends"
            else:
                dl = impact_end + timedelta(hours=24)
        elif key == "pt-final":
            if impact_end is None:
                note = "runs from the end-of-impact notification (needs --impact-end)"
            else:
                base = submitted.get("pt-end")
                if base is None:
                    base = impact_end + timedelta(hours=24)
                    note = "ASSUMED end-of-impact notification sent at its deadline (pass --submitted pt-end=…); "
                local_base = base.astimezone(tz).date() if tz else base.date()
                day, skipped = add_working_days(local_base, WORKING_DAYS_FINAL)
                dl = end_of_day(day, tz)
                hol = ", ".join(h.strftime("%d %b") for h in skipped)
                note += (f"counted from {local_base.isoformat()} (not included); "
                         f"holidays skipped: {hol or 'none'}; end of day, Lisbon")
        elif key == "gdpr-33":
            dl = aware + timedelta(hours=72)
            note = "'where feasible'; if later, say why (art. 33(1))"
        elif key in ("gdpr-34", "pt-48"):
            note = "without undue delay — no fixed hours"
        elif key == "insurer":
            dl = aware + timedelta(hours=insurer_hours)
            note = f"{insurer_hours} h — read YOUR policy wording"
        elif key == "eu-early":
            dl = aware + timedelta(hours=24)
        elif key == "eu-notification":
            dl = aware + timedelta(hours=72)
        elif key == "eu-final":
            base = submitted.get("eu-notification", aware + timedelta(hours=72))
            dl = add_months(base, 1)
        row = {"key": key, "section": section, "obligation": name, "basis": basis, "recipient": to,
               "deadline_utc": dl.strftime("%Y-%m-%dT%H:%M:%SZ") if dl else None, "deadline": dl,
               "note": note.strip()}
        if key in submitted:
            sub = submitted[key]
            row["submitted_utc"] = sub.strftime("%Y-%m-%dT%H:%M:%SZ")
            if dl:
                row["status"] = "ON TIME" if sub <= dl else f"LATE by {human(sub - dl)}"
            else:
                row["status"] = f"sent {human(sub - aware)} after awareness"
        elif section == "EU":
            row["status"] = "(comparison)"
        elif now and dl:
            left = dl - now
            row["status"] = f"{human(left)} left" if left.total_seconds() >= 0 else f"OVERDUE by {human(-left)}"
        elif dl is None and key in ("gdpr-34", "pt-48"):
            row["status"] = "act now, record when and why"
        else:
            row["status"] = ""
        rows.append(row)
    return rows, two_hour_rule


def fmt_utc(dt):
    return dt.strftime("%a %d %b %H:%MZ") if dt else "—"


def fmt_local(dt, tz) -> str:
    if dt is None:
        return "—"
    if tz is None:
        return "(no tzdata)"
    loc = dt.astimezone(tz)
    off = loc.strftime("%z")
    return f"{loc.strftime('%a %d %b %H:%M')} ({off[:3]}:{off[3:]})"


def print_table(title, aware, impact_end, rows, tz, tzname, now, show_eu):
    print()
    head = f"== {title}: aware {aware.strftime('%a %Y-%m-%d %H:%M:%SZ')}"
    if impact_end:
        head += f" · impact ended {impact_end.strftime('%a %Y-%m-%d %H:%MZ')}"
    if now:
        head += f"   (as of {now.strftime('%Y-%m-%d %H:%MZ')})"
    print(head)
    w = [44, 20, 26]
    for sec, sec_title in SECTIONS:
        if sec == "EU" and not show_eu:
            continue
        print(f"\n  {sec_title}")
        print(f"  {'obligation':<{w[0]}} {'deadline (UTC)':<{w[1]}} {('deadline (' + tzname + ')'):<{w[2]}} status")
        print("  " + "-" * (sum(w) + 20))
        for r in rows:
            if r["section"] != sec:
                continue
            dl = r["deadline"]
            utc_s = fmt_utc(dl) if dl else ("without undue delay" if r["key"] in ("gdpr-34", "pt-48") else "—")
            print(f"  {r['obligation']:<{w[0]}} {utc_s:<{w[1]}} {fmt_local(dl, tz):<{w[2]}} {r['status']}")
            if r["note"]:
                print(f"  {'':<4}↳ {r['basis']}: {r['note']}")


def print_markdown(scenarios, tz, tzname, now, show_eu):
    for title, aware, impact_end, rows in scenarios:
        asof = f" — status as of {now.strftime('%Y-%m-%d %H:%MZ')}" if now else ""
        imp = f", impact ended {impact_end.strftime('%Y-%m-%d %H:%MZ')}" if impact_end else ""
        print(f"### {title} — aware {aware.strftime('%Y-%m-%d %H:%M:%SZ')}{imp}{asof}\n")
        print(f"| Obligation | Basis | Recipient | Deadline (UTC) | Deadline ({tzname}) | Status | Note |")
        print("|---|---|---|---|---|---|---|")
        for r in rows:
            if r["section"] == "EU" and not show_eu:
                continue
            dl = r["deadline"]
            name = r["obligation"] + (" *(EU baseline)*" if r["section"] == "EU" else "")
            print(f"| {name} | {r['basis']} | {r['recipient']} | "
                  f"{dl.strftime('%a %Y-%m-%d %H:%MZ') if dl else 'without undue delay' if r['key'] in ('gdpr-34', 'pt-48') else '—'} | "
                  f"{fmt_local(dl, tz)} | {r['status']} | {r['note']} |")
        print()
    print("> Format, procedure and taxonomy: CNCS *instrução técnica* (RJC art. 41.º n.º 4) — "
          "version checked: ______ (date). Working days exclude weekends and the national "
          "holidays listed in clocks.py; municipal holidays and counting rules confirmed with: ______.")


CAVEAT = """
  !! Format, procedure and taxonomy of the CNCS notifications come from a CNCS
  !! instrução técnica (RJC art. 41.º n.º 4): check the current one on cncs.gov.pt.
  !! Other notifications are NOT replaced by these (RJC art. 40.º n.º 5: Ministério
  !! Público, Polícia Judiciária, CNPD, GNS...). The insurer deadline is a contract.
  !! Dates, not legal advice: confirm working-day counting with counsel."""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Notification deadlines for a significant incident in Portugal (RJC / CNCS), "
                    "GDPR and the insurer, with the EU baseline for comparison.",
        epilog="Example: ./clocks.py --aware '2026-03-11 08:31Z' --impact-end '2026-03-16 17:00Z'\n"
               "Submission keys: " + ", ".join(KEYS),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--aware", required=True,
                    help="when the entity concluded there is, or may be, a significant incident (e.g. '2026-03-11 08:31Z')")
    ap.add_argument("--basis", choices=["aware", "detected", "confirmed"], default="aware",
                    help="what the --aware timestamp actually is (default: aware)")
    ap.add_argument("--alt", help="an alternative awareness time to compare (e.g. an earlier, defensible one)")
    ap.add_argument("--impact-end", help="when the significant impact ended (starts the art. 43.º clock)")
    ap.add_argument("--detected", help="when the incident was detected, for the 2-hour rule (default: --aware)")
    ap.add_argument("--now", help="evaluate time left as of this moment")
    ap.add_argument("--submitted", action="append", default=[], metavar="KEY=TIME",
                    help="mark something as sent, e.g. pt-initial=2026-03-12T08:52Z (repeatable)")
    ap.add_argument("--insurer-hours", type=int, default=48, help="policy notice period in hours (default 48)")
    ap.add_argument("--no-eu", action="store_true", help="hide the EU-baseline comparison rows")
    ap.add_argument("--tz", default="Europe/Lisbon", help="local time zone to display (default Europe/Lisbon)")
    ap.add_argument("--input-tz", help="interpret timestamps WITHOUT a zone in this zone (otherwise they are refused)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--markdown", action="store_true", help="a table for your communication pack")
    a = ap.parse_args(argv)

    if a.basis == "confirmed":
        print("refused: --basis confirmed.\n"
              "  The CNCS clock starts when the entity concludes that a significant incident\n"
              "  exists OR MAY COME TO EXIST (RJC art. 42.º n.º 1) — not when the investigation\n"
              "  is finished. GDPR art. 33 likewise runs from awareness. The initial notification\n"
              "  is meant to go with what you know at the time.\n"
              "  Work out when a person with authority could reasonably conclude that, write down\n"
              "  why, and pass that as --aware.", file=sys.stderr)
        return 2

    try:
        aware = parse_ts(a.aware, a.input_tz)
        alt = parse_ts(a.alt, a.input_tz) if a.alt else None
        impact_end = parse_ts(a.impact_end, a.input_tz) if a.impact_end else None
        detected = parse_ts(a.detected, a.input_tz) if a.detected else aware
        now = parse_ts(a.now, a.input_tz) if a.now else None
        submitted = {}
        for s in a.submitted:
            if "=" not in s:
                raise ValueError(f"--submitted wants KEY=TIME, got '{s}'")
            k, v = s.split("=", 1)
            if k not in KEYS:
                raise ValueError(f"unknown key '{k}'. Use one of: {', '.join(KEYS)}")
            submitted[k] = parse_ts(v, a.input_tz)
        if impact_end and impact_end < detected:
            raise ValueError("--impact-end is before the incident was detected/aware: check both times")
        if "pt-end" in submitted and impact_end is None:
            raise ValueError("pt-end was submitted, but there is no --impact-end: when did the impact end?")
        tz = get_tz(a.tz)
        if tz is None and not a.json:
            print(f"warning: time zone '{a.tz}' not available (install tzdata); local column left empty, "
                  "end of working day taken in UTC", file=sys.stderr)
        scenarios = []
        for title, aw in (("Declared awareness", aware), ("Alternative awareness", alt)):
            if aw is None:
                continue
            det = detected if a.detected else aw
            rows, two_h = compute(aw, impact_end, det, submitted, a.insurer_hours, now, tz)
            scenarios.append((title, aw, impact_end, rows, two_h))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    show_eu = not a.no_eu
    if a.json:
        out = [{"scenario": t, "aware_utc": aw.strftime("%Y-%m-%dT%H:%M:%SZ"), "basis": a.basis,
                "impact_end_utc": ie.strftime("%Y-%m-%dT%H:%M:%SZ") if ie else None,
                "two_hour_rule": two_h,
                "obligations": [{k: v for k, v in r.items() if k != "deadline"} for r in rows
                                if show_eu or r["section"] != "EU"]}
               for t, aw, ie, rows, two_h in scenarios]
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    if a.markdown:
        print_markdown([(t, aw, ie, rows) for t, aw, ie, rows, _ in scenarios], tz, a.tz, now, show_eu)
        return 0

    if a.basis == "detected":
        print("note: --basis detected. A tool raising an alert is not automatically awareness; a\n"
              "      person able to conclude there is (or may be) a significant incident is. Justify it.")
    for t, aw, ie, rows, two_h in scenarios:
        print_table(t, aw, ie, rows, tz, a.tz, now, show_eu)
        if two_h:
            print("\n  2-hour rule: the impact ended within 2 h of detection, so only the end-of-impact\n"
                  "  notification is due (RJC art. 41.º n.º 2). Record the detection time carefully.")
    if alt:
        d = aware - alt
        print(f"\n  The alternative moves every awareness-based deadline {human(abs(d))} "
              f"{'earlier' if d.total_seconds() > 0 else 'later'}. If you can defend the earlier one, plan to it.")
    if impact_end is None:
        print("\n  No --impact-end yet: the end-of-impact notification and the final report cannot be dated.\n"
              "  The final report counts from the date the end-of-impact NOTIFICATION is sent, not from awareness.")
    print(CAVEAT)
    rows_all = [r for *_, rows, _ in scenarios for r in rows if show_eu or r["section"] != "EU"]
    weekend = sorted({r["obligation"] for r in rows_all if r["deadline"] and r["deadline"].weekday() >= 5})
    if weekend:
        print(f"\n  Weekend deadlines: {', '.join(weekend)}. Hours do not stop on Saturdays.")
    if tz is not None:
        offs = {r["deadline"].astimezone(tz).utcoffset() for r in rows_all if r["deadline"]}
        if len(offs) > 1:
            print(f"  The {a.tz} offset changes between these deadlines (summer time). "
                  "UTC in the notification, local time in the calendar invite.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

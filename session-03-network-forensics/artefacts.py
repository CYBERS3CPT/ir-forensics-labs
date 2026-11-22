#!/usr/bin/env python3
"""artefacts.py — small, honest helpers for a Windows triage package.

  ./artefacts.py webkit 13417605956896604          Chrome/Edge time -> UTC
  ./artefacts.py webkit --to "2026-03-10 08:41:19Z"  UTC -> Chrome/Edge time
  ./artefacts.py filetime 134177053168966040       Windows FILETIME -> UTC
  ./artefacts.py decode-ps <base64>                 decode a powershell -enc argument (UTF-16LE)
  ./artefacts.py history <path/to/History>          Edge/Chrome visits + downloads, read-only
  ./artefacts.py timeline <triage dir>              every timestamp in the package, one UTC timeline
  ./artefacts.py timeline <triage dir> --skew WS-FIN-07=+SECONDS --from "2026-03-10 08:30" --to "2026-03-10 12:00"

  The WS-FIN-07 package (exhibit EXH-WSFIN07-01) stays in the Session 2 folder:
  T=../session-02-communication-and-collection/evidence/WS-FIN-07_triage
  ./artefacts.py timeline $T

The timeline has a `clock` column, and that column is the point. A timestamp
is only as good as the clock that wrote it: WS-FIN-07's own artefacts carry
WS-FIN-07's clock, a shortcut file carries the clock of the machine that
CREATED the shortcut, and Shimcache times are file-modification times, not
executions. --skew HOST=+SECONDS corrects only rows written by that host's
clock (host time = true time + SECONDS), and says so in every row.

Standard library only. Opens databases read-only (SQLite URI immutable=1) so
that looking at evidence does not change it.
"""
from __future__ import annotations

import argparse
import base64
import csv
import glob
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

UTC = timezone.utc
EPOCH1601 = datetime(1601, 1, 1, tzinfo=UTC)


# --- conversions -----------------------------------------------------------
def from_webkit(v: int) -> datetime:
    """Chrome/Edge: microseconds since 1601-01-01 UTC."""
    return EPOCH1601 + timedelta(microseconds=int(v))


def to_webkit(dt: datetime) -> int:
    d = dt - EPOCH1601
    return (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds


def from_filetime(v: int) -> datetime:
    """Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC."""
    return EPOCH1601 + timedelta(microseconds=int(v) // 10)


def parse_ez(s: str) -> datetime | None:
    """EZ tools write 'yyyy-MM-dd HH:mm:ss[.fffffff]', UTC as the SOURCE recorded it."""
    s = (s or "").strip()
    if not s:
        return None
    m = re.match(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d+))?$", s)
    if not m:
        return None
    dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    if m.group(3):
        dt += timedelta(microseconds=int(m.group(3)[:6].ljust(6, "0")))
    return dt


def parse_user(s: str) -> datetime:
    s = s.strip().replace("T", " ")
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?)(Z)?$", s)
    if not m:
        raise SystemExit(f"error: cannot read '{s}' — use 'YYYY-MM-DD HH:MM[:SS][Z]' (always UTC)")
    v = m.group(1) + (":00" if len(m.group(1)) == 16 else "")
    return datetime.strptime(v, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def fmt(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S") + (f".{dt.microsecond // 1000:03d}" if dt.microsecond else ".000") + "Z"


TRANSITIONS = {0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME", 4: "MANUAL_SUBFRAME",
               5: "GENERATED", 6: "AUTO_TOPLEVEL", 7: "FORM_SUBMIT", 8: "RELOAD", 9: "KEYWORD",
               10: "KEYWORD_GENERATED"}
QUALIFIERS = [(0x01000000, "FORWARD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"), (0x04000000, "HOME_PAGE"),
              (0x08000000, "FROM_API"), (0x10000000, "CHAIN_START"), (0x20000000, "CHAIN_END"),
              (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT")]


def transition(v: int) -> str:
    core = TRANSITIONS.get(v & 0xFF, str(v & 0xFF))
    q = [n for bit, n in QUALIFIERS if v & bit]
    return core + ("|" + "|".join(q) if q else "")


DL_STATE = {0: "IN_PROGRESS", 1: "COMPLETE", 2: "CANCELLED", 3: "BUG_22", 4: "INTERRUPTED"}


def open_ro(path: str) -> sqlite3.Connection:
    """Read-only AND immutable: no journal, no WAL replay, no lock files next to the evidence."""
    if not os.path.isfile(path):
        raise SystemExit(f"error: no such file: {path}")
    uri = "file:" + quote(os.path.abspath(path)) + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


# --- history -----------------------------------------------------------------
def history_rows(path: str):
    db = open_ro(path)
    out = []
    for vt, url, title, tr in db.execute(
            "SELECT v.visit_time, u.url, u.title, v.transition FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time"):
        out.append((from_webkit(vt), "visit", f"{url}  [{transition(tr)}]  \"{title}\"", vt))
    for (i, path_, st, en, rb, tb, state, opened, la, ref, site, tab, mime) in db.execute(
            "SELECT id,target_path,start_time,end_time,received_bytes,total_bytes,state,opened,last_access_time,"
            "referrer,site_url,tab_url,mime_type FROM downloads ORDER BY start_time"):
        chain = [r[0] for r in db.execute("SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index", (i,))]
        src = chain[-1] if chain else tab
        out.append((from_webkit(st), "download-start", f"{src} -> {path_} ({rb}/{tb} bytes, {mime}, "
                    f"{DL_STATE.get(state, state)}, referrer='{ref}')", st))
        if en:
            out.append((from_webkit(en), "download-end", f"{path_}", en))
        if opened and la:
            out.append((from_webkit(la), "download-opened", f"{path_} opened from the browser", la))
    db.close()
    return sorted(out, key=lambda r: r[0])


def cmd_history(a):
    rows = history_rows(a.path)
    print(f"# {a.path}\n# times as recorded by the browser host's clock (raw value in last column)")
    for dt, kind, detail, raw in rows:
        print(f"{fmt(dt)}  {kind:<16} {detail}  ({raw})")
    print(f"# {len(rows)} events. The URL of a file that was only DOWNLOADED is in `downloads`, not in `visits`.")


# --- timeline ----------------------------------------------------------------
class Ev:
    __slots__ = ("ts", "clock", "source", "kind", "detail")

    def __init__(self, ts, clock, source, kind, detail):
        self.ts, self.clock, self.source, self.kind, self.detail = ts, clock, source, kind, detail


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        yield from csv.DictReader(f)


def tl_pecmd(path, host):
    for r in read_csv(path):
        name = os.path.basename(r["SourceFilename"].replace("\\", "/"))
        runs = [r.get("LastRun")] + [r.get(f"PreviousRun{i}") for i in range(7)]
        for i, v in enumerate(runs):
            dt = parse_ez(v or "")
            if dt:
                yield Ev(dt, host, "Prefetch", "run" if i else "run (last)",
                         f"{r['ExecutableName']} ({name}, RunCount {r['RunCount']})")


def tl_amcache(path, host):
    for r in read_csv(path):
        dt = parse_ez(r.get("FileKeyLastWriteTimestamp", ""))
        if dt:
            yield Ev(dt, host, "Amcache", "key last write",
                     f"{r['FullPath']}  SHA1={r['SHA1']}  \"{r.get('Description', '')}\"")


def tl_shim(path, host):
    for r in read_csv(path):
        dt = parse_ez(r.get("LastModifiedTimeUTC", ""))
        if dt:
            yield Ev(dt, host, "Shimcache", "FILE MODIFIED (not execution)", f"{r['Path']} (position {r['CacheEntryPosition']})")


def tl_lecmd(path, host):
    for r in read_csv(path):
        tgt = r.get("LocalPath") or (r.get("NetworkPath", "") + "\\" + r.get("CommonPath", ""))
        args = r.get("Arguments", "")
        if len(args) > 60:
            args = args[:60] + "…"
        lnk = r["SourceFile"]
        for col, kind in (("SourceCreated", "lnk created"), ("SourceModified", "lnk modified")):
            dt = parse_ez(r.get(col, ""))
            if dt and not (col == "SourceModified" and r.get("SourceModified") == r.get("SourceCreated")):
                yield Ev(dt, host, "LNK", kind, f"{lnk} -> {tgt} {args}".rstrip())
        # Target times are copied INTO the shortcut when it is made, from the file
        # system that held the target: the machine named in MachineID (an attacker's
        # build box, or the file server behind a share). That is another clock.
        mid = (r.get("MachineID") or "").lower()
        owner = host if mid == host.lower() else f"lnk-maker:{mid or '?'}"
        dt = parse_ez(r.get("TargetCreated", ""))
        if dt:
            yield Ev(dt, owner, "LNK", "target created (as stored in lnk)", f"{tgt}  [in {os.path.basename(lnk.replace(chr(92), '/'))}]")
        dt = parse_ez(r.get("TrackerCreatedOn", ""))
        if dt and owner != host:
            yield Ev(dt, owner, "LNK", "tracker created (maker's machine)",
                     f"MachineID={mid} MAC={r.get('MachineMACAddress')} ({r.get('MACVendor')})")


def tl_recmd(path, host):
    for r in read_csv(path):
        dt = parse_ez(r.get("LastWriteTimestamp", ""))
        if dt:
            vd = r.get("ValueData", "")
            yield Ev(dt, host, "Registry", f"KEY last write ({r.get('Description')})",
                     f"{r.get('HiveType')}\\{r.get('KeyPath')} : {r.get('ValueName')} = {vd} {r.get('ValueData2', '')}".rstrip())


def tl_mft(path, host):
    for r in read_csv(path):
        p = f"{r.get('ParentPath', '')}\\{r.get('FileName', '')}"
        flag = "" if r.get("InUse") == "True" else "  [DELETED record: InUse=False]"
        seen = {}
        for col, kind in (("Created0x10", "$SI created"), ("LastModified0x10", "$SI modified"),
                          ("Created0x30", "$FN created")):
            dt = parse_ez(r.get(col, ""))
            if not dt:
                continue
            if col == "Created0x30" and dt == seen.get("Created0x10"):
                continue   # $FN only interesting when it disagrees with $SI
            if col == "LastModified0x10" and dt == seen.get("Created0x10"):
                continue
            seen[col] = dt
            yield Ev(dt, host, "$MFT", kind, f"{p} ({r.get('FileSize')} B){flag}")


def tl_usn(path, host):
    for r in read_csv(path):
        dt = parse_ez(r.get("UpdateTimestamp", ""))
        if dt:
            yield Ev(dt, host, "$J", r.get("UpdateReasons", ""), f"{r.get('ParentPath')}\\{r.get('Name')}")


def tl_history(path, host):
    for dt, kind, detail, _raw in history_rows(path):
        yield Ev(dt, host, "Edge", kind, detail)


PARSERS = [("*_PECmd_Output.csv", tl_pecmd), ("*_Amcache_UnassociatedFileEntries.csv", tl_amcache),
           ("*_AppCompatCache_Output.csv", tl_shim), ("*_LECmd_Output.csv", tl_lecmd),
           ("*_RECmd_Batch_*_Output.csv", tl_recmd), ("*_MFTECmd_$MFT_Output.csv", tl_mft),
           ("*_MFTECmd_$J_Output.csv", tl_usn), ("History", tl_history)]


def cmd_timeline(a):
    base = a.dir
    if not os.path.isdir(base):
        raise SystemExit(f"error: not a directory: {base}")
    host = a.host or os.path.basename(os.path.normpath(base)).split("_")[0]
    skews = {}
    for s in a.skew:
        m = re.match(r"^([^=]+)=([+-]?\d+(?:\.\d+)?)$", s)
        if not m:
            raise SystemExit(f"error: --skew wants HOST=+SECONDS (host clock minus true time), got '{s}'")
        skews[m.group(1)] = float(m.group(2))
    evs, used = [], []
    for pattern, fn in PARSERS:
        for p in sorted(glob.glob(os.path.join(glob.escape(base), "**", pattern), recursive=True)):
            used.append(os.path.relpath(p, base))
            evs.extend(fn(p, host))
    if not evs:
        raise SystemExit("error: found no parsable artefacts under " + base)
    rows = []
    for e in evs:
        off = skews.get(e.clock)
        corr = e.ts - timedelta(seconds=off) if off is not None else e.ts
        note = f"{e.clock}{'' if off is None else f' {off:+g}s corrected'}"
        rows.append((corr, e.ts, note, e.source, e.kind, e.detail))
    if a.since:
        rows = [r for r in rows if r[0] >= parse_user(a.since)]
    if a.until:
        rows = [r for r in rows if r[0] <= parse_user(a.until)]
    if a.grep:
        rx = re.compile(a.grep, re.I)
        rows = [r for r in rows if rx.search(" ".join(map(str, r[2:])))]
    if a.exclude:
        rx = re.compile(a.exclude, re.I)
        rows = [r for r in rows if not rx.search(" ".join(map(str, r[2:])))]
    rows.sort(key=lambda r: (r[0], r[3]))

    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["utc", "as_recorded", "clock", "source", "event", "detail"])
            for r in rows:
                w.writerow([fmt(r[0]), fmt(r[1]), r[2], r[3], r[4], r[5]])
        print(f"wrote {len(rows)} rows to {a.csv}", file=sys.stderr)
        return
    print(f"# timeline of {base}  (host clock: {host})")
    print("# parsed: " + ", ".join(used))
    if skews:
        print("# skew applied: " + ", ".join(f"{k} {v:+g}s" for k, v in skews.items())
              + " — rows from other clocks are NOT corrected")
    else:
        print(f"# NO skew applied: every time is AS RECORDED by its clock. Have you checked {host}'s clock?")
    print(f"{'utc':<25} {'clock':<26} {'source':<9} {'event':<30} detail")
    w = None if a.wide else 110
    for r in rows:
        d = r[5] if w is None or len(r[5]) <= w else r[5][:w - 1] + "…"
        print(f"{fmt(r[0]):<25} {r[2]:<26} {r[3]:<9} {r[4][:30]:<30} {d}")
    print(f"# {len(rows)} events")


def cmd_webkit(a):
    if a.to:
        print(to_webkit(parse_user(a.to)))
    else:
        for v in a.value:
            print(f"{v}  ->  {fmt(from_webkit(int(v)))}   (UTC as recorded by the writing host's clock)")


def cmd_filetime(a):
    for v in a.value:
        print(f"{v}  ->  {fmt(from_filetime(int(v, 0)))}")


def cmd_decode(a):
    data = a.b64.strip()
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        txt = raw.decode("utf-16-le")
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"error: not base64 UTF-16LE ({e}). PowerShell -enc is always UTF-16LE.")
    print(txt)
    print("\n# decoded only, never executed. Indicators in here are evidence: do not look them up online.", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Timestamp conversion, browser history and a skew-aware timeline for a triage package.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog="\n\n".join(__doc__.split("\n\n")[1:3]))
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("webkit", help="Chrome/Edge microseconds-since-1601 <-> UTC")
    w.add_argument("value", nargs="*"); w.add_argument("--to", help="convert this UTC time to WebKit instead")
    w.set_defaults(fn=cmd_webkit)
    f = sub.add_parser("filetime", help="Windows FILETIME -> UTC")
    f.add_argument("value", nargs="+"); f.set_defaults(fn=cmd_filetime)
    d = sub.add_parser("decode-ps", help="decode a PowerShell -enc / -EncodedCommand argument")
    d.add_argument("b64"); d.set_defaults(fn=cmd_decode)
    h = sub.add_parser("history", help="visits and downloads from a Chromium History database (read-only)")
    h.add_argument("path"); h.set_defaults(fn=cmd_history)
    t = sub.add_parser("timeline", help="merge every artefact in a triage folder into one UTC timeline")
    t.add_argument("dir")
    t.add_argument("--host", help="whose clock wrote the package (default: folder name before '_')")
    t.add_argument("--skew", action="append", default=[], metavar="HOST=+SECONDS",
                   help="host clock minus true time, e.g. HOST=+90 or HOST=-12.5 (repeatable)")
    t.add_argument("--from", dest="since", help="only events at/after this corrected UTC time")
    t.add_argument("--to", dest="until", help="only events at/before this corrected UTC time")
    t.add_argument("--grep", help="keep rows matching this regex (case-insensitive)")
    t.add_argument("--exclude", help="drop rows matching this regex")
    t.add_argument("--csv", help="write CSV here instead of printing")
    t.add_argument("--wide", action="store_true", help="do not truncate the detail column")
    t.set_defaults(fn=cmd_timeline)
    a = ap.parse_args(argv)
    if a.cmd == "webkit" and not a.value and not a.to:
        ap.error("webkit: give a value, or --to 'YYYY-MM-DD HH:MM:SSZ'")
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())

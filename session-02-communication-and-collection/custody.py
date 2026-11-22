#!/usr/bin/env python3
"""custody.py — a chain-of-custody record that refuses to have gaps.

A JSON record (machine-checkable) plus a printable text form (for the binder
and for signatures). Each entry is hash-chained to the one before it, so an
entry edited after the fact breaks the chain and `verify` says where.

  ./custody.py new --case INC-2026-007 --exhibit EXH-01 \\
        --description "triage package of WS-FIN-07" \\
        --collected-by "Sofia Teixeira (IT)" --when 2026-03-11T12:41:10Z \\
        --where "Finance, floor 1, Maia" --why "triage before reimaging, on IM instruction" \\
        --manifest evidence/WS-FIN-07_triage/MANIFEST.sha256 --seal CER-0412 \\
        -o custody-EXH-01.json

  ./custody.py transfer custody-EXH-01.json --from "Sofia Teixeira (IT)" \\
        --to "Rui Calado (IM)" --when 2026-03-11T12:58:00Z \\
        --why "storage in IT safe pending panel firm" --seal-in CER-0412 --seal-out CER-0412

  ./custody.py verify custody-EXH-01.json                 hashes vs manifest + chain integrity
  ./custody.py verify custody-EXH-01.json --record --by "Your Name"   ...and log that you did
  ./custody.py show custody-EXH-01.json [--text custody-EXH-01.txt]

What it refuses, and why:
  * an entry without WHO, WHEN or WHY. Each one missing is the question the
    other side's expert asks first.
  * a time without a zone, or in the future, or before the previous entry.
  * a transfer FROM someone who, according to the record, does not hold the
    exhibit. That is a gap, and one gap defeats the whole record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(Z|[+-]\d{2}:?\d{2})$")
VAGUE = {"", "-", "n/a", "na", "none", "?", "tbd", "todo", "same", "idem", "transfer", "custody"}


class Refused(Exception):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_when(s: str | None, field="--when") -> datetime:
    if not s:
        raise Refused(f"{field} is missing. WHEN did it happen? (UTC, e.g. 2026-03-11T12:58:00Z)")
    m = TS_RE.match(s.strip())
    if not m:
        raise Refused(f"{field} '{s}' needs a date, a time AND a zone, e.g. 2026-03-11T12:58:00Z. "
                      "A time without a zone is a time nobody can check.")
    d, t, z = m.groups()
    if len(t) == 5:
        t += ":00"
    dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S")
    if z == "Z":
        dt = dt.replace(tzinfo=UTC)
    else:
        z = z.replace(":", "")
        off = timedelta(hours=int(z[1:3]), minutes=int(z[3:5])) * (1 if z[0] == "+" else -1)
        dt = dt.replace(tzinfo=timezone(off)).astimezone(UTC)
    if dt > now_utc() + timedelta(minutes=5):
        raise Refused(f"{field} {iso(dt)} is in the future. Record things after they happen.")
    return dt


def need(value: str | None, what: str, question: str) -> str:
    if value is None or value.strip().lower() in VAGUE:
        raise Refused(f"{what} is missing or meaningless ('{value or ''}'). {question}")
    if what == "why" and len(value.strip()) < 10:
        raise Refused(f"why='{value}' is too thin. Say what the movement was FOR "
                      "(analysis, storage, transport to lab, return...). A court reads this line.")
    return value.strip()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(path: str) -> dict:
    """sha256sum format: '<64 hex>  relative/path' (or ' *path' for binary mode)."""
    files = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            m = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
            if not m:
                raise Refused(f"{path}:{n} is not a sha256sum line: {line[:60]!r}")
            files[m.group(2)] = m.group(1).lower()
    if not files:
        raise Refused(f"{path} lists no files")
    return files


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(path: str, rec: dict):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def append(rec: dict, entry: dict):
    entry["seq"] = len(rec["entries"]) + 1
    entry["recorded_utc"] = iso(now_utc())
    entry["prev_hash"] = rec["entries"][-1]["entry_hash"] if rec["entries"] else rec["manifest"]["sha256"]
    entry["entry_hash"] = entry_hash(entry)
    rec["entries"].append(entry)


def rel_base(manifest: str, record: str) -> str:
    base = os.path.dirname(os.path.abspath(manifest))
    rdir = os.path.dirname(os.path.abspath(record))
    try:
        if os.path.dirname(os.path.commonpath([base, rdir])) == os.path.commonpath([base, rdir]):
            return base         # nothing in common but the root (e.g. /mnt/case): absolute is clearer
        return os.path.relpath(base, rdir).replace(os.sep, "/")
    except ValueError:          # different drives on Windows: no relative path exists
        return base


def resolve_base(rec: dict, record_path: str) -> str:
    base = rec["manifest"]["base_dir"]
    if os.path.isabs(base):     # records made by older versions stored an absolute path
        return base
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(record_path)), base))


def holder(rec: dict) -> str:
    h = None
    for e in rec["entries"]:
        if e["type"] == "collected":
            h = e["who"]
        elif e["type"] == "transfer":
            h = e["to"]
    return h


def last_when(rec: dict) -> datetime | None:
    ws = [parse_when(e["when_utc"]) for e in rec["entries"] if e.get("when_utc")]
    return max(ws) if ws else None


# ---------------------------------------------------------------------------
def cmd_new(a):
    if os.path.exists(a.output) and not a.force:
        raise Refused(f"{a.output} exists. A custody record is appended to, never restarted (use --force only for a lab redo).")
    who = need(a.collected_by, "who (--collected-by)", "WHO collected it? Name and role.")
    when = parse_when(a.when)
    why = need(a.why, "why", "WHY was it collected? Under whose authority?")
    where = need(a.where, "where", "WHERE was it collected? Building, room, host.")
    need(a.description, "description", "WHAT is it? Host, media, serial, what it contains.")
    if not a.manifest:
        raise Refused("--manifest is missing. Without hashes there is nothing to keep custody OF.")
    files = read_manifest(a.manifest)
    rec = {
        "format": "ir-forensics-labs/custody v1",
        "case": need(a.case, "case", "Which case?"), "exhibit": need(a.exhibit, "exhibit", "Which exhibit ID?"),
        "description": a.description,
        # base_dir is stored RELATIVE to the record itself, so the record still verifies
        # when the record and the evidence move together (to the lab, to a reviewer, into
        # a zip) and it does not carry your home directory around.
        "manifest": {"path": a.manifest, "base_dir": rel_base(a.manifest, a.output),
                     "sha256": sha256_file(a.manifest), "file_count": len(files), "files": files},
        "entries": [],
    }
    append(rec, {"type": "collected", "when_utc": iso(when), "who": who, "where": where, "why": why,
                 "seal_out": a.seal or "", "method": a.method or "", "notes": a.notes or ""})
    save(a.output, rec)
    print(f"created {a.output}: {rec['exhibit']} · {len(files)} files · manifest sha256 {rec['manifest']['sha256'][:16]}…")
    print(f"holder now: {who}")


def cmd_transfer(a):
    rec = load(a.record)
    # Collect every problem before refusing: a student who fixes one thin field only to
    # discover the real gap on the next run learns the wrong lesson.
    problems = []

    def check(fn, *args):
        try:
            return fn(*args)
        except Refused as e:
            problems.append(str(e))
            return None

    frm = check(need, a.frm, "from", "WHO handed it over?")
    to = check(need, a.to, "to", "WHO received it?")
    when = check(parse_when, a.when)
    why = check(need, a.why, "why", "WHY did it move?")
    cur = holder(rec)
    if frm is not None and frm != cur:     # the gap in the hands goes first: it is the serious one
        problems.insert(0, f"the record says the exhibit is held by '{cur}', not '{frm}'.\n"
                        "  Either a transfer is missing (record it first) or the name is spelled differently.\n"
                        "  Both are gaps; fix the record, do not paper over it.")
    if frm is not None and frm == to:
        problems.append("from and to are the same person. If nothing moved, it is a note, not a transfer.")
    lw = last_when(rec)
    if when is not None and lw and when < lw:
        problems.append(f"{iso(when)} is BEFORE the previous entry ({iso(lw)}). Entries are recorded in order.")
    if problems:
        raise Refused("\n  ".join(problems) if len(problems) == 1 else
                      f"{len(problems)} problems:\n  - " + "\n  - ".join(problems))
    prev_seal = next((e.get("seal_out") for e in reversed(rec["entries"]) if e.get("seal_out")), "")
    if prev_seal and a.seal_in and a.seal_in != prev_seal:
        raise Refused(f"seal-in {a.seal_in} does not match the last recorded seal {prev_seal}. "
                      "If the seal was broken, say so with --seal-in BROKEN and explain in --notes.")
    append(rec, {"type": "transfer", "when_utc": iso(when), "from": frm, "to": to, "why": why,
                 "seal_in": a.seal_in or "", "seal_out": a.seal_out or "", "method": a.method or "",
                 "notes": a.notes or ""})
    save(a.record, rec)
    print(f"entry {len(rec['entries'])}: {frm} -> {to} at {iso(when)}; holder now: {to}")


def check_chain(rec: dict) -> list[str]:
    problems, prev = [], rec["manifest"]["sha256"]
    for e in rec["entries"]:
        if e.get("prev_hash") != prev:
            problems.append(f"entry {e.get('seq')}: prev_hash does not match entry {e.get('seq', 1) - 1}")
        if entry_hash(e) != e.get("entry_hash"):
            problems.append(f"entry {e.get('seq')}: content changed after it was recorded")
        prev = e.get("entry_hash")
    return problems


def cmd_verify(a):
    rec = load(a.record)
    base = a.dir or resolve_base(rec, a.record)
    files = rec["manifest"]["files"]
    ok = mism = miss = 0
    print(f"verifying {rec['exhibit']} — {len(files)} files under {base}")
    for rel, want in sorted(files.items()):
        p = os.path.join(base, rel)
        if not os.path.isfile(p):
            print(f"  MISSING   {rel}")
            miss += 1
            continue
        got = sha256_file(p)
        if got == want:
            ok += 1
            if a.verbose:
                print(f"  OK        {rel}")
        else:
            print(f"  MISMATCH  {rel}\n            expected {want}\n            found    {got}")
            mism += 1
    listed = set(files) | {os.path.basename(rec["manifest"]["path"])}
    extra = []
    for root, _, names in os.walk(base):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), base).replace(os.sep, "/")
            if rel not in listed:
                extra.append(rel)
    for x in sorted(extra):
        print(f"  EXTRA     {x}   (not in the manifest: say what it is, or why it is there)")
    chain = check_chain(rec)
    # The chain starts from the manifest's hash, but the file list inside the JSON is
    # only as good as that manifest: if the manifest file is still there, re-read it
    # and make sure nobody edited the expected hashes in the record by hand.
    mpath = os.path.join(base, os.path.basename(rec["manifest"]["path"]))
    if os.path.isfile(mpath):
        if sha256_file(mpath) != rec["manifest"]["sha256"]:
            chain.append(f"manifest {os.path.basename(mpath)} no longer has the hash recorded at collection")
        elif read_manifest(mpath) != files:
            chain.append("the file list in this record does not match the manifest it claims to come from")
    for c in chain:
        print(f"  CHAIN     {c}")
    result = "PASS" if mism == miss == 0 and not chain else "FAIL"
    print(f"\n  {ok} ok · {mism} mismatch · {miss} missing · {len(extra)} extra · chain {'intact' if not chain else 'BROKEN'}"
          f"  =>  {result}")
    if a.record_it:
        who = need(a.by, "who (--by)", "WHO verified it?")
        when = parse_when(a.when) if a.when else now_utc()
        lw = last_when(rec)
        if lw and when < lw:
            raise Refused(f"{iso(when)} is BEFORE the previous entry ({iso(lw)}). Entries are recorded in order.")
        append(rec, {"type": "verification", "when_utc": iso(when), "who": who,
                     "why": "hash verification against the manifest",
                     "result": f"{result}: {ok} ok, {mism} mismatch, {miss} missing, {len(extra)} extra",
                     "notes": a.notes or ""})
        save(a.record, rec)
        print(f"  recorded as entry {len(rec['entries'])} by {who}")
    return 0 if result == "PASS" else 1


def render(rec: dict) -> str:
    L = []
    L.append("CHAIN OF CUSTODY")
    L.append("=" * 78)
    L.append(f"Case:         {rec['case']}")
    L.append(f"Exhibit:      {rec['exhibit']}")
    L.append(f"Description:  {rec['description']}")
    m = rec["manifest"]
    L.append(f"Manifest:     {m['path']}  ({m['file_count']} files)")
    L.append(f"              sha256 {m['sha256']}")
    L.append(f"Holder now:   {holder(rec)}")
    L.append("")
    for e in rec["entries"]:
        L.append("-" * 78)
        L.append(f"#{e['seq']}  {e['type'].upper():<13} {e['when_utc']}      (recorded {e['recorded_utc']})")
        if e["type"] == "transfer":
            L.append(f"    from:   {e['from']}")
            L.append(f"    to:     {e['to']}")
        else:
            L.append(f"    who:    {e['who']}")
        for k in ("where", "why", "method", "result"):
            if e.get(k):
                L.append(f"    {k + ':':<7} {e[k]}")
        if e.get("seal_in") or e.get("seal_out"):
            L.append(f"    seals:  in {e.get('seal_in') or '-'} / out {e.get('seal_out') or '-'}")
        if e.get("notes"):
            L.append(f"    notes:  {e['notes']}")
        L.append(f"    hash:   {e['entry_hash'][:32]}…  (prev {e['prev_hash'][:12]}…)")
        if e["type"] == "transfer":
            L.append("    signed (from): ____________________   signed (to): ____________________")
        else:
            L.append("    signed:        ____________________")
    L.append("-" * 78)
    chain = check_chain(rec)
    L.append("Chain integrity: " + ("intact" if not chain else "BROKEN — " + "; ".join(chain)))
    return "\n".join(L) + "\n"


def cmd_show(a):
    rec = load(a.record)
    text = render(rec)
    if a.text:
        with open(a.text, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {a.text}")
    else:
        sys.stdout.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Chain-of-custody record: JSON + printable text, hash-chained, no gaps.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Run '%(prog)s <command> --help' for each command. Times in UTC with a zone (…Z).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("new", help="start a record for an exhibit (the collection entry)")
    n.add_argument("--case"); n.add_argument("--exhibit"); n.add_argument("--description")
    n.add_argument("--collected-by"); n.add_argument("--when"); n.add_argument("--where"); n.add_argument("--why")
    n.add_argument("--manifest", help="sha256sum-format manifest of the exhibit's files")
    n.add_argument("--seal", help="seal number applied at collection")
    n.add_argument("--method", help="how it was collected (tool, version)")
    n.add_argument("--notes")
    n.add_argument("-o", "--output", required=True)
    n.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    n.set_defaults(fn=cmd_new)

    t = sub.add_parser("transfer", help="record a movement from one person to another")
    t.add_argument("record")
    t.add_argument("--from", dest="frm"); t.add_argument("--to"); t.add_argument("--when"); t.add_argument("--why")
    t.add_argument("--seal-in", help="seal number found intact on receipt (or BROKEN)")
    t.add_argument("--seal-out", help="seal number applied when handing on")
    t.add_argument("--method", help="hand delivery, courier (tracking no.), SFTP (host, account)...")
    t.add_argument("--notes")
    t.set_defaults(fn=cmd_transfer)

    v = sub.add_parser("verify", help="re-hash every file against the manifest and check the chain")
    v.add_argument("record")
    v.add_argument("--dir", help="where the files are now (default: where the manifest was, relative to this record)")
    v.add_argument("--record", dest="record_it", action="store_true", help="append the result as an entry")
    v.add_argument("--by", help="who is verifying (needed with --record)")
    v.add_argument("--when", help="when (default: now)")
    v.add_argument("--notes")
    v.add_argument("-v", "--verbose", action="store_true")
    v.set_defaults(fn=cmd_verify)

    s = sub.add_parser("show", help="print the record as a form (or --text FILE)")
    s.add_argument("record"); s.add_argument("--text")
    s.set_defaults(fn=cmd_show)

    a = ap.parse_args(argv)
    try:
        return a.fn(a) or 0
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

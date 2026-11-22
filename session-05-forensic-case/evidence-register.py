#!/usr/bin/env python3
"""
evidence-register.py — give every file in the case bundle a stable evidence ID.

A report that says "the Sysmon log shows..." makes the reader guess which log,
which copy, and whether it is the one you were given. A report that says
"E-14 (SHA-256 3f1a...)" does not. This reads the bundle's MANIFEST.tsv and
assigns E-01, E-02, ... in a fixed order (session, then path), so everyone who
builds the bundle from the same commit gets the same IDs.

Usage
    ./evidence-register.py work/case-bundle                 write the register, print it
    ./evidence-register.py work/case-bundle --show E-07     one item, in full
    ./evidence-register.py work/case-bundle --find usn      search paths
    ./evidence-register.py work/case-bundle --md            print the Markdown table for your report

Writes, next to the manifest:
    evidence-register.csv    id, session, path, sha256, bytes, host, kind
    evidence-register.md     the same as a Markdown table, ready for the report

What it does NOT do: describe the evidence for you. The "kind" and "host"
columns are guesses from the file name, to help you find things; the
description in your report is yours, written after you have looked.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

# Files that describe evidence rather than being evidence. They stay in the
# bundle (and in the manifest) but get no E-number.
NOT_EVIDENCE = re.compile(r"(^|/)(SHA256SUMS|README(\.md|\.txt)?)$", re.I)

HOSTS = ["WS-FIN-07", "WS-IT-02", "SRV-BKP01", "FS01", "DC01", "FW01", "SIEM01", "M365"]
KINDS = [  # (pattern on the lower-cased path, label) — first match wins
    (r"sysmon", "Sysmon event log"),
    (r"security", "Windows Security log"),
    (r"terminalservices|rdp|localsession", "RDP / Terminal Services log"),
    (r"usnjrnl|\$j", "NTFS change journal ($UsnJrnl)"),
    (r"mft", "NTFS $MFT"),
    (r"systemd|\.service$|\.timer$", "systemd unit"),
    (r"_system\.|system\.(jsonl|evtx)", "Windows System log"),
    (r"\.eml$", "email (MIME)"),
    (r"trace", "mail message trace"),
    (r"\.pcap(ng)?(\.gz)?$", "packet capture"),
    (r"conn\.log|dns\.log|http\.log|ssl\.log|files\.log|zeek", "Zeek log"),
    (r"fw01|firewall|egress|proxy", "firewall / proxy log"),
    (r"auth\.log|syslog|secure", "Linux log"),
    (r"wtmp|btmp|lastlog", "Linux login records"),
    (r"bash_history", "shell history"),
    (r"prefetch|amcache|shimcache|registry|ntuser|\.hve", "Windows registry / execution artefact"),
    (r"leia-me|ransom", "ransom note"),
    (r"rc\.conf", "tool configuration"),
    (r"memo|findings", "third-party report"),
    (r"subject", "data-subject inventory"),
    (r"handover|custody|coc", "custody / provenance record"),
    (r"response-log", "response log"),
    (r"ticket|helpdesk", "helpdesk tickets"),
    (r"alert", "alert queue"),
    (r"\.jsonl$", "event log (JSON Lines)"),
    (r"\.csv$", "table (CSV)"),
    (r"\.md$|\.txt$", "document"),
]


def guess_host(path):
    up = path.upper()
    for h in HOSTS:
        if h in up or h.replace("-", "") in up.replace("-", "").replace("_", ""):
            return h
    if "phish" in path.lower() or ".eml" in path.lower():
        return "M365"
    return ""


def guess_kind(path):
    low = path.lower()
    for pat, label in KINDS:
        if re.search(pat, low):
            return label
    return "file"


def load_manifest(bundle):
    m = Path(bundle) / "MANIFEST.tsv"
    if not m.is_file():
        sys.exit(f" fail  no MANIFEST.tsv in {bundle} — run ./bundle.sh first")
    with m.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    need = {"sha256", "bytes", "session", "path"}
    if not rows or not need <= set(rows[0]):
        sys.exit(f" fail  {m} does not look like a bundle manifest (columns {sorted(need)})")
    return rows


def assign(rows):
    """The ID rule, in one place: sort by session then path, skip non-evidence."""
    items = [r for r in rows if not NOT_EVIDENCE.search(r["path"])]
    items.sort(key=lambda r: (r["session"], r["path"]))
    width = 2 if len(items) < 100 else 3
    out = []
    for i, r in enumerate(items, 1):
        out.append({"id": f"E-{i:0{width}d}", "session": r["session"], "path": r["path"],
                    "sha256": r["sha256"], "bytes": r["bytes"],
                    "host": guess_host(r["path"]), "kind": guess_kind(r["path"])})
    return out


def markdown(reg):
    lines = ["| ID | Item (bundle path) | SHA-256 | Bytes | Host | Received from / custody ref |",
             "|---|---|---|---|---|---|"]
    for r in reg:
        lines.append(f"| {r['id']} | `{r['path']}` | `{r['sha256']}` | {r['bytes']} | {r['host']} | |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", nargs="?", default="work/case-bundle", help="bundle directory (default work/case-bundle)")
    ap.add_argument("--show", metavar="E-NN", help="print one item in full")
    ap.add_argument("--find", metavar="TEXT", help="list items whose path contains TEXT (case-insensitive)")
    ap.add_argument("--md", action="store_true", help="print the Markdown table only")
    ap.add_argument("--no-write", action="store_true", help="do not write the register files")
    args = ap.parse_args()

    reg = assign(load_manifest(args.bundle))
    if not reg:
        sys.exit(" fail  the manifest lists no evidence files")

    if args.show:
        want = args.show.upper()
        for r in reg:
            if r["id"] == want:
                for k in ("id", "session", "path", "sha256", "bytes", "host", "kind"):
                    print(f"  {k:8} {r[k]}")
                print(f"  {'file':8} {Path(args.bundle) / r['path']}")
                return
        sys.exit(f" fail  {want} is not in this register (E-01 .. {reg[-1]['id']})")

    if args.find:
        hits = [r for r in reg if args.find.lower() in r["path"].lower()]
        for r in hits:
            print(f"  {r['id']}  {r['path']}")
        if not hits:
            print(f"  nothing matches '{args.find}'")
        return

    if not args.no_write:
        b = Path(args.bundle)
        try:
            with (b / "evidence-register.csv").open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=["id", "session", "path", "sha256", "bytes", "host", "kind"])
                w.writeheader()
                w.writerows(reg)
            (b / "evidence-register.md").write_text(markdown(reg), encoding="utf-8")
        except PermissionError:
            sys.exit(f" fail  cannot write in {b} — it should be writable (only S0?/ are read-only)")

    if args.md:
        sys.stdout.write(markdown(reg))
        return

    print()
    print(f"  {len(reg)} evidence items  (from {Path(args.bundle) / 'MANIFEST.tsv'})")
    print()
    for r in reg:
        print(f"  {r['id']}  {r['session']}  {r['path'][4:]:<58} {r['host']:<9} {r['kind']}")
    print()
    if not args.no_write:
        print(f"  wrote {Path(args.bundle) / 'evidence-register.csv'} and evidence-register.md")
    print("  Cite these IDs in your findings. Same commit + same bundle = same IDs for everyone.")
    print()


if __name__ == "__main__":
    main()

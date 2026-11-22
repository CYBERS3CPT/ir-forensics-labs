#!/usr/bin/env python3
"""zcut.py - zeek-cut without Zeek, plus the uid pivot.

Zeek logs are TSV with a #fields header. You rarely want all thirty columns,
and you always want the timestamp readable. That is what zeek-cut does; this
does the same with the standard library, so you do not need Zeek installed.

    python3 zcut.py evidence/zeek/conn.log ts id.orig_h id.resp_h id.resp_p orig_bytes
    python3 zcut.py -d evidence/zeek/dns.log ts id.orig_h query answers     -d: ts as UTC text
    python3 zcut.py --fields evidence/zeek/ssl.log                          which columns exist?
    python3 zcut.py --uid CHhfblMmDufmlJ2WTt evidence/zeek/                 every record with that uid/fuid
    python3 zcut.py --uid <cert sha256> evidence/zeek/                      ssl.log -> x509.log by fingerprint

The uid is Zeek's connection id. The SAME uid appears in conn.log, dns.log,
http.log, ssl.log and files.log for the same connection: that is how you go
from "a connection" to "the name it asked, the URL it fetched, the certificate
it got and the file that came back". files.log also carries a fuid, which
http.log references in resp_fuids. Certificates are keyed differently: ssl.log
lists cert_chain_fps (SHA-256 of each certificate) and x509.log has one record
per fingerprint, so --uid also accepts a fingerprint.

Output is tab-separated, so it pipes into sort, uniq, awk and grep.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys
from datetime import datetime, timezone


def rows(path):
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#"):
                continue
            yield fields, line.split("\t")


def fmt_ts(v: str) -> str:
    try:
        return datetime.fromtimestamp(float(v), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return v


def main():
    ap = argparse.ArgumentParser(description="zeek-cut for people without Zeek; --uid to pivot across logs.",
                                 epilog="Example: python3 zcut.py -d evidence/zeek/http.log ts uid host uri user_agent")
    ap.add_argument("-d", action="store_true", help="convert time columns (ts, ...) to ISO 8601 UTC")
    ap.add_argument("--fields", action="store_true", help="list the columns of the log and exit")
    ap.add_argument("--uid", help="print every record, in every log under the directory, with this uid, fuid or certificate fingerprint")
    ap.add_argument("log", help="a Zeek log, or (with --uid) a directory of logs")
    ap.add_argument("columns", nargs="*", help="columns to print, in this order (default: all)")
    a = ap.parse_args()

    if a.uid:
        paths = sorted(glob.glob(os.path.join(a.log, "*.log"))) if os.path.isdir(a.log) else [a.log]
        hit = 0
        for p in paths:
            for fields, vals in rows(p):
                rec = dict(zip(fields, vals))
                keys = ("uid", "fuid", "resp_fuids", "orig_fuids", "parent_fuid", "fingerprint")
                if any(a.uid in rec.get(k, "").split(",") for k in keys):
                    hit += 1
                    print(f"== {os.path.basename(p)}")
                    for k, v in rec.items():
                        if v not in ("-", "(empty)"):
                            dated = k == "ts" or k in ("certificate.not_valid_before", "certificate.not_valid_after")
                            print(f"   {k:<28} {fmt_ts(v) if dated else v}")
        if not hit:
            sys.exit(f"{a.uid}: not found in {a.log}")
        return

    first = True
    for fields, vals in rows(a.log):
        if a.fields:
            print("\n".join(fields))
            return
        idx = [fields.index(c) if c in fields else None for c in a.columns] if a.columns else list(range(len(fields)))
        if first and a.columns and None in idx:
            missing = [c for c, i in zip(a.columns, idx) if i is None]
            sys.exit(f"no such column(s): {', '.join(missing)}  (try --fields)")
        first = False
        out = []
        for i in idx:
            v = vals[i]
            if a.d and fields[i] == "ts" or (a.d and fields[i] in ("certificate.not_valid_before", "certificate.not_valid_after")):
                v = fmt_ts(v)
            out.append(v)
        try:
            print("\t".join(out))
        except BrokenPipeError:      # | head
            sys.stderr.close()
            return


if __name__ == "__main__":
    main()

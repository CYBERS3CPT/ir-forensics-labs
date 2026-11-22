#!/usr/bin/env python3
"""
attack-flow.py — turn your hop list into an ATT&CK-tagged attack flow, and check it.

You write the flow as a CSV, one row per step (copy hops-template.csv):

    step,utc,from_host,to_host,action,technique,credential,evidence
    3,2026-03-10T00:00:00Z,HOST,HOST,what happened,T1234.001,account + how obtained,FILE.jsonl#RECORD

This script then:
  - checks every evidence reference exists: FILE.jsonl#RECORD for Windows,
    HOST/var/log/FILE:LINE for text logs (any collected file: HOST/root/.bash_history:3),
    HOST/var/log/wtmp@OFFSET for wtmp/btmp (a leading linux/, as in the supertimeline's
    ref column, is accepted); `ext:` refs (other sessions, other sources) are listed, not checked;
  - checks the time you wrote against the event's CORRECTED time (±3 s), using
    the same --skew decisions as supertimeline.py, and tells you when you quoted
    a host clock instead of true UTC;
  - checks the technique IDs are well formed and known, and names them;
  - prints (or writes, --md) a Markdown table, the host path, and which ATT&CK
    tactics the flow covers — the backbone of the S4 deliverable.

Usage
    ./attack-flow.py work/hops.csv --year 2026 --skew SOMEHOST=+90 --skew '*=0'
    ./attack-flow.py work/hops.csv --year 2026 --skew ... --md work/attack-flow.md

A flow that does not validate is not finished: every ✗ is either a typo or a
claim the evidence does not support.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evtxlib as L  # noqa: E402

UTC = timezone.utc
ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
         "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
         "collection", "command-and-control", "exfiltration", "impact"]
# Enterprise ATT&CK (v15+) — the techniques you are likely to need, and many you are not.
TECH = {
    "T1566": ("Phishing", "initial-access"), "T1566.001": ("Spearphishing Attachment", "initial-access"),
    "T1566.002": ("Spearphishing Link", "initial-access"), "T1078": ("Valid Accounts", "defense-evasion,persistence,privilege-escalation,initial-access"),
    "T1078.002": ("Domain Accounts", "defense-evasion,persistence,privilege-escalation,initial-access"),
    "T1078.003": ("Local Accounts", "defense-evasion,persistence,privilege-escalation,initial-access"),
    "T1133": ("External Remote Services", "initial-access,persistence"), "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1204": ("User Execution", "execution"), "T1204.001": ("Malicious Link", "execution"), "T1204.002": ("Malicious File", "execution"),
    "T1059": ("Command and Scripting Interpreter", "execution"), "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"), "T1059.004": ("Unix Shell", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"), "T1053": ("Scheduled Task/Job", "execution,persistence,privilege-escalation"),
    "T1053.003": ("Cron", "execution,persistence,privilege-escalation"), "T1053.005": ("Scheduled Task", "execution,persistence,privilege-escalation"),
    "T1569": ("System Services", "execution"), "T1569.002": ("Service Execution", "execution"),
    "T1547": ("Boot or Logon Autostart Execution", "persistence,privilege-escalation"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence,privilege-escalation"),
    "T1543": ("Create or Modify System Process", "persistence,privilege-escalation"),
    "T1543.003": ("Windows Service", "persistence,privilege-escalation"), "T1136": ("Create Account", "persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation,defense-evasion"),
    "T1548.002": ("Bypass User Account Control", "privilege-escalation,defense-evasion"),
    "T1548.003": ("Sudo and Sudo Caching", "privilege-escalation,defense-evasion"),
    "T1218": ("System Binary Proxy Execution", "defense-evasion"), "T1218.011": ("Rundll32", "defense-evasion"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"), "T1140": ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1036": ("Masquerading", "defense-evasion"), "T1036.003": ("Rename Legitimate Utilities", "defense-evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "defense-evasion"), "T1112": ("Modify Registry", "defense-evasion"),
    "T1070": ("Indicator Removal", "defense-evasion"), "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1070.002": ("Clear Linux or Mac System Logs", "defense-evasion"), "T1070.003": ("Clear Command History", "defense-evasion"),
    "T1070.004": ("File Deletion", "defense-evasion"), "T1562": ("Impair Defenses", "defense-evasion"),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion"), "T1562.002": ("Disable Windows Event Logging", "defense-evasion"),
    "T1550": ("Use Alternate Authentication Material", "defense-evasion,lateral-movement"),
    "T1550.002": ("Pass the Hash", "defense-evasion,lateral-movement"), "T1550.003": ("Pass the Ticket", "defense-evasion,lateral-movement"),
    "T1003": ("OS Credential Dumping", "credential-access"), "T1003.001": ("LSASS Memory", "credential-access"),
    "T1003.002": ("Security Account Manager", "credential-access"), "T1003.003": ("NTDS", "credential-access"),
    "T1003.006": ("DCSync", "credential-access"), "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"), "T1110.003": ("Password Spraying", "credential-access"),
    "T1110.004": ("Credential Stuffing", "credential-access"), "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1552": ("Unsecured Credentials", "credential-access"), "T1558": ("Steal or Forge Kerberos Tickets", "credential-access"),
    "T1558.003": ("Kerberoasting", "credential-access"),
    "T1033": ("System Owner/User Discovery", "discovery"), "T1069": ("Permission Groups Discovery", "discovery"),
    "T1069.001": ("Local Groups", "discovery"), "T1069.002": ("Domain Groups", "discovery"),
    "T1087": ("Account Discovery", "discovery"), "T1087.002": ("Domain Account", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"), "T1135": ("Network Share Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"), "T1046": ("Network Service Discovery", "discovery"),
    "T1016": ("System Network Configuration Discovery", "discovery"), "T1082": ("System Information Discovery", "discovery"),
    "T1057": ("Process Discovery", "discovery"), "T1083": ("File and Directory Discovery", "discovery"),
    "T1021": ("Remote Services", "lateral-movement"), "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral-movement"), "T1021.004": ("SSH", "lateral-movement"),
    "T1021.006": ("Windows Remote Management", "lateral-movement"), "T1570": ("Lateral Tool Transfer", "lateral-movement"),
    "T1560": ("Archive Collected Data", "collection"), "T1560.001": ("Archive via Utility", "collection"),
    "T1039": ("Data from Network Shared Drive", "collection"), "T1005": ("Data from Local System", "collection"),
    "T1074": ("Data Staged", "collection"), "T1074.001": ("Local Data Staging", "collection"),
    "T1071": ("Application Layer Protocol", "command-and-control"), "T1071.001": ("Web Protocols", "command-and-control"),
    "T1573": ("Encrypted Channel", "command-and-control"), "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1090": ("Proxy", "command-and-control"), "T1572": ("Protocol Tunneling", "command-and-control"),
    "T1219": ("Remote Access Software", "command-and-control"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"), "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"), "T1567.002": ("Exfiltration to Cloud Storage", "exfiltration"),
    "T1486": ("Data Encrypted for Impact", "impact"), "T1490": ("Inhibit System Recovery", "impact"),
    "T1489": ("Service Stop", "impact"), "T1485": ("Data Destruction", "impact"), "T1531": ("Account Access Removal", "impact"),
}
COLS = ["step", "utc", "from_host", "to_host", "action", "technique", "credential", "evidence"]


def load_mod(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Resolver:
    def __init__(self, ev_root: Path, year, skew):
        self.root, self.year, self.skew = ev_root, year, skew
        self.win = {}
        for e in L.load([str(ev_root / "windows")]) if (ev_root / "windows").exists() else []:
            self.win[(e["_file"].lower(), str(e["RecordID"]))] = e
        self.st = load_mod("supertimeline", "supertimeline.py")
        self.wt = load_mod("wtmp_read", "wtmp-read.py")

    def resolve(self, ref: str):
        """-> (host, host_time) or raises ValueError with a reason."""
        ref = ref.strip()
        m = re.fullmatch(r"([\w.-]+\.jsonl)#(\d+)", ref)
        if m:
            e = self.win.get((m.group(1).lower(), m.group(2)))
            if not e:
                raise ValueError("no such record in that file")
            return e["Host"], e["Time"], L.describe(e)
        m = re.fullmatch(r"(?:linux/)?([\w.-]+)/var/log/(\w+)@(\d+)", ref)
        if m:
            f = self.root / "linux" / m.group(1) / "var" / "log" / m.group(2)
            for r in self.wt.records(f):
                if r["offset"] == int(m.group(3)):
                    return m.group(1).upper(), r["time"], f"{r['type']} {r['user']} {r['line']} {r['host']}"
            raise ValueError("no record at that offset")
        m = re.fullmatch(r"(?:linux/)?([\w./-]+):(\d+)", ref)
        if m:
            rel, n_ = m.group(1), m.group(2)
            hostdirs = [p.name for p in (self.root / "linux").iterdir() if p.is_dir()] if (self.root / "linux").exists() else []
            first = rel.split("/", 1)
            cands = []
            if first[0] in hostdirs and len(first) == 2:
                cands = [(first[0], self.root / "linux" / first[0] / first[1])]
            else:
                for h in hostdirs:
                    cands += [(h, self.root / "linux" / h / rel), (h, self.root / "linux" / h / "var" / "log" / rel)]
            for h, f in cands:
                if f.is_file():
                    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
                    n = int(n_)
                    if not 1 <= n <= len(lines):
                        raise ValueError(f"{f.name} has {len(lines)} lines")
                    line = lines[n - 1]
                    sm = self.st.SYSLOG.match(line)
                    if sm:
                        if not self.year:
                            raise ValueError("syslog line: give --year")
                        hh, mi, ss = map(int, sm["time"].split(":"))
                        return h.upper(), datetime(self.year, self.st.MONTHS[sm["mon"]], int(sm["day"]), hh, mi, ss, tzinfo=UTC), line[16:120]
                    mm_ = re.match(r"^Modify: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line.strip())
                    if mm_:
                        return h.upper(), datetime.strptime(mm_.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC), "mtime " + line.strip()
                    im = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z", line)
                    if im:
                        return h.upper(), datetime.strptime(im.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC), line[:100]
                    return h.upper(), None, line[:100]      # a line with no time (shell history, config)
            raise ValueError("file not found under evidence/linux/")
        raise ValueError("unrecognised reference (FILE.jsonl#RECORD, HOST/var/log/FILE:LINE, HOST/var/log/wtmp@OFFSET, ext:...)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvfile", help="your hops CSV (columns: " + ",".join(COLS) + ")")
    ap.add_argument("--evidence", default=str(HERE / "evidence"))
    ap.add_argument("--skew", action="append", help="HOST=+SECONDS, the same decisions as your supertimeline")
    ap.add_argument("--year", type=int, help="year for syslog-format references")
    ap.add_argument("--md", help="also write the Markdown to this file")
    ap.add_argument("--tolerance", type=float, default=3.0, help="seconds allowed between your time and the event (default 3)")
    a = ap.parse_args()

    skew = L.parse_skew(a.skew)
    with open(a.csvfile, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(line for line in fh if line.strip() and not line.lstrip().startswith("#"))]
    if not rows:
        sys.exit(" fail  no rows (lines starting with # are comments)")
    miss = [c for c in COLS if c not in rows[0]]
    if miss:
        sys.exit(f" fail  missing column(s): {', '.join(miss)} — start from hops-template.csv")

    res = Resolver(Path(a.evidence), a.year, skew)
    problems, md, tactics = 0, [], set()
    md.append("| # | UTC | From → To | Action | ATT&CK | Tactic | Credential | Evidence |")
    md.append("|---|---|---|---|---|---|---|---|")
    path = []
    print()
    for r in rows:
        step = r["step"].strip()
        notes = []
        try:
            when = datetime.strptime(r["utc"].strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            when = None
            notes.append("✗ utc must look like 2026-03-10T11:30:47Z (UTC, seconds, trailing Z)")
        techs = [t.strip().upper() for t in re.split(r"[;/ ]+", r["technique"]) if t.strip()]
        tnames, ttac = [], []
        for t in techs:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                notes.append(f"✗ {t!r} is not a technique ID (T1234 or T1234.001)")
                continue
            if t not in TECH:
                notes.append(f"? {t} not in this script's table — check it on attack.mitre.org")
                tnames.append(t)
                continue
            tnames.append(f"{t} {TECH[t][0]}")
            ttac.append(TECH[t][1].split(",")[0] if t not in ("T1078", "T1078.002", "T1078.003") else "defense-evasion/initial-access")
            tactics.update(TECH[t][1].split(","))
        refs = [x.strip() for x in r["evidence"].split(";") if x.strip()]
        if not refs:
            notes.append("✗ no evidence reference: every hop needs one")
        okrefs = []
        matched, timed = False, 0
        for ref in refs:
            if ref.startswith("ext:"):
                okrefs.append(f"{ref} (not checked)")
                continue
            try:
                host, ht, desc = res.resolve(ref)
            except ValueError as exc:
                notes.append(f"✗ {ref}: {exc}")
                continue
            if ht is None:
                okrefs.append(f"{ref} ✓ (no time on that line)")
                continue
            timed += 1
            off = L.offset_for(host, skew)
            if off is None:
                notes.append(f"✗ {ref}: no clock decision for {host} (--skew {host}=...)")
                continue
            corr = ht - timedelta(seconds=off)
            if when and abs((when - corr).total_seconds()) <= a.tolerance:
                okrefs.append(f"{ref} ✓")
                matched = True
            elif when and off and abs((when - ht).total_seconds()) <= a.tolerance:
                notes.append(f"✗ {ref}: your time is {host}'s own clock, not the corrected UTC")
            else:
                okrefs.append(f"{ref} · supporting event at {L.fmt(corr, False)} UTC")
            okrefs.append(f"   {desc[:110]}")
        if when and timed and not matched and not any(n.startswith("✗") for n in notes):
            notes.append(f"✗ none of the references is at {r['utc'].strip()} (±{a.tolerance:g} s): which event is this step's time?")
        status = "ok " if not any(n.startswith("✗") for n in notes) else "FIX"
        problems += status == "FIX"
        print(f"  [{status}] {step:>3}  {r['utc'].strip():<21} {r['from_host'].strip()} -> {r['to_host'].strip():<10} {r['action'].strip()[:60]}")
        for x in okrefs:
            print(f"              {x}")
        for n in notes:
            print(f"              {n}")
        fh_, th_ = r["from_host"].strip(), r["to_host"].strip()
        if fh_ and th_ and fh_ != th_ and "-" not in (fh_, th_) and (fh_, th_) not in path:
            path.append((fh_, th_))
        md.append(f"| {step} | {r['utc'].strip()} | {r['from_host'].strip()} → {r['to_host'].strip()} | {r['action'].strip()} | "
                  f"{'<br>'.join(tnames)} | {'<br>'.join(ttac)} | {r['credential'].strip()} | {'<br>'.join(refs)} |")

    covered = [t for t in ORDER if t in tactics]
    gaps = [t for t in ORDER[2:] if t not in tactics]
    md += ["", "**Hops (first seen):** " + ", ".join(f"{x} → {y}" for x, y in path), "", "**Tactics covered:** " + ", ".join(covered),
           "", "**Tactics with no step:** " + (", ".join(gaps) or "none")]
    print("\n  hops:     " + ", ".join(f"{x} -> {y}" for x, y in path))
    print("  tactics:  " + ", ".join(covered))
    print("  no step:  " + (", ".join(gaps) or "none") + "   (a gap is fine if the evidence has nothing — say so)")
    print(f"\n  {len(rows)} step(s), {problems} to fix" + ("" if problems else " — every reference resolves and every time matches"))
    if a.md:
        Path(a.md).parent.mkdir(parents=True, exist_ok=True)
        Path(a.md).write_text("\n".join(md) + "\n", encoding="utf-8")
        print(f"  markdown -> {a.md}")
    else:
        print("\n" + "\n".join(md))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

"""
evtxlib.py — shared plumbing for the Session 4 scripts. Not run directly.

Reads Windows event logs exported as JSON Lines in the `evtx_dump -o jsonl`
shape (one `{"Event": {...}}` per line), flattens each event into one dict,
and knows how to say in one line what an event means.

Two decisions live here so every script makes them the same way:

1. Flattening. `System` fields keep short names (Time, Host, Channel, EventID,
   RecordID...). `EventData` fields keep their Windows names (Image,
   TargetUserName, LogonType...). `UserData` is nested one level deeper by
   Windows (UserData -> LogFileCleared -> SubjectUserName); we lift the leaf
   fields to the top so a 1102 and a 4624 can be queried the same way.

2. Clocks. An event's time is the clock of the host that wrote it. A clock
   correction ("this host was N seconds fast") is an analyst's decision, made
   on evidence and written down — so it is an explicit argument, `--skew
   HOST=+N`, never a default.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
HERE = Path(__file__).resolve().parent
DEFAULT_WINDOWS = HERE / "evidence" / "windows"

CHANNEL_SHORT = {
    "Microsoft-Windows-Sysmon/Operational": "Sysmon",
    "Security": "Security",
    "System": "System",
    "Microsoft-Windows-PowerShell/Operational": "PowerShell",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "TS-LSM",
}


# --- time -------------------------------------------------------------------
def parse_systemtime(s: str) -> datetime:
    # "2026-03-10T08:47:28.123456Z" — fromisoformat on 3.9/3.10 refuses the Z
    s = s.replace("Z", "+00:00")
    # evtx_dump can print 7 fraction digits; Python 3.9 accepts only 3 or 6
    m = re.match(r"^(.*?)\.(\d+)(\+00:00)$", s)
    if m:
        s = f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}{m.group(3)}"
    return datetime.fromisoformat(s)


TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d")


def parse_user_time(s: str) -> datetime:
    """--since / --until. Always read as UTC; a trailing Z is accepted, an offset is refused."""
    raw = s.strip()
    if re.search(r"[+-]\d{2}:?\d{2}$", raw) and not raw.endswith("Z"):
        sys.exit(f" fail  {s!r}: give times in UTC (2026-03-10 11:30 or 2026-03-10T11:30:00Z), not with an offset")
    raw = raw.rstrip("Z")
    for f in TIME_FORMATS:
        try:
            return datetime.strptime(raw, f).replace(tzinfo=UTC)
        except ValueError:
            pass
    sys.exit(f" fail  could not read the time {s!r} — try '2026-03-10 11:30:00'")


def fmt(dt: datetime, ms=True) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") + (f".{dt.microsecond // 1000:03d}" if ms else "")


def parse_skew(items: list[str] | None) -> dict[str, float]:
    """['SOMEHOST=+90', '*=0'] -> {'SOMEHOST': 90.0, '*': 0.0}

    +N means the host clock was AHEAD of true time by N seconds, so the
    corrected time is host_time - N. Say it the same way in your report.
    """
    out: dict[str, float] = {}
    for it in items or []:
        m = re.fullmatch(r"\s*([A-Za-z0-9*._-]+)\s*=\s*([+-]?\d+(?:\.\d+)?)\s*s?\s*", it)
        if not m:
            sys.exit(f" fail  --skew {it!r}: expected HOST=+SECONDS, e.g. --skew FS01=0 or --skew SOMEHOST=+90\n"
                     "       (+N = that host's clock was N seconds AHEAD of true time)")
        out[m.group(1).upper() if m.group(1) != "*" else "*"] = float(m.group(2))
    return out


def offset_for(host: str, skew: dict[str, float]) -> float | None:
    if host.upper() in skew:
        return skew[host.upper()]
    return skew.get("*")


# --- loading ----------------------------------------------------------------
def _lift(d, out):
    """Copy leaf values of nested UserData into out (skipping #attributes)."""
    for k, v in d.items():
        if k == "#attributes":
            continue
        if isinstance(v, dict):
            _lift(v, out)
        else:
            out.setdefault(k, v)


def flatten(raw: dict, fname: str, lineno: int) -> dict:
    e = raw.get("Event", raw)
    s = e.get("System", {})
    comp = s.get("Computer", "") or ""
    ev = {
        "Time": parse_systemtime(s["TimeCreated"]["#attributes"]["SystemTime"]),
        "Host": comp.split(".")[0].upper(),
        "Computer": comp,
        "Channel": CHANNEL_SHORT.get(s.get("Channel", ""), s.get("Channel", "")),
        "ChannelFull": s.get("Channel", ""),
        "EventID": int(s.get("EventID") if not isinstance(s.get("EventID"), dict) else s["EventID"].get("#text", 0)),
        "RecordID": s.get("EventRecordID"),
        "Provider": (s.get("Provider") or {}).get("#attributes", {}).get("Name", ""),
        "Level": s.get("Level"),
        "UserID": ((s.get("Security") or {}).get("#attributes") or {}).get("UserID", ""),
        "_file": fname,
        "_line": lineno,
    }
    for k in ("EventData", "UserData"):
        block = e.get(k)
        if isinstance(block, dict):
            _lift(block, ev)
    return ev


def iter_files(paths: list[str] | None):
    paths = paths or [str(DEFAULT_WINDOWS)]
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            files += sorted(pp.glob("*.jsonl"))
        elif pp.is_file():
            files.append(pp)
        else:
            sys.exit(f" fail  no such file or directory: {p}")
    if not files:
        sys.exit(" fail  no .jsonl files found in " + ", ".join(paths))
    return files


def load(paths: list[str] | None):
    """Yield flattened events from every .jsonl given (files or directories)."""
    for f in iter_files(paths):
        with open(f, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield flatten(json.loads(line), f.name, i)
                except (ValueError, KeyError) as exc:
                    print(f" warn  {f.name}:{i}: skipped unreadable event ({exc})", file=sys.stderr)


def true_time(ev: dict, skew: dict[str, float]) -> tuple[datetime, float | None]:
    off = offset_for(ev["Host"], skew)
    if off is None:
        return ev["Time"], None
    return ev["Time"] - timedelta(seconds=off), off


# --- one-line descriptions -------------------------------------------------
def base(p) -> str:
    p = str(p or "")
    return p.replace("/", "\\").split("\\")[-1] or p


LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock", 8: "network-cleartext",
               9: "new-credentials", 10: "remote-interactive (RDP)", 11: "cached-interactive"}
KRB_ENC = {"0x17": "RC4", "0x12": "AES256", "0x11": "AES128", "0x3": "DES"}


def _g(ev, k, d="-"):
    v = ev.get(k)
    return d if v in (None, "") else v


def describe(ev: dict) -> str:
    c, i = ev["Channel"], ev["EventID"]
    g = lambda k, d="-": _g(ev, k, d)  # noqa: E731
    if c == "Sysmon":
        if i == 1:
            return f"{g('User')} ran {base(g('Image'))}: {g('CommandLine')}  [parent {base(g('ParentImage'))}, {g('IntegrityLevel')}]"
        if i == 3:
            arrow = "<-" if str(g("Initiated")).lower() == "false" else "->"
            dst = f"{g('DestinationIp')}:{g('DestinationPort')}"
            name = g("DestinationHostname")
            return f"{base(g('Image'))} {g('SourceIp')}:{g('SourcePort')} {arrow} {dst}" + (f" ({name})" if name != "-" else "")
        if i == 5:
            return f"{base(g('Image'))} (pid {g('ProcessId')}) ended"
        if i == 7:
            return f"{base(g('Image'))} loaded {g('ImageLoaded')} (signed={g('Signed')})"
        if i == 10:
            return f"{base(g('SourceImage'))} opened {base(g('TargetImage'))} with access {g('GrantedAccess')}"
        if i == 11:
            return f"{base(g('Image'))} created {g('TargetFilename')}"
        if i in (12, 13, 14):
            return f"{base(g('Image'))} {g('EventType')} {g('TargetObject')}" + (f" = {g('Details')}" if i == 13 else "")
        if i == 15:
            return f"{base(g('Image'))} wrote stream {g('TargetFilename')}: {str(g('Contents'))[:90]}"
        if i == 22:
            return f"{base(g('Image'))} resolved {g('QueryName')} -> {g('QueryResults')}"
        if i in (23, 26):
            return f"{base(g('Image'))} deleted {g('TargetFilename')}"
    if c == "Security":
        if i == 4624:
            lt = int(g("LogonType", 0))
            s = (f"logon type {lt} {LOGON_TYPES.get(lt, '')}: {g('TargetDomainName')}\\{g('TargetUserName')}"
                 f" from {g('IpAddress')} ws={g('WorkstationName')} {g('AuthenticationPackageName')}/{str(g('LogonProcessName')).strip()}")
            if g("TargetOutboundUserName") not in ("-", ""):
                s += f" outbound={g('TargetOutboundDomainName')}\\{g('TargetOutboundUserName')}"
            return s + f" id={g('TargetLogonId')}"
        if i == 4625:
            return f"FAILED logon type {g('LogonType')}: {g('TargetDomainName')}\\{g('TargetUserName')} from {g('IpAddress')} ws={g('WorkstationName')} status={g('Status')}/{g('SubStatus')}"
        if i == 4634:
            return f"logoff type {g('LogonType')}: {g('TargetUserName')} id={g('TargetLogonId')}"
        if i == 4647:
            return f"user-initiated logoff: {g('TargetUserName')} id={g('TargetLogonId')}"
        if i == 4648:
            return f"explicit credentials: {g('SubjectUserName')} used {g('TargetDomainName')}\\{g('TargetUserName')} to {g('TargetServerName')}"
        if i == 4672:
            return f"special privileges assigned to {g('SubjectDomainName')}\\{g('SubjectUserName')} id={g('SubjectLogonId')}"
        if i == 4688:
            return f"{g('SubjectUserName')} ran {g('NewProcessName')}: {g('CommandLine')}"
        if i == 4697:
            return f"service installed: {g('ServiceName')} -> {g('ServiceFileName')} by {g('SubjectUserName')}"
        if i == 4720:
            return f"user account created: {g('TargetUserName')} by {g('SubjectUserName')}"
        if i == 4768:
            return f"Kerberos TGT for {g('TargetUserName')} from {str(g('IpAddress')).replace('::ffff:', '')} enc={g('TicketEncryptionType')} ({KRB_ENC.get(str(g('TicketEncryptionType')), '?')}) status={g('Status')}"
        if i == 4769:
            return f"Kerberos service ticket {g('ServiceName')} for {g('TargetUserName')} from {str(g('IpAddress')).replace('::ffff:', '')} enc={g('TicketEncryptionType')}"
        if i == 4771:
            return f"Kerberos pre-auth FAILED for {g('TargetUserName')} from {str(g('IpAddress')).replace('::ffff:', '')} status={g('Status')}"
        if i == 4776:
            return f"NTLM validation for {g('TargetUserName')} from workstation {g('Workstation')} status={g('Status')}"
        if i in (4778, 4779):
            what = "reconnected" if i == 4778 else "disconnected"
            return f"session {what}: {g('AccountDomain')}\\{g('AccountName')} client {g('ClientName')} {g('ClientAddress')} ({g('SessionName')})"
        if i in (4798, 4799):
            return f"group membership enumerated for {g('TargetUserName')} by {g('SubjectUserName')} ({base(g('CallerProcessName'))})"
        if i in (4800, 4801):
            return f"workstation {'locked' if i == 4800 else 'unlocked'} by {g('TargetUserName')}"
        if i == 5379:
            return f"credential manager read by {g('SubjectUserName')}: {g('TargetName')}"
        if i == 1102:
            return f"SECURITY LOG CLEARED by {g('SubjectDomainName')}\\{g('SubjectUserName')} id={g('SubjectLogonId')}"
    if c == "System":
        if i == 7045:
            return f"service installed: {g('ServiceName')} -> {g('ImagePath')} ({g('StartType')}, {g('AccountName')}) by SID {g('UserID')}"
        if i == 7036:
            return f"service '{g('param1')}' entered the {g('param2')} state"
        if i == 7040:
            return f"service '{g('param1')}' start type {g('param2')} -> {g('param3')}"
        if i == 104:
            return f"log cleared: {g('Channel')} by {g('SubjectUserName')}"
        if i == 1014:
            return f"DNS resolution timed out: {g('QueryName')}"
        if i == 5719:
            return "no domain controller available (NETLOGON 5719)"
        if i == 6013:
            return "system uptime report (6013)"
        if i == 37:
            return f"time service receiving from {g('TimeSource')}"
        if i == 10016:
            return "DCOM permission warning (10016)"
    if c == "PowerShell":
        if i == 4104:
            txt = str(g("ScriptBlockText")).replace("\n", " ⏎ ")
            return f"scriptblock (level {ev.get('Level')}): {txt[:160]}" + ("…" if len(txt) > 160 else "")
        if i == 40961:
            return "PowerShell console starting"
        if i == 40962:
            return "PowerShell console ready"
        if i == 53504:
            return f"PowerShell IPC listener in process {g('param1')}"
    if c == "TS-LSM":
        what = {21: "session logon", 22: "shell start", 23: "session logoff", 24: "session DISCONNECTED",
                25: "session RECONNECTED", 39: "session disconnected by another session", 40: "disconnect reason",
                41: "begin session arbitration", 42: "end session arbitration"}.get(i, f"event {i}")
        if i == 40:
            return f"{what}: session {g('Session')} reason {g('Reason')}"
        return f"{what}: {g('User')} session {g('SessionID')} from {g('Address')}"
    keys = [k for k in ev if k[0].isupper() and k not in ("Time", "Host", "Computer", "Channel", "ChannelFull",
                                                       "EventID", "RecordID", "Provider", "Level", "UserID")]
    return " ".join(f"{k}={ev[k]}" for k in keys[:6])


def user_of(ev: dict) -> str:
    for k in ("TargetUserName", "User", "AccountName", "SubjectUserName", "ParentUser", "SourceUser"):
        v = ev.get(k)
        if v and v not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") and not str(v).endswith("$"):
            return str(v).split("\\")[-1].split("@")[0]
    return ""

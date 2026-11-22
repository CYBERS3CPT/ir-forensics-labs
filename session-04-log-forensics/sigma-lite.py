#!/usr/bin/env python3
"""
sigma-lite.py — run Sigma-style rules over evtx_dump JSONL. Standard library only.

Real Sigma is a YAML language plus a converter (sigma-cli / pySigma) that turns a
rule into a SIEM query. This is the same idea with no SIEM: it reads the rules
in rules/, reads the events, and prints every event a rule matches, so you can
see what a detection would have said — and what it would have missed.

Usage
    ./sigma-lite.py                          every rule in rules/ against evidence/windows/
    ./sigma-lite.py --list                   the rules, their logsource and ATT&CK tags
    ./sigma-lite.py --rule lsass             only rules whose file name or title contains 'lsass'
    ./sigma-lite.py --summary                one line per rule: hits, hosts, first/last
    ./sigma-lite.py --skew SOMEHOST=+90      show corrected times for a host clock you measured
    ./sigma-lite.py --rules my-rules/ evidence/windows/FS01_Sysmon.jsonl

What is supported (enough for the rules in this course, and for yours)
    logsource: product windows; category process_creation, network_connection,
               image_load, process_access, file_event, file_delete, registry_set,
               registry_event, dns_query, ps_script; or service security, system,
               sysmon, powershell, terminalservices-localsessionmanager
    detection: named selections (maps; a list of maps = OR), a list value = OR,
               modifiers |contains |startswith |endswith |re |all |cidr,
               * and ? wildcards in plain values, case-insensitive like Sigma.
    condition: and / or / not / parentheses / '1 of sel*' / 'all of sel*' /
               '1 of them' / 'all of them'

The YAML reader understands the block style Sigma rules are written in (maps,
lists, quoted and plain scalars, | and > text blocks, comments). It is not a
general YAML parser: anchors, tags and flow maps are refused with a message.

A rule that cannot see its data cannot fire. When nothing you loaded matches a
rule's logsource, the rule is reported as BLIND, not as clean — a cleared log,
an unforwarded channel or a missing host all look like silence otherwise.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evtxlib as L  # noqa: E402

HERE = Path(__file__).resolve().parent


# --- a small YAML subset ----------------------------------------------------
class YamlError(Exception):
    pass


def _scalar(s: str, where: str):
    s = s.strip()
    if s == "" or s in ("~", "null"):
        return None
    if s[0] == "'":
        if not s.endswith("'") or len(s) < 2:
            raise YamlError(f"{where}: unterminated single quote")
        return s[1:-1].replace("''", "'")
    if s[0] == '"':
        if not s.endswith('"') or len(s) < 2:
            raise YamlError(f"{where}: unterminated double quote")
        return bytes(s[1:-1], "utf-8").decode("unicode_escape")
    if s[0] in "&*!|>{":
        raise YamlError(f"{where}: anchors, tags and flow maps are not supported here")
    if s[0] == "[":
        if not s.endswith("]"):
            raise YamlError(f"{where}: flow list must end on the same line")
        inner = s[1:-1].strip()
        return [] if not inner else [_scalar(x, where) for x in _split_flow(inner)]
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if s in ("true", "false"):
        return s == "true"
    return s


def _split_flow(s):
    out, cur, q = [], "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            cur += ch
        elif ch == ",":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _strip_comment(line: str) -> str:
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def parse_yaml(text: str, name="rule"):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlError(f"{name}:{n}: tab in indentation")
        line = _strip_comment(raw)
        if line.strip() in ("", "---"):
            continue
        lines.append((len(line) - len(line.lstrip(" ")), line.strip(), n))

    def block(i, indent):
        if i >= len(lines):
            return None, i
        if lines[i][1].startswith("- ") or lines[i][1] == "-":
            return seq(i, lines[i][0])
        return mapping(i, lines[i][0])

    def mapping(i, indent):
        out = {}
        while i < len(lines) and lines[i][0] == indent:
            _, t, n = lines[i]
            if t.startswith("- "):
                break
            m = re.match(r"^((?:'[^']*'|\"[^\"]*\"|[^:])+):(?:\s+(.*))?$", t)
            if not m:
                raise YamlError(f"{name}:{n}: expected 'key: value', got {t!r}")
            key = _scalar(m.group(1), f"{name}:{n}")
            rest = m.group(2)
            i += 1
            if rest is not None and re.fullmatch(r"[|>][-+]?", rest.strip()):
                # block scalar: the indented lines that follow are the text
                parts = []
                while i < len(lines) and lines[i][0] > indent:
                    parts.append(lines[i][1])
                    i += 1
                out[str(key)] = ("\n" if rest.strip()[0] == "|" else " ").join(parts)
                continue
            if rest is None or rest == "":
                if i < len(lines) and (lines[i][0] > indent or (lines[i][0] == indent and lines[i][1].startswith("- "))):
                    val, i = block(i, lines[i][0])
                else:
                    val = None
            else:
                val = _scalar(rest, f"{name}:{n}")
            out[str(key)] = val
        return out, i

    def seq(i, indent):
        out = []
        while i < len(lines) and lines[i][0] == indent and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
            _, t, n = lines[i]
            item = t[1:].strip()
            if re.match(r"^((?:'[^']*'|\"[^\"]*\"|[^:'\"])+):(\s|$)", item):
                # "- key: value" starts a map inside the list: re-read it as a map at deeper indent
                sub_indent = indent + 2
                lines[i] = (sub_indent, item, n)
                val, i = mapping(i, sub_indent)
                out.append(val)
                continue
            i += 1
            if item == "":
                val, i = block(i, lines[i][0])
                out.append(val)
            else:
                out.append(_scalar(item, f"{name}:{n}"))
        return out, i

    val, i = block(0, 0)
    if i != len(lines):
        raise YamlError(f"{name}:{lines[i][2]}: unexpected indentation")
    return val


# --- logsource --------------------------------------------------------------
CATEGORY = {
    "process_creation": ("Sysmon", {1}), "network_connection": ("Sysmon", {3}), "image_load": ("Sysmon", {7}),
    "process_access": ("Sysmon", {10}), "file_event": ("Sysmon", {11}), "file_delete": ("Sysmon", {23, 26}),
    "registry_set": ("Sysmon", {13}), "registry_event": ("Sysmon", {12, 13, 14}), "dns_query": ("Sysmon", {22}),
    "ps_script": ("PowerShell", {4104}),
}
SERVICE = {"security": "Security", "system": "System", "sysmon": "Sysmon", "powershell": "PowerShell",
           "terminalservices-localsessionmanager": "TS-LSM"}


def logsource_filter(ls: dict):
    ls = ls or {}
    if ls.get("product", "windows") != "windows":
        return None
    if ls.get("category"):
        if ls["category"] not in CATEGORY:
            return None
        ch, eids = CATEGORY[ls["category"]]
        return lambda ev: ev["Channel"] == ch and ev["EventID"] in eids
    if ls.get("service"):
        ch = SERVICE.get(str(ls["service"]).lower())
        if not ch:
            return None
        return lambda ev: ev["Channel"] == ch
    return lambda ev: True


# --- detection --------------------------------------------------------------
def _glob_to_rx(v: str):
    return re.compile("^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in v) + "$",
                      re.I | re.S)


def field_matcher(key: str, values):
    parts = key.split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    allm = "all" in mods
    vals = values if isinstance(values, list) else [values]
    tests = []
    for v in vals:
        if v is None:
            tests.append(lambda x: x in (None, "", "-"))
            continue
        sv = str(v)
        if "re" in mods:
            rx = re.compile(sv)
            tests.append(lambda x, rx=rx: x is not None and bool(rx.search(str(x))))
        elif "cidr" in mods:
            net = ipaddress.ip_network(sv, strict=False)

            def t(x, net=net):
                try:
                    return ipaddress.ip_address(str(x).replace("::ffff:", "")) in net
                except ValueError:
                    return False
            tests.append(t)
        elif "contains" in mods:
            tests.append(lambda x, s=sv.lower(): x is not None and s in str(x).lower())
        elif "startswith" in mods:
            tests.append(lambda x, s=sv.lower(): x is not None and str(x).lower().startswith(s))
        elif "endswith" in mods:
            tests.append(lambda x, s=sv.lower(): x is not None and str(x).lower().endswith(s))
        elif "*" in sv or "?" in sv:
            rx = _glob_to_rx(sv)
            tests.append(lambda x, rx=rx: x is not None and bool(rx.match(str(x))))
        else:
            tests.append(lambda x, s=sv.lower(): x is not None and str(x).lower() == s)
    if allm:
        return lambda ev: all(t(ev.get(field)) for t in tests)
    return lambda ev: any(t(ev.get(field)) for t in tests)


def selection_matcher(sel):
    if isinstance(sel, list):          # list of maps = OR; list of strings = keywords
        subs = [selection_matcher(s) if isinstance(s, dict) else
                (lambda ev, k=str(s).lower(): k in " ".join(str(v) for v in ev.values()).lower()) for s in sel]
        return lambda ev: any(m(ev) for m in subs)
    if isinstance(sel, dict):
        ms = [field_matcher(k, v) for k, v in sel.items()]
        return lambda ev: all(m(ev) for m in ms)
    raise YamlError("a selection must be a map or a list")


def compile_condition(cond: str, sels: dict):
    toks = re.findall(r"\(|\)|[A-Za-z0-9_*]+", cond)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def names(pat):
        if pat == "them":
            return list(sels)
        got = [n for n in sels if fnmatch.fnmatchcase(n, pat)]
        if not got:
            raise YamlError(f"condition: nothing matches {pat!r}")
        return got

    def atom():
        t = take()
        if t == "(":
            e = expr()
            if take() != ")":
                raise YamlError("condition: missing ')'")
            return e
        if t == "not":
            a = atom()
            return lambda ev: not a(ev)
        if t in ("1", "all") and peek() == "of":
            take()
            ns = [sels[n] for n in names(take())]
            return (lambda ev: any(m(ev) for m in ns)) if t == "1" else (lambda ev: all(m(ev) for m in ns))
        if t not in sels:
            raise YamlError(f"condition: unknown selection {t!r}")
        return sels[t]

    def conj():
        a = atom()
        while peek() == "and":
            take()
            b = atom()
            a = (lambda x, y: lambda ev: x(ev) and y(ev))(a, b)
        return a

    def expr():
        a = conj()
        while peek() == "or":
            take()
            b = conj()
            a = (lambda x, y: lambda ev: x(ev) or y(ev))(a, b)
        return a

    e = expr()
    if peek() is not None:
        raise YamlError(f"condition: unexpected {peek()!r}")
    return e


class Rule:
    def __init__(self, path: Path):
        self.path = path
        try:
            y = parse_yaml(path.read_text(encoding="utf-8"), path.name)
            self.title = y.get("title", path.stem)
            self.id = y.get("id", path.stem)
            self.level = y.get("level", "medium")
            self.tags = y.get("tags") or []
            self.fps = y.get("falsepositives") or []
            self.logsource = y.get("logsource") or {}
            det = dict(y.get("detection") or {})
            cond = det.pop("condition", None)
            if not cond:
                raise YamlError("detection has no condition")
            self.ls = logsource_filter(self.logsource)
            if self.ls is None:
                raise YamlError(f"logsource {self.logsource} is not one this script understands")
            sels = {k: selection_matcher(v) for k, v in det.items()}
            self.match = compile_condition(cond if isinstance(cond, str) else " or ".join(cond), sels)
        except YamlError as exc:
            sys.exit(f" fail  {path}: {exc}")
        except re.error as exc:
            sys.exit(f" fail  {path}: bad regex in a |re value ({exc})")

    @property
    def attack(self):
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", str(t))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="JSONL files/directories (default: evidence/windows/)")
    ap.add_argument("--rules", default=str(HERE / "rules"), help="directory of .yml rules (default: rules/)")
    ap.add_argument("--rule", help="only rules whose file name or title contains this text")
    ap.add_argument("--list", action="store_true", help="list the rules and exit")
    ap.add_argument("--summary", action="store_true", help="one line per rule")
    ap.add_argument("--skew", action="append", help="HOST=+SECONDS clock correction (repeatable)")
    ap.add_argument("--max", type=int, default=25, help="hits to print per rule (default 25, 0 = all)")
    a = ap.parse_args()

    rdir = Path(a.rules)
    files = sorted(rdir.glob("*.yml")) + sorted(rdir.glob("*.yaml"))
    if not files:
        sys.exit(f" fail  no rules in {rdir}")
    rules = [Rule(f) for f in files]
    if a.rule:
        k = a.rule.lower()
        rules = [r for r in rules if k in r.path.name.lower() or k in str(r.title).lower()]
        if not rules:
            sys.exit(f" fail  no rule matches {a.rule!r} (try --list)")
    if a.list:
        for r in rules:
            ls = r.logsource.get("category") or r.logsource.get("service")
            print(f"  {r.path.name:<46} {r.level:<9} {ls:<36} {' '.join(r.attack)}")
            print(f"  {'':<46} {r.title}")
        return

    skew = L.parse_skew(a.skew)
    events = list(L.load(a.paths))
    hits = defaultdict(list)
    seen = defaultdict(int)
    for ev in events:
        for r in rules:
            if r.ls(ev):
                seen[r.id] += 1
                if r.match(ev):
                    hits[r.id].append(ev)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rules.sort(key=lambda r: (order.get(str(r.level), 5), r.path.name))
    for r in rules:
        hs = sorted(hits[r.id], key=lambda e: L.true_time(e, skew)[0])
        tag = " ".join(r.attack) or "-"
        if not seen[r.id]:
            print(f"\n  BLIND  [{r.level}] {r.title}  ({r.path.name})")
            print(f"         no loaded event matches its logsource {r.logsource} — this rule could not fire.")
            print("         Silence here is not 'clean'. Which log would it need, and do you have it?")
            continue
        hosts = sorted({e["Host"] for e in hs})
        if a.summary:
            span = f"{L.fmt(L.true_time(hs[0], skew)[0], False)} .. {L.fmt(L.true_time(hs[-1], skew)[0], False)}" if hs else ""
            print(f"  {len(hs):>5}  [{r.level:<8}] {r.title:<58} {tag:<12} {','.join(hosts):<20} {span}")
            continue
        print(f"\n  [{r.level}] {r.title}   {tag}   ({r.path.name})")
        print(f"  {len(hs)} hit(s) in {seen[r.id]:,} candidate event(s)" + (f" on {', '.join(hosts)}" if hs else ""))
        for e in hs[: a.max or None]:
            tt, off = L.true_time(e, skew)
            clock = f" (host {L.fmt(e['Time'])})" if off else ""
            print(f"    {L.fmt(tt)}{clock}  {e['Host']:<10} {e['Channel']}/{e['EventID']} #{e['RecordID']}  {L.describe(e)[:150]}")
        if a.max and len(hs) > a.max:
            print(f"    … {len(hs) - a.max} more (--max 0 for all)")
        if hs and r.fps:
            print("    known false positives: " + "; ".join(str(x) for x in r.fps))
    sys.stdout.flush()
    if not a.summary:
        print("\n  A hit is a lead, not a finding: open the event, pivot on its process GUID, user and time.",
              file=sys.stderr)


if __name__ == "__main__":
    main()

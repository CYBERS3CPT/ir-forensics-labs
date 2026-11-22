#!/usr/bin/env bash
# check-lab.sh — is this VM ready for the course?
#
# Checks every tool the five sessions use and prints how to install what is
# missing. It changes nothing.
. "$(dirname "$0")/lib/common.sh"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  say "usage: ./check-lab.sh        report which course tools are present"
  exit 0
fi

banner "Lab check" "Incident Response and Digital Forensics"
missing=0
chk() {  # chk <command> <apt package> <used in> [optional]
  if command -v "$1" >/dev/null 2>&1; then ok "$(printf '%-10s' "$1") $3"
  elif [[ -n "${4:-}" ]]; then warn "$(printf '%-10s' "$1") $3 — optional"; hint "sudo apt install -y $2"
  else bad "$(printf '%-10s' "$1") $3"; hint "sudo apt install -y $2"; missing=1; fi
}
chk python3  python3        "every session"
chk jq       jq             "every session"
chk column   bsdextrautils  "every session (readable CSV)"
chk sha256sum coreutils     "every session"
chk sqlite3  sqlite3        "session 3 (browser history)"
chk fls      sleuthkit      "session 3 (go further)" optional
chk tshark   tshark         "session 3"
chk capinfos tshark         "session 3"
chk suricata suricata       "session 3 (graded exercise 11)"
chk 7z       p7zip-full     "inspecting archives (on Kali the package is 7zip)" optional
chk xxd      xxd            "session 5 (go further)" optional
chk openssl  openssl        "session 5 (go further)" optional
chk git      git            "git pull before each session" optional

if command -v python3 >/dev/null 2>&1; then
  v=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
  python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,9) else 1)' \
    && ok "python $v" || { bad "python $v is older than 3.9"; missing=1; }
  # Session 2's clocks.py prints Lisbon time next to UTC; that needs tz data.
  python3 -c 'from zoneinfo import ZoneInfo; ZoneInfo("Europe/Lisbon")' 2>/dev/null \
    && ok "tzdata     session 2 (Lisbon time)" \
    || { bad "tzdata     session 2 (Lisbon time)"; hint "sudo apt install -y tzdata"; missing=1; }
fi
if command -v docker >/dev/null 2>&1; then ok "docker     session 3 (optional: run Zeek yourself)"
else hint "docker not found — only needed to run Zeek yourself in session 3 (optional)"; fi

rule
if [[ $missing -eq 0 ]]; then ok "ready"; else warn "install the above, then run this again"; exit 1; fi

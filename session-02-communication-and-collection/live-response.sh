#!/usr/bin/env bash
# live-response.sh — volatile data first, from YOUR OWN Linux VM, and say what it cost
#
#   ./live-response.sh -o /mnt/case                     collect into /mnt/case/collection-<host>-<stamp>/
#   ./live-response.sh -o /mnt/case --ntp pool.ntp.org  ...and measure the clock against an NTP server
#   ./live-response.sh -o DIR --case INC-001 --examiner "Your Name"
#   ./live-response.sh -o DIR --allow-same-fs "lab VM, no external media"
#   ./live-response.sh plan                             print the collection order, run nothing
#
# Order of volatility (RFC 3227): the things that change fastest go first. The
# clock goes before everything, because every timestamp you collect afterwards
# is only as good as your knowledge of that clock.
#
# Every output file gets a SHA-256 the moment it is written, the exact command
# and its exit code go into a transcript, the tools' versions and hashes are
# recorded, and at the end the script reports its OWN footprint: what it
# changed on the system it was examining. A collector that claims to change
# nothing is lying; one that tells you what it changed is evidence-grade.
#
# It refuses to write into a path it is collecting from (/tmp, /var/log, /etc,
# home directories...), and refuses to write to the system disk unless you say
# why with --allow-same-fs. Your own machine only.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit   # a failed collector command is recorded, not fatal

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# Paths this script reads from. Output may not live inside any of them: you
# would be collecting your own output, and overwriting what you came for.
COLLECTED=(/tmp /var/tmp /dev/shm /var/log /etc /proc /run /root /home)

OUT=""; CASE_ID="-"; EXAMINER="-"; NTP=""; SAMEFS_REASON=""
utcn() { date -u '+%Y-%m-%dT%H:%M:%S.%3NZ' 2>/dev/null || utc; }

plan() {
  cat <<'P'
  file   what                              why this early
  -----  --------------------------------  ---------------------------------------------
   00    clock: date, timedatectl, NTP     every later timestamp depends on it
   01    uptime / boot time                tells you what volatile state can still exist
   02-03 processes (full + tree)           processes start and die in seconds
   04    network connections + owners      sockets close in seconds
   05    logged-on users                   sessions end
   06-07 open files, deleted executables   handles close; deleted-but-open files vanish
   08-09 routes, ARP / neighbours          caches expire in minutes
   10    interfaces                        addresses can be DHCP-renewed
   11    kernel modules                    rootkits live here; rarely change, cheap
   ---   less volatile ------------------
   12    mounts                            what disks/shares were attached
   13-14 systemd services and timers       persistence
   15    crontabs                          persistence
   16    /tmp, /var/tmp, /dev/shm listing  attackers' favourite staging (listing, NOT copy)
   17-18 logins: last, lastlog             history of access (wtmp)
   19-20 recent system journal / auth.log  rotates; not volatile in RAM terms
   21    shell histories (copied)          small, high value
   22    users and groups                  changes rarely
  (the numbers are the NN- prefixes of the files it writes)
P
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
[[ $# -eq 0 ]] && usage 1
case "${1:-}" in -h|--help|help) usage 0 ;; plan) banner "Collection order" "RFC 3227 — most volatile first"; plan; exit 0 ;; esac
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out) OUT="${2:-}"; shift 2 ;;
    --case) CASE_ID="${2:-}"; shift 2 ;;
    --examiner) EXAMINER="${2:-}"; shift 2 ;;
    --ntp) NTP="${2:-}"; shift 2 ;;
    --allow-same-fs) SAMEFS_REASON="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) bad "unknown argument: $1"; usage 1 ;;
  esac
done
[[ -n "$OUT" ]] || die "no output directory. Use -o DIR — on separate media, not on the disk you are examining."
need_all date "coreutils" ps "procps" ss "iproute2" ip "iproute2" sha256sum "coreutils"

# ---------------------------------------------------------------------------
# where may we write?
# ---------------------------------------------------------------------------
OUTREAL=$(realpath -m "$OUT")
for p in "${COLLECTED[@]}"; do
  if [[ "$OUTREAL" == "$p" || "$OUTREAL" == "$p"/* ]]; then
    bad "$OUTREAL is inside $p, which this script COLLECTS from"
    hint "writing there would mix your output into the evidence and overwrite what you came for"
    hint "use external media (USB, second disk) mounted elsewhere, e.g. /mnt/case or /media/\$USER/CASE"
    exit 1
  fi
done
mkdir -p "$OUTREAL" 2>/dev/null || die "cannot create $OUTREAL (mount the media and make it writable first)"
dev_out=$(df -P "$OUTREAL" 2>/dev/null | awk 'NR==2{print $1}')
dev_root=$(df -P / 2>/dev/null | awk 'NR==2{print $1}')
if [[ "$dev_out" == "$dev_root" ]]; then
  if [[ -z "$SAMEFS_REASON" ]]; then
    bad "$OUTREAL is on the system disk ($dev_root)"
    hint "every byte written there may overwrite deleted data that is evidence"
    hint "use separate media, or accept it knowingly: --allow-same-fs \"<why>\" (the reason goes in the notes)"
    exit 1
  fi
  warn "writing to the system disk: \"$SAMEFS_REASON\" (recorded)"
fi

HOSTN=$(hostname -s 2>/dev/null || hostname)
START_EPOCH=$(date -u +%s)
CD="$OUTREAL/collection-${HOSTN}-$(stamp)"
mkdir -p "$CD" || die "cannot create $CD"
TRANSCRIPT="$CD/transcript.log"
MANIFEST="$CD/manifest.csv"
: > "$TRANSCRIPT"
printf 'seq,file,started_utc,finished_utc,exit,bytes,sha256,command\n' > "$MANIFEST"
SEQ=0
TOOLS_USED=()

log() { printf '%s  %s\n' "$(utcn)" "$*" >> "$TRANSCRIPT"; }

# grab <name> <description> <command...>   — one artefact, hashed as soon as it exists
grab() {
  local name="$1" desc="$2"; shift 2
  local f; f=$(printf '%02d-%s' "$SEQ" "$name")
  SEQ=$((SEQ + 1))
  local bin="$1"
  [[ "$bin" == "bash" ]] && bin="${GRAB_TOOL:-bash}"
  if ! command -v "$bin" >/dev/null 2>&1; then
    printf '  %-34s %-40s %s\n' "$f" "$desc" "skipped ($bin not installed)"
    log "SKIP  $f  ($bin not installed)  cmd=$*"
    printf '%s,%s,%s,%s,%s,%s,%s,"%s"\n' "$((SEQ-1))" "$f" "$(utcn)" "" "127" "0" "" "${*//\"/\"\"}" >> "$MANIFEST"
    return
  fi
  TOOLS_USED+=("$bin")
  local s e rc bytes h
  s=$(utcn)
  log "RUN   $f  cmd=$*"
  "$@" > "$CD/$f" 2>> "$CD/stderr.log"
  rc=$?
  e=$(utcn)
  bytes=$(wc -c < "$CD/$f" | tr -d ' ')
  h=$(sha256sum "$CD/$f" | awk '{print $1}')
  log "DONE  $f  exit=$rc bytes=$bytes sha256=$h"
  printf '%s,%s,%s,%s,%s,%s,%s,"%s"\n' "$((SEQ-1))" "$f" "$s" "$e" "$rc" "$bytes" "$h" "${*//\"/\"\"}" >> "$MANIFEST"
  printf '  %-34s %-40s %9s B%s\n' "$f" "$desc" "$bytes" "$([[ $rc -ne 0 ]] && echo "  (exit $rc)")"
}

# SNTP in a dozen lines of Python, so the clock check does not depend on which
# NTP client this distribution happens to ship. One UDP packet leaves the host;
# that is footprint, and it is recorded.
ntp_offset() {
  python3 - "$1" <<'PY'
import socket, struct, sys, time
host = sys.argv[1]
EPOCH = 2208988800  # 1900 -> 1970
pkt = b'\x23' + 47 * b'\0'           # LI=0, VN=4, Mode=3 (client)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
t0 = time.time()
s.sendto(pkt, (host, 123)); data, _ = s.recvfrom(48); t3 = time.time()
r = struct.unpack('!12I', data)
t1 = r[8] + r[9] / 2**32 - EPOCH      # server receive
t2 = r[10] + r[11] / 2**32 - EPOCH    # server transmit
offset = ((t1 - t0) + (t2 - t3)) / 2  # positive => local clock is BEHIND the server
delay = (t3 - t0) - (t2 - t1)
print(f"ntp_server={host}")
print(f"local_utc_at_query={time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t0))}Z")
print(f"offset_seconds={offset:+.6f}   (positive: this host is BEHIND the reference; negative: AHEAD)")
print(f"round_trip_delay_seconds={delay:.6f}")
PY
}

clock_block() {
  echo "system_utc=$(date -u '+%Y-%m-%dT%H:%M:%S.%NZ')"
  echo "system_local=$(date '+%Y-%m-%dT%H:%M:%S%z (%Z)')"
  echo "hwclock: $( (hwclock -r 2>/dev/null) || echo 'not readable without root (or no RTC)')"
  echo "--- timedatectl"
  timedatectl 2>/dev/null || echo "timedatectl unavailable"
  if command -v chronyc >/dev/null 2>&1; then echo "--- chronyc tracking"; chronyc tracking 2>/dev/null; fi
  echo "--- reference"
  if [[ -n "$NTP" ]]; then
    ntp_offset "$NTP" 2>&1 || echo "NTP query to $NTP failed — record a manual reference (phone, GPS clock) in your notes"
  else
    echo "no reference queried (--ntp not given). Write down a manual comparison NOW:"
    echo "  this host showed ________ when the reference (________) showed ________"
  fi
}

# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------
banner "Live response — $HOSTN" "case $CASE_ID · examiner $EXAMINER · output $CD"
log "START collection host=$HOSTN case=$CASE_ID examiner=$EXAMINER euid=${EUID:-$(id -u)} pid=$$ ppid=$PPID"
log "COMMAND $0 -o $OUT --case $CASE_ID --examiner $EXAMINER ${NTP:+--ntp $NTP}"
[[ -n "$SAMEFS_REASON" ]] && log "SAMEFS output on system disk; reason given: $SAMEFS_REASON"
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  warn "not running as root: other users' process sockets, open files and some logs will be missing"
  hint "that is a legitimate choice on a lab VM — but it goes in your notes as a limitation"
  log "LIMIT not root: ss -p / lsof / journal are partial"
fi

info "most volatile first"
grab clock.txt                           "clock + reference offset"        clock_block
grab uptime.txt                          "uptime, boot time"               bash -c 'uptime; echo; echo "boot: $(uptime -s 2>/dev/null)"; cat /proc/uptime'
grab processes.txt                       "processes (full)"                ps -eo pid,ppid,user,lstart,etime,stat,args --sort=pid
grab process-tree.txt                    "process tree"                    ps auxfww
grab network-connections.txt             "sockets + owning process"        ss -tunapH
grab logged-on-users.txt                 "logged on now"                   who -a
grab open-files.txt                      "open files (incl. deleted)"      lsof -n -P
GRAB_TOOL=ls grab deleted-but-running.txt "executables deleted from disk"  bash -c 'ls -l /proc/[0-9]*/exe 2>/dev/null | grep "(deleted)" || echo "(none)"'
grab routes.txt                          "routing tables"                  ip route show table all
grab arp-neighbours.txt                  "ARP / neighbour cache"           ip neigh show
grab interfaces.txt                      "interfaces and addresses"        ip -d addr show
if command -v lsmod >/dev/null 2>&1; then
grab kernel-modules.txt                  "loaded kernel modules"           lsmod
else
GRAB_TOOL=cat grab kernel-modules.txt    "loaded kernel modules"           cat /proc/modules
fi

info "less volatile"
GRAB_TOOL=cat grab mounts.txt            "mounts"                          cat /proc/mounts
grab systemd-services.txt                "running services"                systemctl list-units --type=service --state=running --no-pager --no-legend
grab systemd-timers.txt                  "timers"                          systemctl list-timers --all --no-pager
GRAB_TOOL=cat grab crontabs.txt          "crontabs (system + spool)"       bash -c 'for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && echo "### $f" && cat "$f"; done; ls -la /var/spool/cron/crontabs 2>&1; true'
GRAB_TOOL=find grab tmp-listing.tsv      "/tmp /var/tmp /dev/shm listing"  bash -c 'printf "path\tsize\tmtime\tctime\tatime\towner\tmode\n"; find /tmp /var/tmp /dev/shm -xdev -printf "%p\t%s\t%TY-%Tm-%TdT%TH:%TM:%TS\t%CY-%Cm-%CdT%CH:%CM:%CS\t%AY-%Am-%AdT%AH:%AM:%AS\t%u\t%m\n" 2>/dev/null'
# Debian 13 / current Kali replaced the classic wtmp tools with wtmpdb and
# lastlog2; older systems still have last/lastlog. Use whichever exists.
if command -v last >/dev/null 2>&1; then
grab logins-last.txt                     "login history (wtmp)"            last -F -w -n 200
elif command -v wtmpdb >/dev/null 2>&1; then
grab logins-last.txt                     "login history (wtmpdb)"          wtmpdb last -F
else
grab logins-last.txt                     "login history (raw wtmp)"        utmpdump /var/log/wtmp
fi
if command -v lastlog2 >/dev/null 2>&1; then
grab logins-lastlog.txt                  "last login per account"          lastlog2
else
grab logins-lastlog.txt                  "last login per account"          lastlog
fi
grab journal-recent.txt                  "journal, last 24 h"              journalctl --since "-24h" --no-pager -o short-iso-precise
GRAB_TOOL=cat grab auth-log-tail.txt     "auth.log (tail)"                 bash -c 'tail -n 500 /var/log/auth.log 2>/dev/null || echo "no /var/log/auth.log (journal-only system)"'
GRAB_TOOL=cat grab shell-histories.txt   "shell histories (copies)"        bash -c 'for h in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do [ -r "$h" ] && { echo "### $h ($(stat -c "%s bytes, mtime %y" "$h"))"; cat "$h"; }; done; true'
GRAB_TOOL=getent grab users-groups.txt   "accounts and groups"             bash -c 'getent passwd; echo; getent group'

# ---------------------------------------------------------------------------
# tool versions — the binary that produced the evidence is part of the evidence
# ---------------------------------------------------------------------------
{
  echo "collector: $0"
  echo "collector_sha256: $(sha256sum "$0" | awk '{print $1}')"
  echo "bash: $BASH_VERSION"
  echo "kernel: $(uname -srvmo 2>/dev/null || uname -a)"
  echo "os: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  echo
  printf '%-12s %-28s %-66s %s\n' tool path sha256 version
  for t in $(printf '%s\n' "${TOOLS_USED[@]}" | sort -u); do
    [[ "$(type -t "$t")" == "file" ]] || { printf '%-12s %-28s %-66s %s\n' "$t" "(function in this script)" "-" "see collector_sha256"; continue; }
    p=$(command -v "$t")
    v=$("$t" --version 2>/dev/null | head -1)
    [[ -z "$v" ]] && v=$("$t" -V 2>/dev/null | head -1)
    printf '%-12s %-28s %-66s %s\n' "$t" "$p" "$(sha256sum "$p" 2>/dev/null | awk '{print $1}')" "${v:-n/a}"
  done
} > "$CD/tool-versions.txt"

# ---------------------------------------------------------------------------
# footprint — what this run changed on the system it examined
# ---------------------------------------------------------------------------
END_EPOCH=$(date -u +%s)
{
  echo "FOOTPRINT of this collection on $HOSTN"
  echo "run: $(date -u -d "@$START_EPOCH" '+%FT%TZ') -> $(date -u -d "@$END_EPOCH" '+%FT%TZ') ($((END_EPOCH-START_EPOCH)) s)"
  echo
  echo "1. Processes. The collector ran as PID $$ (parent $PPID) and spawned one child per command"
  echo "   ($SEQ commands + hashing). It appears in its own evidence:"
  grep -E "^ *($$|[0-9]+ +$$) " "$CD/02-processes.txt" 2>/dev/null | sed 's/^/     /' | head -5
  echo
  echo "2. Memory. Every command was loaded into RAM, displacing pages that may have held evidence"
  echo "   (freed memory of terminated processes, file cache). Unavoidable; this is why memory"
  echo "   imaging, if needed, comes BEFORE a broad live response, not after."
  echo
  echo "3. Files changed outside the output directory since the start (NOT all necessarily by us):"
  find /tmp /var/tmp /dev/shm "${HOME:-/nonexistent}" -xdev -newermt "@$START_EPOCH" \
       -not -path "$OUTREAL" -not -path "$OUTREAL/*" 2>/dev/null | head -40 | sed 's/^/     /'
  echo "   (empty = nothing observed in those locations)"
  echo
  mo=$(awk '$2=="/"{print $4}' /proc/mounts)
  echo "4. Access times. Mount options for / : $mo"
  case ",$mo," in
    *,noatime,*) echo "   'noatime': reading files did not update access times. (Which also means atime is"
                 echo "   useless as evidence on this system — note that too.)" ;;
    *,strictatime,*) echo "   'strictatime': EVERY file this script read now has a fresh atime." ;;
    *) echo "   'relatime' (default): a read updates atime at most once a day, so the binaries and"
       echo "   files this script read may now show today's atime." ;;
  esac
  echo
  echo "5. Network. $([[ -n "$NTP" ]] && echo "One NTP query (UDP/123) to $NTP left this host." || echo "No network traffic generated by the collector itself.")"
  echo
  echo "6. Logs. $([[ ${EUID:-$(id -u)} -eq 0 && -n "${SUDO_USER:-}" ]] && echo "sudo by $SUDO_USER wrote an entry to the auth log/journal." || echo "No sudo used by this run.")"
  echo "   The interactive shell that launched this script will record the command line in its"
  echo "   history when that shell exits."
} > "$CD/footprint.txt"

log "END collection"

# hashes of everything, last — including the transcript, footprint and versions
( cd "$CD" && sha256sum -- * > SHA256SUMS )
rule
ok "$SEQ artefacts collected into $CD"
ok "manifest: manifest.csv · hashes: SHA256SUMS · transcript: transcript.log"
say ""
info "footprint (also in footprint.txt)"
sed -n '1,12p' "$CD/footprint.txt" | sed 's/^/  /'
say ""
hint "verify now:   (cd \"$CD\" && sha256sum -c SHA256SUMS)"
hint "then custody: ./custody.py new --case $CASE_ID --exhibit <ID> --manifest \"$CD/SHA256SUMS\" ..."

#!/usr/bin/env bash
# pcap-triage.sh — six questions to ask a capture before you open Wireshark
#
#   ./pcap-triage.sh <capture.pcap>                     all six, in order
#   ./pcap-triage.sh <capture.pcap> --section dns       just one
#   ./pcap-triage.sh <capture.pcap> --out triage/       also save each answer to a file
#
# Sections (the six questions):
#   integrity  is this the file I think it is?        sha256 + capinfos
#   protocols  what is in it?                         protocol hierarchy
#   talkers    who talked to whom, and how much?      IP and TCP conversations by bytes
#   dns        which names were asked, first when?    DNS queries + answers
#   http       what crossed in clear text?            HTTP requests, user agents, content types
#   tls        where did the encrypted traffic go?    SNI, server IP, JA3 / JA4, count, first seen
#
# Every timestamp is UTC, taken from the capture (the sensor's clock), never
# from the host the traffic came from. Read-only: nothing is resolved,
# replayed or sent anywhere.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

PCAP=""; ONLY=""; OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --section) ONLY="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) PCAP="$1"; shift ;;
  esac
done
[[ -n "$PCAP" && -f "$PCAP" ]] || die "usage: $0 <capture.pcap> [--section <name>] [--out <dir>]   (--help for more)"
need_all tshark "sudo apt install -y tshark" capinfos "sudo apt install -y tshark"
refuse_root
[[ -n "$OUT" ]] && mkdir -p "$OUT"
export LC_ALL=C
# capinfos prints first/last packet in the VM's local time zone; the promise
# above is UTC, so make the local zone UTC for every tool this script calls.
export TZ=UTC

want() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }
save() { if [[ -n "$OUT" ]]; then tee "$OUT/$1"; else cat; fi; }
# epoch -> "YYYY-mm-dd HH:MM:SS" UTC (mawk and gawk both have strftime with a utc flag)
EPOCH2UTC='function u(e){ return strftime("%Y-%m-%d %H:%M:%S", int(e), 1) }'

if want integrity; then
  banner "1. Integrity — is this the file I think it is?" "hash first, analyse second: the hash goes in your notes before anything else"
  sha256 "$PCAP" | save sha256.txt
  say ""
  # -a/-e first and last packet, -c packets, -u duration, -l/-E link type and encapsulation
  capinfos -a -e -c -u -E -T "$PCAP" 2>/dev/null | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++)h[i]=$i; next}{for(i=1;i<=NF;i++) printf "  %-26s %s\n", h[i], $i}' | save capinfos.txt
  hint "first/last packet are the CAPTURE window, not the incident window. Anything outside it you cannot see."
fi

if want protocols; then
  banner "2. Protocols — what is in it?" "where the frames and bytes are; surprises here decide what you look at next"
  tshark -r "$PCAP" -q -z io,phs 2>/dev/null | sed -n '/^frame/,/^=/p' | grep -v '^=' | sed 's/^/  /' | save protocols.txt
  hint "'media' under http = a body tshark did not recognise (often a download). 'data' under tcp = an unknown protocol."
fi

if want talkers; then
  banner "3. Talkers — who talked to whom, and how much?" "<- is bytes FROM the right-hand host, -> is bytes TO it"
  info "IP conversations, largest first"
  tshark -r "$PCAP" -q -z conv,ip 2>/dev/null | sed -n '6,25p' | grep -v '^=' | sed 's/^/  /' | save conv-ip.txt
  say ""
  info "TCP conversations to port 443/80, by total bytes (top 15)"
  tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null | grep -E ':(443|80) ' | head -15 | sed 's/^/  /' | save conv-tcp.txt
  hint "many SHORT conversations to one IP is a pattern (beaconing); one LONG fat one is another (transfer)."
fi

if want dns; then
  banner "4. DNS — which names were asked, and when first?" "the client asks the internal resolver; the answer tells you the IP to pivot on"
  tshark -r "$PCAP" -Y 'dns.flags.response==1 && dns.qry.type==1' -T fields \
      -e frame.time_epoch -e ip.dst -e dns.qry.name -e dns.a -e dns.resp.ttl 2>/dev/null \
    | awk -F'\t' "$EPOCH2UTC"'
        { k=$3; n[k]++; if(!(k in first)){first[k]=$1; cl[k]=$2; ans[k]=$4} }
        END { for(k in n) printf "%s\t%s\t%4d\t%-45s %s\n", u(first[k]), cl[k], n[k], k, (ans[k]==""?"(no A record)":ans[k]) }' \
    | sort | awk -F'\t' 'BEGIN{printf "  %-19s  %-12s %5s  %-45s %s\n","first answer (UTC)","client","count","name","A"} {printf "  %-19s  %-12s %5s  %s\n",$1,$2,$3,$4}' \
    | save dns.txt
  hint "count = number of answers in this window. A name the browser never shows (no human typed it) that is"
  hint "re-asked on a schedule is worth a column in your notes. So is the first one right after a download."
fi

if want http; then
  banner "5. HTTP — what crossed in clear text?" "full URLs, user agents and content types: the cheapest evidence in the capture"
  info "requests"
  tshark -r "$PCAP" -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.request.method \
      -e http.host -e http.request.uri -e tcp.stream 2>/dev/null \
    | awk -F'\t' "$EPOCH2UTC"'{ printf "  %s  %s -> %-14s %-4s http://%s%s   (tcp.stream %s)\n", u($1), $2, $3, $4, $5, $6, $7 }' \
    | save http-requests.txt
  say ""
  info "user agents"
  tshark -r "$PCAP" -Y 'http.request' -T fields -e http.user_agent 2>/dev/null | sort | uniq -c | sort -rn | sed 's/^/  /'
  say ""
  info "responses: status, content type, length"
  tshark -r "$PCAP" -Y 'http.response' -T fields -e frame.time_epoch -e ip.src -e http.response.code \
      -e http.content_type -e http.content_length -e tcp.stream 2>/dev/null \
    | awk -F'\t' "$EPOCH2UTC"'{ printf "  %s  %-14s %s  %-28s %8s bytes  (tcp.stream %s)\n", u($1), $2, $3, $4, $5, $6 }' \
    | save http-responses.txt
  hint "an archive or executable content type from a host you have never seen is the start of a timeline."
  hint "carve it with ./carve.sh — never by double-clicking in Wireshark on a machine you care about."
fi

if want tls; then
  banner "6. TLS — where did the encrypted traffic go?" "no decryption: the ClientHello is in clear, and it says a lot"
  tshark -r "$PCAP" -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.dst \
      -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4 2>/dev/null \
    | awk -F'\t' "$EPOCH2UTC"'
        { k=$3 "\t" $2 "\t" $5; n[k]++; if(!(k in f)) f[k]=$1
          if(!((k SUBSEP $4) in seen)){ seen[k SUBSEP $4]=1; nj[k]++ } }
        END { for(k in n) printf "%s\t%d\t%d\t%s\n", u(f[k]), n[k], nj[k], k }' \
    | sort \
    | awk -F'\t' 'BEGIN{printf "  %-19s %5s %5s  %-36s %-15s %s\n","first ClientHello","count","#ja3","SNI","server IP","JA4"}
                 {printf "  %-19s %5s %5s  %-36s %-15s %s\n",$1,$2,$3,$4,$5,$6}' \
    | save tls-sni.txt
  say ""
  hint "#ja3 = distinct JA3 values for that SNI+JA4. Browsers permute their extensions, so their JA3 changes on"
  hint "every connection while JA4 (sorted) stays put. One stable JA3/JA4 across many connections = one program."
  hint "certificates (TLS 1.2 only — in 1.3 they are encrypted):  tshark -r <pcap> -Y tls.handshake.type==11 -V"
fi

say ""
rule
[[ -n "$OUT" ]] && ok "answers saved in $OUT/"
cat <<'NEXT'
  Next: put a time and a source on every line you keep.
    python3 beacon-hunt.py evidence/zeek/conn.log     is anything calling home on a schedule?
    ./carve.sh <pcap>                                   what was downloaded, and its hash
NEXT
exit 0

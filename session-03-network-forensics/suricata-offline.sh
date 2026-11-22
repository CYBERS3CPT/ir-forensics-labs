#!/usr/bin/env bash
# suricata-offline.sh — run your rules against a capture, offline, and show
#                       what fired and why
#
#   ./suricata-offline.sh <capture.pcap>                    uses rules/local.rules
#   ./suricata-offline.sh <capture.pcap> <file.rules>       your own rule file
#
# Steps: (1) refuse to run with unfilled placeholders, (2) validate the rule
# file, (3) suricata -r over the capture with ONLY your rules (-S), checksum
# checks off (-k none: captured traffic often has offloaded checksums), output
# to out/suricata-<timestamp>/, (4) summarise eve.json: alerts with the field
# that matched (SNI, URL, query), and how many TLS/HTTP/DNS events Suricata
# parsed — if it parsed zero TLS sessions, a TLS rule can never fire, and the
# problem is not your rule.
#
# Offline mode: nothing is captured, nothing is sent. Does not need root.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

[[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]] && { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
PCAP="$1"
RULES="${2:-$(dirname "$0")/rules/local.rules}"
CFG="${SURICATA_CFG:-/etc/suricata/suricata.yaml}"
[[ -f "$PCAP" ]] || die "no such capture: $PCAP"
[[ -f "$RULES" ]] || die "no such rule file: $RULES"
need_all suricata "sudo apt install -y suricata" jq "sudo apt install -y jq"
refuse_root
export LC_ALL=C
# eve.json timestamps are written in the machine's local zone (+0100, -0500...).
# The summary below promises UTC, so run Suricata with UTC as its local zone.
export TZ=UTC

banner "Suricata, offline" "$(basename "$PCAP")  ·  rules: $RULES"

# 1. placeholders left in active (uncommented) rules?
if grep -vE '^\s*#' "$RULES" | grep -qE '__[A-Z]+__'; then
  bad "the rule file still has placeholders:"
  grep -nE '__[A-Z]+__' "$RULES" | grep -vE '^[0-9]+:\s*#' | sed 's/^/     /'
  hint "fill them in (see the comments above each rule), then run this again."
  hint "a rule with a placeholder is valid syntax that matches nothing: Suricata would say 'zero alerts' and mean it."
  exit 1
fi

# One fresh directory per run: Suricata APPENDS to an existing eve.json, so two
# runs in the same second would otherwise mix their alerts.
mkdir -p out
OUT=$(mktemp -d "out/suricata-$(stamp)-XXXX")
# Do not touch the system's socket or rule cache: we are a user replaying a file.
SETS=(--set unix-command.enabled=no --set detect.sgh-mpm-caching=no)

# 2. validate
info "validating $RULES"
if ! suricata -T -c "$CFG" -S "$RULES" -l "$OUT" "${SETS[@]}" >"$OUT/validate.txt" 2>&1; then
  bad "rule file does not load:"
  grep -iE 'error|E: ' "$OUT/validate.txt" | head -10 | sed 's/^/     /'
  exit 1
fi
nrules=$(grep -cE '^\s*(alert|drop|pass|reject)' "$RULES" || true)
ok "$nrules rule(s) load"

# 3. run
info "replaying the capture"
suricata -r "$PCAP" -c "$CFG" -S "$RULES" -k none -l "$OUT" "${SETS[@]}" >"$OUT/run.txt" 2>&1 \
  || { bad "suricata failed:"; tail -5 "$OUT/run.txt" | sed 's/^/     /'; exit 1; }
EVE="$OUT/eve.json"
[[ -s "$EVE" ]] || die "no eve.json produced — see $OUT/run.txt"

# 4. summarise
say ""
info "what Suricata parsed (event types in eve.json)"
jq -r '.event_type' "$EVE" | sort | uniq -c | sort -rn | sed 's/^/  /'
say ""
n=$(jq -s '[.[] | select(.event_type=="alert")] | length' "$EVE")
if [[ "$n" -eq 0 ]]; then
  warn "zero alerts"
  hint "check: is the protocol in the list above? is the content exactly what is on the wire (case, trailing dot)?"
  hint "is the direction right (to_server for SNI and URI)? Look at the parsed values with:"
  hint "  jq -r 'select(.event_type==\"tls\") | .tls.sni' $EVE | sort | uniq -c"
else
  ok "$n alert(s)"
  say ""
  info "per rule: count, first and last time (UTC, from the capture), flow"
  jq -r 'select(.event_type=="alert") | [.alert.signature_id, .alert.signature, .timestamp[0:19], (.src_ip+" -> "+.dest_ip+":"+(.dest_port|tostring))] | @tsv' "$EVE" \
    | sort -t$'\t' -k1,1n -k3,3 \
    | awk -F'\t' '{ k=$1"\t"$2; n[k]++; if(!(k in f)) f[k]=$3; l[k]=$3; fl[k]=$4 }
                  END { for (k in n) { split(k,a,"\t"); printf "  sid %-8s %4d  %s -> %s  %-40s  %s\n", a[1], n[k], f[k], l[k], a[2], fl[k] } }' \
    | sort -k2,2n
  say ""
  info "the evidence each alert matched on (first 3 per rule)"
  jq -r 'select(.event_type=="alert") | [.alert.signature_id, .timestamp[0:19],
          ( .tls.sni // (if .http then ((.http.hostname // "") + (.http.url // "")) else null end)
            // (.dns.query[0].rrname? // .dns.rrname? // .dns.queries[0].rrname? // "-") )] | @tsv' "$EVE" \
    | sort -t$'\t' -k1,1n -k2,2 | awk -F'\t' '{ if (c[$1]++ < 3) printf "  sid %-8s %s  %s\n", $1, $2, $3 }'
fi
say ""
hint "full output: $OUT   (eve.json is one JSON object per line: jq is your friend)"
hint "a rule that fires on the evidence is step one. Step two: what ELSE would it fire on? (false positives)"

#!/usr/bin/env bash
# verify.sh — before you read a single log line: is this the evidence you were given?
#
# Checks every file in evidence/ against evidence/SHA256SUMS, checks the tools
# this session uses, and prints what you have: hosts, files, sizes. It never
# writes into evidence/. Your work goes in work/ (created here, ignored by git).
. "$(dirname "$0")/../lib/common.sh"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  say "usage: ./verify.sh      verify the Session 4 evidence hashes and the tools"
  exit 0
fi
cd "$(dirname "$0")"
refuse_root
banner "Session 4 — evidence check" "$(utc)"

need_all python3 "sudo apt install -y python3" jq "sudo apt install -y jq" sha256sum "coreutils"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "python3 is older than 3.9 — the scripts need 3.9+"
ok "python3 $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])'), jq $(jq --version | sed 's/^jq-//')"

# Hash check: a mismatch means you are not analysing what was collected. Stop.
if (cd evidence && sha256sum --quiet -c SHA256SUMS); then
  ok "all $(grep -c . evidence/SHA256SUMS) evidence files match SHA256SUMS"
else
  die "hash mismatch: re-clone the repository; do not analyse altered evidence"
fi

rule
info "Windows event logs (one JSON object per line, evtx_dump shape)"
for f in evidence/windows/*.jsonl; do
  printf '    %-52s %7s events  %6s\n' "$(basename "$f")" "$(wc -l < "$f" | tr -d ' ')" "$(du -h "$f" | cut -f1)"
done
info "Linux: SRV-BKP01 (files as collected; wtmp/btmp are binary)"
(cd evidence/linux/SRV-BKP01 && find . -type f | sort | sed 's|^\./|    |')

mkdir -p work
rule
hint "Work in ./work — never edit, gunzip or 'fix' anything under evidence/."
hint "Next: ./evtx-query.py --stats"

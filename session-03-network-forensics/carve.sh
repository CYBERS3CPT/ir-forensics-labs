#!/usr/bin/env bash
# carve.sh — pull files out of a capture, hash them, and look inside archives
#            without extracting anything to disk
#
#   ./carve.sh <capture.pcap>                    exports to out/carved-<timestamp>/
#   ./carve.sh <capture.pcap> <dir>              exports to <dir>
#
# What it does, in order:
#   1. records the capture's sha256 and the tshark version (your custody line)
#   2. tshark --export-objects for HTTP, SMB, TFTP and IMF (mail)
#   3. sha256 + size + type of every object, written to <dir>/MANIFEST.txt
#   4. for ZIP archives: lists every member with ITS sha256 and sha1, in memory
#      (the inner file is the one that matches host evidence, not the zip)
#
# Objects carved from a capture are hostile until proven otherwise. They are
# saved non-executable, never opened, and nothing is uploaded anywhere.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

[[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]] && { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
PCAP="$1"
[[ -f "$PCAP" ]] || die "no such file: $PCAP"
need_all tshark "sudo apt install -y tshark" python3 "sudo apt install -y python3"
refuse_root
export LC_ALL=C
OUT=$(outdir "${2:-out/carved-$(stamp)}")
umask 077

banner "Carving $(basename "$PCAP")" "export, hash, list — never execute"
{
  echo "# carve.sh manifest"
  echo "# carved_at_utc: $(utc)"
  echo "# capture: $PCAP"
  echo "# capture_sha256: $(sha256 "$PCAP" | cut -d' ' -f1)"
  echo "# tool: $(tshark --version 2>/dev/null | head -1)"
} > "$OUT/MANIFEST.txt"
info "capture sha256 $(sed -n 's/^# capture_sha256: //p' "$OUT/MANIFEST.txt")"

for proto in http smb tftp imf; do
  mkdir -p "$OUT/$proto"
  tshark -r "$PCAP" -q --export-objects "$proto,$OUT/$proto" >/dev/null 2>&1 || true
  rmdir "$OUT/$proto" 2>/dev/null || true
done
chmod -R a-x+X "$OUT" 2>/dev/null || true

n=$(find "$OUT" -type f ! -name MANIFEST.txt | wc -l | tr -d ' ')
if [[ "$n" -eq 0 ]]; then
  warn "no objects exported (encrypted traffic carries no exportable objects — that is normal)"
  exit 0
fi
ok "$n object(s) exported"
say ""
printf '  %-64s %10s  %-28s %s\n' "sha256" "bytes" "type" "file" | tee -a "$OUT/MANIFEST.txt"
find "$OUT" -type f ! -name MANIFEST.txt | sort | while read -r f; do
  h=$(sha256 "$f" | cut -d' ' -f1)
  s=$(wc -c < "$f" | tr -d ' ')
  t=$(file -b "$f" 2>/dev/null | cut -c1-28 || echo "?")
  printf '  %-64s %10s  %-28s %s\n' "$h" "$s" "$t" "${f#$OUT/}" | tee -a "$OUT/MANIFEST.txt"
done

# Archives: list members and hash them from memory. python3's zipfile reads the
# member bytes without writing them anywhere — so nothing executable ever lands
# on this disk, and the hash you get is the one Sysmon or Amcache would show.
find "$OUT" -type f ! -name MANIFEST.txt | while read -r f; do
  python3 - "$f" "$OUT/MANIFEST.txt" <<'PY'
import hashlib, sys, zipfile
path, manifest = sys.argv[1], sys.argv[2]
if not zipfile.is_zipfile(path):
    sys.exit(0)
lines = [f"\n  members of {path.split('/')[-1]} (hashed in memory, not extracted):",
         f"  {'sha256':<64} {'bytes':>10}  {'modified (zip, local time)':<19}  name"]
with zipfile.ZipFile(path) as z:
    for i in z.infolist():
        try:
            data = z.read(i)
        except RuntimeError:
            lines.append(f"  {'(encrypted member: password needed — do not guess on the evidence copy)':<64} {i.file_size:>10}  {'':<19}  {i.filename}")
            continue
        dt = "%04d-%02d-%02d %02d:%02d:%02d" % i.date_time
        lines.append(f"  {hashlib.sha256(data).hexdigest():<64} {i.file_size:>10}  {dt:<19}  {i.filename}")
        # KAPE's CopyLog and Amcache record SHA-1, not SHA-256: give both, so the
        # member can be matched against host evidence without extracting it.
        lines.append(f"    sha1 {hashlib.sha1(data).hexdigest()}")
print("\n".join(lines))
with open(manifest, "a") as m:
    m.write("\n".join(lines) + "\n")
PY
done
say ""
hint "ZIP timestamps are DOS local time with no zone: say so if you quote one."
hint "double extensions (.pdf.lnk, .doc.exe) are the lure, not the file type. The 'type' column is."
ok "manifest: $OUT/MANIFEST.txt"

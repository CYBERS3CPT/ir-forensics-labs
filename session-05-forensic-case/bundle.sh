#!/usr/bin/env bash
# bundle.sh — assemble the whole case into one read-only working bundle.
#
# Tonight you write the report on everything the investigation has: the
# evidence released in Sessions 1 to 4 plus the new items in this folder. This
# script copies all of it into ONE place, verifies every folder against its own
# SHA256SUMS on the way in, makes the copy read-only, and writes a manifest with
# the SHA-256 of every file it now holds.
#
# Why bother, when the files are right there in the repo?
#   - A report cites evidence by ID, and an ID is only meaningful against a
#     fixed, hashed list. The manifest is that list.
#   - The repo is not evidence. A file you edited by accident, or a git pull that
#     changed something, is caught here and not three days later.
#   - Read-only is a habit. Tools that "just open" a file sometimes write to it.
#
# It never modifies the repo. It refuses to overwrite an existing bundle unless
# you say --force, because a bundle you have already cited is itself evidence.
#
# Usage
#   ./bundle.sh                         bundle into ./work/case-bundle
#   ./bundle.sh --out ~/ceres-bundle    somewhere else
#   ./bundle.sh --force                 replace an existing bundle (asks first)
#   ./bundle.sh --verify                re-hash an existing bundle against its manifest
#
# Output
#   <out>/S01 ... <out>/S05             the evidence, read-only, one folder per session
#   <out>/MANIFEST.tsv                  sha256, bytes, session, path   (one line per file)
#   <out>/MANIFEST.sha256               the same hashes, in `sha256sum -c` format
#   <out>/BUNDLE-INFO.txt               when, by whom, from which commit, what was checked
. "$(dirname "$0")/../lib/common.sh"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT="$HERE/work/case-bundle"
FORCE=0
VERIFY=0

# The sessions whose evidence makes up the case, in the order an investigator
# received it. Session 1's alert queue and helpdesk tickets matter tonight too:
# they are where the 10:20 RDP gets its innocent explanation.
SESSIONS=(
  "S01:session-01-ir-methodology"
  "S02:session-02-communication-and-collection"
  "S03:session-03-network-forensics"
  "S04:session-04-log-forensics"
  "S05:session-05-forensic-case"
)

usage() { sed -n '2,/^\. "/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --repo) REPO="${2:?--repo needs a directory}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --verify) VERIFY=1; shift ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

refuse_root
need_all python3 "sudo apt install -y python3"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
  || die "need sha256sum (coreutils) or shasum"

# hash one file, print only the hex digest
hash_of() { sha256 "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------------------
# --verify: is the bundle still what the manifest says it is?
# ---------------------------------------------------------------------------
if [[ $VERIFY -eq 1 ]]; then
  [[ -f "$OUT/MANIFEST.sha256" ]] || die "no manifest at $OUT/MANIFEST.sha256 — build the bundle first"
  banner "Verifying bundle" "$OUT"
  if (cd "$OUT" && sha256 -c --quiet MANIFEST.sha256); then
    n=$(wc -l < "$OUT/MANIFEST.sha256" | tr -d ' ')
    ok "all $n files match MANIFEST.sha256"
    # Files that appeared after bundling are not in the manifest, so -c misses them.
    extra=$(cd "$OUT" && find S0? -type f | LC_ALL=C sort | while read -r f; do
              grep -qF "  $f" MANIFEST.sha256 || echo "$f"; done)
    if [[ -n "$extra" ]]; then
      warn "files in the bundle that are NOT in the manifest:"; say "$extra" | sed 's/^/        /'
      exit 1
    fi
  else
    bad "the bundle no longer matches its manifest — find out why before you cite anything"
    exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
if [[ -e "$OUT" ]]; then
  if [[ $FORCE -eq 1 ]]; then
    warn "$OUT exists. Replacing it changes nothing in the repo, but any evidence"
    warn "IDs you have already cited will be re-derived from the new manifest."
    confirm "replace $OUT?" || die "left it alone"
    chmod -R u+w "$OUT"
    rm -rf "$OUT"
  else
    die "$OUT already exists — use it, or --force to rebuild, or --out somewhere else"
  fi
fi

banner "Case bundle — Ceres Alimentar" "from $REPO"
mkdir -p "$OUT"
INFO="$OUT/BUNDLE-INFO.txt"
{
  say "Case bundle — Ceres Alimentar (INC-2026-007)"
  say "built_utc:   $(utc)"
  say "built_by:    $(id -un)@$(hostname)"
  say "repo:        $REPO"
  if command -v git >/dev/null 2>&1 && git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
    say "repo_commit: $(git -C "$REPO" rev-parse HEAD)"
    dirty=$(git -C "$REPO" status --porcelain -- 'session-*/evidence' 2>/dev/null | wc -l | tr -d ' ')
    say "evidence_files_changed_vs_commit: $dirty"
  else
    say "repo_commit: (not a git checkout)"
  fi
  say ""
  say "per-session checks:"
} > "$INFO"

problems=0
present=0
for entry in "${SESSIONS[@]}"; do
  tag="${entry%%:*}"; dir="${entry#*:}"
  src="$REPO/$dir/evidence"
  if [[ ! -d "$src" ]]; then
    warn "$tag  $dir/evidence — not found (not released yet, or not pulled)"
    say "  $tag  MISSING  $dir/evidence" >> "$INFO"
    continue
  fi
  present=$((present + 1))

  # 1. Verify the source against the folder's own SHA256SUMS, BEFORE copying.
  #    Paths inside SHA256SUMS are relative to evidence/.
  if [[ -f "$src/SHA256SUMS" ]]; then
    listed=0; bad_n=0; gone=0
    while read -r want path; do
      [[ -z "$want" || "$want" == \#* ]] && continue
      path="${path#\*}"            # tolerate binary-mode markers
      listed=$((listed + 1))
      if [[ ! -f "$src/$path" ]]; then
        bad "$tag  listed in SHA256SUMS but missing: $path"; gone=$((gone + 1)); continue
      fi
      got=$(hash_of "$src/$path")
      if [[ "$got" != "$want" ]]; then
        bad "$tag  HASH MISMATCH: $path"; hint "expected $want"; hint "got      $got"
        bad_n=$((bad_n + 1))
      fi
    done < "$src/SHA256SUMS"
    # files in the folder that SHA256SUMS does not vouch for
    unlisted=$(cd "$src" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
               | while read -r f; do awk -v f="$f" '{p=substr($0,67); sub(/^\*/,"",p)} p==f{found=1} END{exit !found}' SHA256SUMS || echo "$f"; done)
    nun=0; [[ -n "$unlisted" ]] && nun=$(printf '%s\n' "$unlisted" | wc -l | tr -d ' ')
    if [[ $bad_n -eq 0 && $gone -eq 0 ]]; then
      ok "$tag  $dir — $listed file(s) match SHA256SUMS"
      say "  $tag  OK       $listed listed, $nun unlisted  ($dir/evidence/SHA256SUMS)" >> "$INFO"
    else
      problems=$((problems + bad_n + gone))
      say "  $tag  FAILED   $bad_n mismatch(es), $gone missing  ($dir/evidence/SHA256SUMS)" >> "$INFO"
    fi
    if [[ $nun -gt 0 ]]; then
      warn "$tag  $nun file(s) not covered by SHA256SUMS — copied, but nobody vouched for them:"
      printf '%s\n' "$unlisted" | sed 's/^/        /' >&2
    fi
  else
    warn "$tag  $dir/evidence has no SHA256SUMS — copied unverified"
    say "  $tag  UNVERIFIED (no SHA256SUMS)" >> "$INFO"
  fi

  # 2. Copy, preserving timestamps (cp -p), then make it read-only.
  mkdir -p "$OUT/$tag"
  cp -Rp "$src/." "$OUT/$tag/"
done

[[ $present -gt 0 ]] || die "found no evidence folders under $REPO — is --repo right?"

# 3. Manifest: hash what is now IN THE BUNDLE (not what was in the repo).
info "hashing the bundle"
(
  cd "$OUT"
  find S0? -type f | LC_ALL=C sort | while read -r f; do
    h=$(hash_of "$f"); b=$(wc -c < "$f" | tr -d ' ')
    printf '%s\t%s\t%s\t%s\n' "$h" "$b" "${f%%/*}" "$f"
  done
) > "$OUT/MANIFEST.tsv.tmp"
{ printf 'sha256\tbytes\tsession\tpath\n'; cat "$OUT/MANIFEST.tsv.tmp"; } > "$OUT/MANIFEST.tsv"
awk -F'\t' '{print $1"  "$4}' "$OUT/MANIFEST.tsv.tmp" > "$OUT/MANIFEST.sha256"
rm -f "$OUT/MANIFEST.tsv.tmp"

nfiles=$(($(wc -l < "$OUT/MANIFEST.tsv") - 1))
nbytes=$(awk -F'\t' 'NR>1{s+=$2} END{print s+0}' "$OUT/MANIFEST.tsv")
manifest_hash=$(hash_of "$OUT/MANIFEST.tsv")
{
  say ""
  say "files:  $nfiles"
  say "bytes:  $nbytes"
  say "MANIFEST.tsv sha256: $manifest_hash"
  say "problems: $problems"
} >> "$INFO"

chmod -R a-w "$OUT"/S0?
chmod a-w "$OUT/MANIFEST.tsv" "$OUT/MANIFEST.sha256" "$INFO"

rule
ok "$nfiles files, $nbytes bytes, read-only, in $OUT"
say "     manifest  $OUT/MANIFEST.tsv"
say "     sha256    $manifest_hash   <- put this in your report's evidence section"
if [[ $problems -gt 0 ]]; then
  bad "$problems integrity problem(s) — see above. Do not cite a file that failed its check;"
  bad "find out why (git status, git pull) and rebuild."
  exit 1
fi
say
hint "next:  ./evidence-register.py $OUT"

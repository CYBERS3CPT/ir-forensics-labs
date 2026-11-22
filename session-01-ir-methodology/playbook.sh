#!/usr/bin/env bash
# playbook.sh — write the playbook before the incident writes it for you
#
# A playbook is not a runbook. A runbook says "isolate the host in the EDR" and
# lists the clicks. A playbook says who decides, what it costs, who gets told,
# which clock starts, and what must be preserved before anyone touches anything.
#
#   ./playbook.sh new [scenario]        interactive: asks the questions that get skipped, writes the template
#   ./playbook.sh blank [scenario]      just the template
#   ./playbook.sh check <playbook.md>   does it answer the questions that matter at 03h00?
#   ./playbook.sh sections              what each section is for, in one line
#
# `check` exits non-zero on any gap, so you can run it until it is quiet.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
ask() { local r; read -r -p "  $1: " r || true; printf '%s' "${r:-${2:-}}"; }
slug() { tr '[:upper:]' '[:lower:]' <<< "$1" | tr -cs '[:alnum:]' '-' | sed 's/^-//; s/-$//'; }

cmd_sections() {
  banner "Playbook sections" "what each one is for — the check looks for all of them"
  cat <<'TXT'
  0  Scope and trigger        when THIS playbook applies, specific enough for whoever is first at 03h00
  1  Roles and RACI           who is Responsible / Accountable / Consulted / Informed, with deputies
  2  Decision rights          which decisions, who takes them, and who deputises out of hours
  3  Triage                   the first hour: verify, scope, rate severity, declare (with UTC time)
  4  Containment options      each option with its BUSINESS COST, who authorises, reversibility
  5  Evidence preservation    what to capture BEFORE containment destroys it
  6  Eradication              what must be removed / reset, and how you know it is gone
  7  Recovery                 restore order, from what, validated how, monitored for how long
  8  Communication + clocks   internal, regulators, insurer, staff, press — each with a deadline and owner
  9  Closure criteria         what must be true to close; "it stopped" is not one
  10 Lessons learned          when, who, and what comes out of it (owned actions with dates)
TXT
}

render() {
cat <<PB
# Playbook — ${SCEN:-<scenario>}

| | |
|---|---|
| Organisation | Ceres Alimentar, S.A. |
| Playbook owner | ${OWNER:-____} |
| Version / last reviewed (UTC) | v0.1 / $(utc) |
| Review cadence | ${CADENCE:-annually, after every use, and after every tabletop} |
| Related | severity matrix, contacts list, backup/restore runbook |

## 0. Scope and trigger

*When this playbook is the right one. Specific enough that whoever is first at
03h00 picks it without asking anybody.*

- TODO: observable triggers (what a user, the helpdesk, the SIEM or EDR would actually report)
- TODO: what is OUT of scope (and which playbook covers it instead)

## 1. Roles and RACI

| Role | Name | Deputy (incl. out of hours) | Authority |
|---|---|---|---|
| Incident manager | ${LEAD:-____} | ${LEAD_DEP:-____} | declares the incident, owns the timeline and the decision log |
| Scribe | ____ | ____ | writes every decision with UTC time, owner and reason |
| Technical lead | ____ | ____ | runs triage, evidence, containment, eradication |
| Communications | ____ | ____ | internal, press, customers — only approved wording |
| Legal / DPO | ____ | ____ | GDPR / NIS2 assessment and notifications |
| Executive sponsor | ____ | ____ | business decisions, budget, ransom question |

| Activity | Incident mgr | Tech lead | DPO / Legal | Comms | Executive | Business owner |
|---|---|---|---|---|---|---|
| Declare the incident | | | | | | |
| Isolate a Tier 1 server | | | | | | |
| Notify CNCS (NIS2) | | | | | | |
| Notify CNPD (GDPR art. 33) | | | | | | |
| Notify the insurer | | | | | | |
| Talk to press | | | | | | |
| Restore from backup | | | | | | |

*R = responsible, A = accountable (exactly one per row), C = consulted, I = informed.*

## 2. Decision rights

| Decision | Who decides | Deputy at 03h00 | Must consult |
|---|---|---|---|
| Declare an incident | ${LEAD:-____} | ${LEAD_DEP:-____} | |
| Isolate / shut down a Tier 1 server | ${DECIDER:-____} | ${DECIDER_DEP:-____} | business owner |
| Disable a privileged account | ____ | ____ | |
| Engage external IR / insurer panel | ____ | ____ | |
| Any contact with the threat actor | ____ | ____ | legal, insurer |

## 3. Triage — the first hour

1. Verify: look at the files / alert yourself. Record what you saw and when (UTC, and which clock).
2. Scope: which hosts, shares, accounts, sites. What else talks to them?
3. Rate severity with the matrix; record the rating with its time. Re-rate later.
4. Declare (or not) and record the **aware** time and the reason. The regulatory clocks start here.
5. Open the decision log. Every decision: time, owner, reason.
6. TODO: Ceres-specific first-hour checks

## 4. Containment options, with their business cost

*The section that makes this a playbook. "Isolate FS01" is an instruction.
"Isolate FS01: Logistics cannot read the delivery schedules, trucks leave at
10:00; evidence in memory is preserved if we do not power off" is a decision.*

| Option | Business cost | Evidence impact | Adversary learns? | Who authorises | Reversible? |
|---|---|---|---|---|---|
| TODO | | | | | |

## 5. Evidence preservation — before containment

- TODO: what, in which order (most volatile first), by whom, stored where, hashed how
- TODO: what must NOT be done (and why)

## 6. Eradication

- TODO: what is removed / rebuilt / reset, and the evidence that it is gone

## 7. Recovery

- TODO: restore order, source (which backup, which date, how verified clean), validation, monitoring period

## 8. Communication and regulatory clocks

*Clocks start at **aware**, not at **confirmed**.*

**Aware moment at Ceres** (in words: what has to be true, who records it, where): ____

| Audience | Trigger | Deadline (from aware) | Owner | Channel |
|---|---|---|---|---|
| Executive | P1 declared | ____ | ____ | ____ |
| CNCS — NIS2 early warning | significant incident | 24 h (EU baseline, art. 23) — check current CNCS guidance | ____ | ____ |
| CNCS — NIS2 incident notification | significant incident | 72 h — check current CNCS guidance | ____ | ____ |
| CNCS — NIS2 final report | | one month after the notification (EU baseline) | ____ | ____ |
| CNPD — GDPR art. 33 | personal data breach | 72 h | ____ | ____ |
| Data subjects — GDPR art. 34 | high risk to individuals | without undue delay | ____ | ____ |
| Insurer | ____ | ____ | ____ | ____ |
| Staff | ____ | ____ | ____ | ____ |
| Customers / press | ____ | ____ | ____ | ____ |

## 9. Closure criteria

- TODO: what has to be true to close (and who signs it off)

## 10. Lessons learned

- TODO: when (date after closure), who attends, blameless format
- TODO: output: actions, each with an owner and a due date
- Where we got lucky — the section people omit and the most valuable one

---
*Generated $(utc). Test it: read it aloud to someone who was not in the room,
and count their questions.*
PB
}

outfile() { printf 'playbook-%s.md' "$(slug "${SCEN:-scenario}")"; }

cmd_blank() {
  SCEN="${1:-ransomware on a file server}"
  local f; f=$(outfile)
  [[ -e "$f" ]] && die "refused: $f exists — it may be your work. Move it or pick another name."
  render > "$f"; ok "wrote $f"; hint "now fill it, then: $0 check $f"
}

cmd_new() {
  SCEN=$(ask "Scenario" "${1:-ransomware on a file server}")
  banner "Playbook — $SCEN" "the questions in the order they get skipped"
  OWNER=$(ask "Owner of this playbook (a person, not a team)")
  CADENCE=$(ask "Review cadence" "annually, after every use, and after every tabletop")
  LEAD=$(ask "Incident manager")
  LEAD_DEP=$(ask "  ...and who deputises out of hours")
  [[ -z "$LEAD_DEP" ]] && { warn "no out-of-hours deputy for the incident manager"
                            hint "the incident that needs a decision at 03h00 is the one where"
                            hint "nobody can reach the person named in the playbook."; }
  DECIDER=$(ask "Who may isolate or shut down a Tier 1 server")
  DECIDER_DEP=$(ask "  ...and who deputises out of hours")
  local f; f=$(outfile)
  if [[ -e "$f" ]]; then confirm "$f exists. Overwrite?" || die "kept $f"; fi
  render > "$f"
  say ""; ok "wrote $f"
  hint "every TODO and ____ left in it is a gap. Fill them in your editor, then:"
  hint "$0 check $f"
}

cmd_check() {
  local f="${1:-}"; [[ -f "$f" ]] || die "usage: $0 check <playbook.md>"
  banner "Checking $(basename "$f")" "the questions that decide whether it works at 03h00"
  local n=0
  q() {  # q <regex> <what> <why>
    if grep -qiE "$1" "$f"; then ok "$2"; else bad "$2"; hint "$3"; n=$((n+1)); fi
  }
  q '^#+ .*(scope|trigger)'          "scope / trigger section"           "whoever is first must know this is the right playbook"
  q '^#+ .*(roles|raci)'             "roles section"                     "who does what, by name"
  q '\| *(R|A|C|I)( *\/ *(R|A|C|I))* *\|' "RACI letters filled in"       "a RACI table with no letters is a list of job titles"
  q '^#+ .*decision'                 "decision rights section"           "who may stop production, and who deputises"
  q 'out of hours|03h00|deputy|deputis' "out-of-hours authority"         "the decision you need at 03h00 is the one nobody is awake to make"
  q '^#+ .*triage'                   "triage section"                    "the first hour, step by step"
  # The template mentions "aware" in passing; only a definition line counts.
  q 'aware moment'                   "'aware' moment defined"            "the regulatory clocks start at aware, not at confirmed: say in words what makes Ceres aware"
  q '^#+ .*contain'                  "containment section"               "this is the section that makes it a playbook"
  q '^#+ .*(evidence|preserv)'       "evidence preservation section"     "containment destroys what you will need later"
  q '^#+ .*eradicat'                 "eradication section"               "removing persistence and credentials, with proof"
  q '^#+ .*recover'                  "recovery section"                  "restore from what, in which order, validated how"
  q '^#+ .*(communic|clock)'         "communication and clocks section"  "every audience with a deadline and an owner"
  q '24 ?h'                          "NIS2 24 h early warning"           "Directive (EU) 2022/2555 art. 23(4)(a)"
  q '72 ?h'                          "72 h (NIS2 notification / GDPR art. 33)" "both run from aware"
  q 'insur'                          "insurer notification"              "most cyber policies have their own clock and their own rules"
  q '^#+ .*closure'                  "closure criteria section"          "'it stopped' is not a criterion"
  q '^#+ .*lesson'                   "lessons learned section"           "actions with owners and dates, or it did not happen"

  # The containment table must have a cost column, and every option must fill it.
  local cost
  cost=$(awk -F'|' '
    BEGIN { IGNORECASE=1; col=0; rows=0; empty=0 }
    /^\|/ {
      if (col==0) { for (i=2;i<NF;i++) if (tolower($i) ~ /cost/) col=i; next_is_sep=(col>0); next }
      if (next_is_sep) { next_is_sep=0; next }
      cell=$col; gsub(/^[ \t]+|[ \t]+$/, "", cell); opt=$2; gsub(/^[ \t]+|[ \t]+$/, "", opt)
      if (opt=="" ) next
      rows++
      if (cell=="" || cell ~ /^_+$/ || cell ~ /TODO|TBD/ || opt ~ /TODO/) empty++
      next
    }
    { if (col>0 && rows>0) { print rows, empty; found=1; exit } }
    END { if (!found) { if (col>0) print rows, empty; else print "nocol" } }' "$f")
  if [[ "$cost" == "nocol" ]]; then
    bad "containment table has no business-cost column"
    hint "an option without its cost is an instruction, not a decision"; n=$((n+1))
  else
    read -r crows cempty <<< "$cost"
    if (( crows < 3 )); then bad "only $crows containment option(s) with a row"; hint "give at least three, including 'do nothing yet'"; n=$((n+1))
    elif (( cempty > 0 )); then bad "$cempty of $crows containment option(s) with no business cost"; hint "every row needs its cost, in business words"; n=$((n+1))
    else ok "containment: $crows options, each with a business cost"; fi
  fi

  # Placeholders read as complete. They are worse than blanks.
  local ph; ph=$(grep -cE '____|\bTODO\b|\bTBD\b|<scenario>' "$f" || true)
  if (( ph > 0 )); then
    bad "$ph line(s) with placeholders (____ / TODO / TBD)"
    grep -nE '____|\bTODO\b|\bTBD\b|<scenario>' "$f" | head -5 | sed 's/^/       /'
    n=$((n+1))
  else ok "no placeholders"; fi

  rule
  if (( n == 0 )); then ok "it answers the questions"
  else bad "$n gap(s)"; fi
  hint "final test: read it aloud to someone who was not in the room. Count their questions."
  (( n == 0 ))
}

case "${1:-}" in
  new)      shift; cmd_new "$@" ;;
  blank)    shift; cmd_blank "$@" ;;
  check)    shift; cmd_check "$@" ;;
  sections) shift; cmd_sections ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac

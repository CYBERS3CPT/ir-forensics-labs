# Incident Response and Digital Forensics — Labs

Exercises for the course *Incident Response and Digital Forensics*, one folder
per session. Five evenings, one incident, worked from the first phone call to
the forensic report.

Read [`CASE.md`](CASE.md) first. Everything else assumes you know who Ceres
Alimentar is and what happened on Wednesday morning.

## Sessions

All sessions run online on Teams, **18h00–21h00** (Lisbon time).

| # | Date | Topic | Folder | Deliverable | Weight | Due |
|---|---|---|---|---|---|---|
| 1 | Mon 23 Nov 2026 | IR methodology, playbook, tabletop | [`session-01-ir-methodology/`](session-01-ir-methodology/) | Triage, severity matrix, playbook, tabletop log | 15 % | Thu 26 Nov, 18:00 |
| 2 | Thu 26 Nov 2026 | Incident communication; NIS2 in Portugal (CNCS); collection | [`session-02-communication-and-collection/`](session-02-communication-and-collection/) | Communication pack: CNCS notifications, CNPD, employees, customers, press | 20 % | Mon 30 Nov, 18:00 |
| 3 | Mon 30 Nov 2026 | Host and network forensics | [`session-03-network-forensics/`](session-03-network-forensics/) | Host and network findings report | 20 % | Thu 3 Dec, 18:00 |
| 4 | Thu 3 Dec 2026 | Log forensics: origin and path of the attack | [`session-04-log-forensics/`](session-04-log-forensics/) | Attack flow reconstruction | 20 % | Wed 9 Dec, 23:59 |
| 5 | Thu 10 Dec 2026 | Practical forensic case and the report | [`session-05-forensic-case/`](session-05-forensic-case/) | Individual forensic report | 25 % | Thu 17 Dec, 23:59 |

The authoritative text for each deliverable (what to hand in, rubric, due
date) is the **Deliverable** section of that session's `EXERCISES.md`.

## Layout

```
CASE.md                                  the organisation, the people, the network
check-lab.sh                             is your VM ready? (changes nothing)
lib/common.sh                            shared shell plumbing (colours, UTC, dependency checks)

session-01-ir-methodology/               triage an alert queue, write a playbook, run a tabletop
session-02-communication-and-collection/ communication, NIS2 in Portugal, deadlines, collection and custody
session-03-network-forensics/            the first workstation, then the capture, Zeek, beacon and exfiltration
session-04-log-forensics/                Windows and Linux logs: origin and path of the attack
session-05-forensic-case/                the whole case, and the report
```

Each session folder has:

- `README.md` — why, what the scripts do, which tools.
- `EXERCISES.md` — what you do in class, what you deliver, how it is assessed.
  **Start here on the night.**
- `evidence/` — the evidence released at that point of the investigation, with
  an `SHA256SUMS` file. Verify it before you start.
- `work/` — created by you (or by the setup step) for everything you produce.
  It is git-ignored, so `git pull` never touches it.

Every script answers `--help`.

## Setup (do this before Session 1)

A **Kali Linux** VM (or any recent Debian/Ubuntu) with:

```bash
sudo apt update
sudo apt install -y tshark wireshark suricata sleuthkit jq sqlite3 python3 tzdata \
                    p7zip-full bsdextrautils openssl git file xxd lsof wtmpdb
git clone https://github.com/CYBERS3CPT/ir-forensics-labs.git
cd ir-forensics-labs
./check-lab.sh
```

`check-lab.sh` tells you what is missing and how to install it; it must end
with `ok ready`. Python scripts need Python 3.9 or newer and use the standard
library only, unless their README says otherwise.

Zeek is optional: the Zeek logs for Session 3 are already in the repository.
If you want to produce them yourself, run Zeek from its container image (see
the Session 3 README) — the Kali package is not always installable.

## Each session

```bash
cd ir-forensics-labs
git pull                                   # get any updates before class
cd session-0N-<name>
(cd evidence && sha256sum -c SHA256SUMS)   # every line must say OK
```

Then follow `EXERCISES.md` from the top. Its first block sets up `work/`.

## Rules of engagement

- **Your own VM only.** The live-response scripts collect from the machine they
  run on. Do not point them at anything you do not own.
- **Nothing gets uploaded.** No hash, domain, file or address from the case goes
  to VirusTotal, urlscan, AbuseIPDB or any other public service. In a real case
  that can warn the adversary and disclose your client. Here it is also
  pointless: everything is fictional.
- **Evidence is read-only.** Work on copies. Every exercise that changes data
  says so, and works in `work/`.
- **UTC, always.** Every timeline you hand in is in UTC, and states which clock
  each timestamp came from.

## Assessment and submission

- The course is assessed **100 % on practical exercises**: one graded
  deliverable per session, weighted as in the table above. The pass mark is
  **9.5 / 20** on the weighted total.
- Each `EXERCISES.md` marks which tasks are graded, gives the rubric, the due
  date and exactly what to hand in.
- **How to submit:** through the assignment announced on the course Teams, one
  archive per session named `S<N>-<student-number>.zip` (for example
  `S3-12345.zip`) unless the session says otherwise. Due times are Lisbon time
  (equal to UTC in November and December).
- Group work happens in class; **every deliverable is individual** unless its
  `EXERCISES.md` says otherwise, and must be in your own words.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied` running `./something.sh` or `.py` | You downloaded a ZIP instead of cloning, and the executable bits were lost. Clone with `git`, or run `chmod +x */*.sh */*.py check-lab.sh`. |
| `sha256sum -c` reports `FAILED` | The evidence was modified, often by line-ending conversion when cloning on Windows. Clone inside the Linux VM, or re-clone with `git -c core.autocrlf=false clone ...`. Never "fix" evidence by hand. |
| `column: command not found` | `sudo apt install -y bsdextrautils` |
| `setlocale: LC_ALL: cannot change locale` warnings | Harmless. Silence them with `export LC_ALL=C.UTF-8`. |
| `python3: ... SyntaxError` or `TypeError` in a script | Python older than 3.9. `./check-lab.sh` reports the version. |
| `zeek: command not found` | Expected. The Zeek logs are in `session-03-network-forensics/evidence/zeek/`. |
| `git pull` refuses because of local changes | You edited a tracked file outside `work/`. `git stash`, pull, and keep your own files in `work/`. |

## Licence

MIT. Use it, adapt it, run it in your own course. The case is fictional and may
be reused.

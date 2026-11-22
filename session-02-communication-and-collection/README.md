# Session 2 — Incident Communication and NIS2 in Portugal

**Exercises:** [`EXERCISES.md`](EXERCISES.md) · **Evidence:** [`evidence/`](evidence/README.md) · **Deliverable:** the communication pack (20 %), due **Monday 30 November 2026, 18:00**

Wednesday, 08:31 UTC: Ceres Alimentar declared an incident. From that moment
the company has to talk — to the CNCS, to the CNPD, to its employees, its
customers, its insurer and a journalist with a 17:00 deadline — and each of
them has a clock. Tonight is about what to say, to whom, by when, and under
which article:

1. **Incident communication.** One voice, facts before hypotheses, every
   audience with its owner, channel and clock — and what never goes out.
2. **NIS2 in Portugal.** The *Regime Jurídico da Cibersegurança* (RJC, annex to
   Decree-Law 125/2025) and *Regulamento* CNCS n.º 756/2026: who must notify,
   what makes an incident significant, the four notifications on MyCiber and
   their deadlines, the other authorities, the recipients of the service — and
   where the Portuguese rules differ from the Directive.
3. **Collection under a notification clock.** A short block: the incident
   response decisions around collection, a live-response demo, and receiving
   the first exhibit with its chain of custody. The forensic fundamentals
   (ACPO, ISO/IEC 27037, order of volatility, chain of custody, Windows and
   Linux artefacts) are in the Blue Team module, Sessions 7 and 8.

```bash
cd ir-forensics-labs/session-02-communication-and-collection
(cd evidence && sha256sum -c SHA256SUMS)      # hash on arrival
mkdir -p work                                 # git-ignored; your output goes here
```

## The scripts

| Script | What it does |
|---|---|
| `clocks.py` | The Portuguese notification deadlines (RJC arts. 42.º–44.º), GDPR, art. 48.º and the insurer, with the EU baseline for comparison, in UTC and Lisbon time; flags late submissions |
| `custody.py` | Chain-of-custody record: JSON + printable form, hash-chained, refuses gaps |
| `live-response.sh` | Volatile-data collection from your own Linux VM, in order of volatility, hashed, with its own footprint |
| `templates/` | The communication pack: the four CNCS notifications, CNPD, employees, customers, staff, press (see its README) |

All of them answer `--help`. Python is standard library only (3.9+).

### `clocks.py` — from awareness, and from the end of the impact

```bash
./clocks.py --aware "2026-03-11 08:31Z"
./clocks.py --aware "2026-03-11 08:31Z" --alt "2026-03-11 08:20Z"          # compare a defensible earlier moment
./clocks.py --aware "2026-03-11 08:31Z" --impact-end "2026-03-16 17:00Z"   # end-of-impact + final report
./clocks.py --aware "2026-03-11 08:31Z" --now "2026-03-13 18:00Z" \
            --submitted pt-initial=2026-03-12T08:52Z                        # what was late, what is left
./clocks.py --aware "…Z" --impact-end "…Z" --submitted … --markdown > work/clocks.md
```

| Row | Basis | Deadline |
|---|---|---|
| *Notificação inicial* (CNCS, MyCiber) | RJC art. 42.º n.º 1 | 24 h after concluding there is, or may be, a significant incident |
| Update of the initial notification | RJC art. 42.º n.º 3 | 72 h from the same moment, when necessary |
| *Notificação do fim de impacto significativo* | RJC art. 43.º | 24 h after the significant impact ends (`--impact-end`) |
| *Relatório final* | RJC art. 44.º n.º 1 | 30 *dias úteis* from the date of the end-of-impact **notification** |
| GDPR breach notification (CNPD) | GDPR art. 33 | 72 h from awareness, where feasible |
| Data subjects · recipients of the service | GDPR art. 34 · RJC art. 48.º | without undue delay |
| Insurer | the policy | 48 h by default (`--insurer-hours`) |
| EU baseline | Directive (EU) 2022/2555 art. 23(4) | 24 h · 72 h · one month after the 72 h notification |

Working days skip weekends and the Portuguese **national** holidays listed at
the top of the script (2025–2027); counting starts the day after the
end-of-impact notification, and the deadline is the end of that day in Lisbon.
It refuses to count through a year it has no holidays for. If the impact ended
within 2 hours of detection (`--detected`), it shows that only the end-of-impact
notification is due (art. 41.º n.º 2).

**It refuses** a timestamp without a time zone ("08:31 on which clock?") and
`--basis confirmed`: the RJC clock starts when the entity concludes that a
significant incident exists **or may come to exist**, not when the
investigation is over.

> **Check the current CNCS *instrução técnica*.** The format, procedure and
> taxonomy of the notifications are set there (RJC art. 41.º n.º 4), not in the
> law. Municipal holidays and the counting convention are questions for
> counsel. The script computes dates; it is not legal advice.

### `custody.py` — one gap defeats the whole record

```bash
./custody.py new --case INC-2026-007 --exhibit EXH-WSFIN07-01 --description "…" \
    --collected-by "…" --when 2026-03-11T12:41:10Z --where "…" --why "…" \
    --manifest evidence/WS-FIN-07_triage/MANIFEST.sha256 --seal CER-0412 -o work/custody-EXH-WSFIN07-01.json
./custody.py transfer work/custody-EXH-WSFIN07-01.json --from "…" --to "…" --when …Z --why "…"
./custody.py verify   work/custody-EXH-WSFIN07-01.json --record --by "Your Name"
./custody.py show     work/custody-EXH-WSFIN07-01.json --text work/custody-EXH-WSFIN07-01.txt
```

Every entry needs **who, when (UTC, with the zone) and why**. A transfer must
come *from* whoever the record says holds the exhibit; entries must be in
order; seal numbers must match. Each entry carries the hash of the previous
one, so editing an old entry by hand breaks the chain and `verify` says which
entry. `verify` also re-hashes every file against the manifest and lists files
that are present but not in it. The record remembers where the files are
*relative to itself*, so a record that travels together with the evidence
still verifies; if only the record moved, point `verify --dir` at the files.

### `live-response.sh` — collect, hash, and admit what it cost

```bash
./live-response.sh plan                                    # the order, and why
./live-response.sh -o /mnt/case --case LAB-02 --examiner "Your Name" --ntp pool.ntp.org
```

Shown as a demo in class; *Go further A* in `EXERCISES.md` runs it on your VM.
It collects in order of volatility (clock first, then processes, network
connections, users, open files, routes, interfaces, modules, then the less
volatile), hashes each artefact as it is written, and ends with
`manifest.csv`, `transcript.log`, `tool-versions.txt`, `footprint.txt` (what
the collection changed) and `SHA256SUMS`.

**It refuses** to write into anything it collects from (`/tmp`, `/var/log`,
`/etc`, `/home`, …) and to write on the system disk unless you give a reason
with `--allow-same-fs "…"` — the reason goes into the transcript. Without root
it still works, and records what it could not see. Your own VM only; see the
README at the top of the repository.

## The WS-FIN-07 package

`evidence/WS-FIN-07_triage/` is exhibit **EXH-WSFIN07-01**, the triage
collection Ceres took from the first workstation. Tonight you **receive** it
(hashes, custody). It is **analysed in Session 3**, which reads it from this
folder.

## Tools

`python3` (3.9+), `tzdata`, `sqlite3`, `sha256sum`; for *Go further A*,
`e2fsprogs` and `lsof`. On Kali:

```bash
sudo apt install -y python3 tzdata sqlite3 e2fsprogs lsof
```

## Reading

- *Regime Jurídico da Cibersegurança*, annex to Decree-Law 125/2025 — arts. 31.º–32.º, 40.º–45.º, 48.º, 61.º (consolidated text on the Diário da República / PGDL sites).
- *Regulamento* CNCS n.º 756/2026 (Diário da República, 2.ª série, 22 June 2026) and the current CNCS *instrução técnica* on incident notification; MyCiber on cncs.gov.pt.
- Directive (EU) 2022/2555 (NIS2), art. 23 · Regulation (EU) 2016/679 (GDPR), arts. 33–34.
- EDPB Guidelines 9/2022 on personal data breach notification.
- NIST SP 800-61 Rev. 3 (April 2025) — incident response recommendations, CSF 2.0 profile.
- RFC 3227 and ISO/IEC 27037:2012 — revised in the Blue Team module, Sessions 7 and 8.

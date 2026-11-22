# Session 2 evidence

Released to the analysts of the insurer's panel firm (you): the exhibit on
Wednesday 11 March 2026 at 16:20 UTC, the messages as they stood on Thursday
12 March, and the response log as it stood on Tuesday 17 March at 12:00 UTC.
Everything is fictional; see [`../../CASE.md`](../../CASE.md).

```bash
sha256sum -c SHA256SUMS        # hash on arrival, before you open anything
```

## Response and communication

| File | What it is |
|---|---|
| `response-log.csv` | The Ceres incident team's log, Wednesday 11 March 07:55 → Tuesday 17 March 11:00. `event_utc` is when it happened, `logged_utc` when someone wrote it down. |
| `draft-press-release.md` | Marketing's draft, circulated Wednesday 17:20. Not approved. |
| `stakeholder-questions.md` | Four messages that reached the team: the CFO, the workers' committee, a journalist, the insurer. |

## `WS-FIN-07_triage/` — exhibit EXH-WSFIN07-01 (analyst package)

In Session 2 you **receive** this exhibit: verify its hashes and record its
chain of custody (exercise 7). It is **analysed in Session 3**, which reads it
from this folder.

The RDP sessions on FS01 came from WS-FIN-07, Marta Antunes's workstation. Before
anyone touched it, the Ceres IT team ran a KAPE triage collection on it. You
get the parsed output, the browser history database, KAPE's own logs and the
collector's notes.

```
collection-notes.txt          the collector's contemporaneous notes (NOT in the manifest — why?)
MANIFEST.sha256               hashes of every file below, as handed over
kape/ConsoleLog.txt           KAPE's run log
kape/CopyLog.csv              what KAPE copied, with SHA-1 of each source file
mout/ProgramExecution/        PECmd (Prefetch), AmcacheParser, AppCompatCacheParser (Shimcache)
mout/FileFolderAccess/        LECmd (shortcut files)
mout/Registry/                RECmd, Kroll batch file
mout/FileSystem/              MFTECmd: $MFT and $J (USN journal) — excerpts
tout/C/Users/m.antunes/AppData/Local/Microsoft/Edge/User Data/Default/History
                              Edge's history database (SQLite), copied raw
```

The `mout` CSVs use the column names of Eric Zimmerman's tools exactly, so
anything you learn here works on real output. They are excerpts: a real
`$MFT` export has a row for every file on the disk.

Not in this package, on purpose: Windows event logs (Session 4) and anything
from the network (Session 3).

**Read `collection-notes.txt` before you build a timeline.** Not every clock
in this case is right.

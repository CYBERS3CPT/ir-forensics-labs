# INITIAL FINDINGS — PRIVILEGED AND CONFIDENTIAL

| | |
|---|---|
| From | Faroleiro DFIR, Lda. (fictional) — on-call lead, engagement for Ceres Alimentar, S.A. |
| To | Mútua Atlântica Seguros (fictional) — cyber claims, claim MA-CYB-26-0193 (policy CYB-2025-004417) |
| Copy | Ceres Alimentar: R. Calado (IT manager), L. Moreira (CFO) |
| Incident | INC-2026-007 |
| Date | 12 March 2026, 18:40 |
| Status | **Preliminary.** Based on the data available at the time of writing. |

## 1. Summary

Ceres Alimentar suffered a ransomware attack by an actor using the "CRS3"
encryptor. The file server FS01 was encrypted during the night of 10–11 March.
Backups on SRV-BKP01 were deleted shortly before encryption. The actor claims
to have stolen data.

Our current assessment:

1. **Initial access and patient zero: WS-IT-02** (workstation of the IT
   helpdesk administrator, J. Pires). The domain administrator account
   `CERES\j.pires` was used throughout the attack.
2. **Lateral movement:** from WS-IT-02 to WS-FIN-07 by RDP at 10:20 on 10 March,
   and from WS-FIN-07 to FS01 by RDP at 11:30 using the same account.
3. **Exfiltration: limited, under 500 MB.**
4. **Encryption:** 02:40–03:52 on 11 March, all three shares on FS01.

## 2. Basis for the assessment

**Patient zero.** DC01 recorded a network logon of `j.pires` from WS-IT-02
(10.20.30.12) to WS-FIN-07 at 10:20:11, followed at 11:30:47 by an RDP logon
of the same account to FS01 originating from WS-FIN-07 (10.20.30.47). The
account is a member of Domain Admins. We assess that the actor controlled the
account on WS-IT-02 and pivoted through WS-FIN-07 to reach the file server.
WS-IT-02 should be treated as the origin of the intrusion.

**Exfiltration.** The FW01 egress log export we received from Ceres IT covers
sessions closed on 10 March between 13:10 and 13:35. It shows 444,306,368 bytes
(~444 MB) sent from FS01 (10.20.10.20) to 192.0.2.77:443. No volume-based alert fired on
FW01 for the rest of the day. We therefore estimate the total volume sent at
**under 500 MB**, well below the 2.1 GB claimed on the actor's portal, which
we assess as exaggerated (a common negotiation tactic).

Given that volume, the data taken is most likely limited to part of the
Finance share. **We consider it unlikely that HR data was exfiltrated**; the
GDPR notification analysis for the HR data may therefore focus on
availability (encryption) rather than confidentiality.

**Encryption and anti-forensics.** On FS01 a service `UpdSvc` was installed at
02:36:15 pointing to `C:\PerfLogs\Admin\crs.exe`; volume shadow copies were
deleted at 02:37:44 and the Security event log was cleared at 02:38:30
(Event 1102). Files were renamed with the `.crs3` extension between 02:40 and
03:52, with a note `LEIA-ME_CRS3.txt` in each folder.

**Backups.** SRV-BKP01 accepted an SSH login as `bkpadmin` from FS01 at
02:10:05 on 11 March after failed attempts for `root` and `admin`; the restic
repositories for FS01 and DC01 were deleted.

## 3. Immediate recommendations

1. Re-image **WS-IT-02** and reset the credentials of `j.pires`.
2. Reset all Domain Admin passwords and the `krbtgt` account (twice).
3. Restore FS01 from the 1 March tape after rebuilding the server.
4. Do not engage with the actor's portal without the insurer's agreement.

## 4. Next steps

Full forensic examination of FS01, WS-FIN-07, WS-IT-02 and SRV-BKP01.
Final report to follow.

*All times in this memo are local time (WET).*

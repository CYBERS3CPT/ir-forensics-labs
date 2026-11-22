# The case: Ceres Alimentar, S.A.

Every session in this course works the same incident, from the first phone call
to the forensic report. You get the evidence in the order an investigator
would: the alerts and the panic first, then the hosts, then the network, then
the logs, and finally everything at once.

> **Everything here is fictional.** The company, the people, the domains
> (`*.example.com`, `*.example.net`, `*.example.org`) and the public IP
> addresses (RFC 5737 documentation ranges) do not exist. The "malware" files
> referenced in the evidence are text placeholders. Nothing in this repository
> executes anything malicious, and nothing needs to be uploaded anywhere.

## The organisation

**Ceres Alimentar, S.A.** is a food wholesale distributor: ambient and chilled
goods to about 1 900 supermarkets, restaurants and hotels. Head office in Maia,
warehouse in Carregado, about 420 employees.

- **Sector:** production, processing and distribution of food — under NIS2 that
  makes it an *important entity*, supervised in Portugal by the CNCS.
- **Personal data:** payroll and HR records for every employee; contacts for
  customers and suppliers. GDPR applies; the supervisory authority is the CNPD.
- **IT team:** six people, business hours only. No 24×7 SOC.
- **Tooling:** Microsoft 365 for mail. On-premises Active Directory
  (`ceres.local`). EDR on workstations, **not** on servers. Sysmon on every
  Windows host, forwarded with the System log to a small Wazuh SIEM. The
  Windows *Security* logs stay on each host. Backups with restic to a Linux
  server; monthly tape kept off-site.
- **Cyber insurance:** the policy requires notifying the insurer within 48 hours
  and using the insurer's panel incident response firm.

## People you will hear about

| Account | Name | Role |
|---|---|---|
| `m.antunes` | Marta Antunes | Accounts payable clerk |
| `j.pires` | João Pires | IT helpdesk and sysadmin |
| `r.calado` | Rui Calado | IT manager, incident manager on call |
| `a.fonseca` | Ana Fonseca | Data Protection Officer |
| `l.moreira` | Luís Moreira | Chief Financial Officer |
| `s.teixeira` | Sofia Teixeira | IT systems administrator |

## Network

```
                 internet
                    │
            FW01  198.51.100.24 (public)  ── egress log
                    │ 10.20.0.1
     ┌──────────────┴──────────────────────────┐
     │ servers 10.20.10.0/24                   │ workstations 10.20.30.0/24
     │  DC01       10.20.10.10  AD, DNS        │  WS-IT-02   10.20.30.12
     │  FS01       10.20.10.20  file server    │  WS-FIN-07  10.20.30.47
     │  SRV-BKP01  10.20.10.30  backups (Linux)│  … ~380 more
     │  SIEM01     10.20.10.40  Wazuh          │
     └─────────────────────────────────────────┘
```

File shares on FS01: `\\FS01\Finance`, `\\FS01\HR`, `\\FS01\Logistica`.

## How it starts

Wednesday 11 March 2026, morning. A warehouse supervisor cannot open the delivery schedule.
The helpdesk ticket says "Excel diz que o ficheiro está corrompido".

That is all you know in Session 1. Each session folder has the evidence that
becomes available at that point of the investigation.

## Time

Portugal is on WET (UTC+0) on the dates of the incident, so local time and UTC
coincide. Write every timestamp in UTC anyway, and say which clock it came from.
Not every clock in this case is right.

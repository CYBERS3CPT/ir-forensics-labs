# Templates — the communication pack

Skeletons for the messages a significant incident needs in Portugal, in its
first weeks. They are **not** forms to fill in mechanically: every `> GUIDANCE`
block says what the field is for, which article asks for it, and the mistake
people make there. Delete the guidance before anything is sent.

| File | Goes to | Basis | Clock |
|---|---|---|---|
| `cncs-1-initial-notification.md` | CNCS, on MyCiber | RJC art. 42.º n.º 1–2 — *notificação inicial* | 24 h from concluding there is / may be a significant incident |
| `cncs-2-update.md` | CNCS, on MyCiber | RJC art. 42.º n.º 3 — update of the initial notification | 72 h from the same moment, when necessary |
| `cncs-3-end-of-impact.md` | CNCS, on MyCiber | RJC art. 43.º — *notificação do fim de impacto significativo* | 24 h after the significant impact ends |
| `cncs-4-final-report.md` | CNCS, on MyCiber | RJC art. 44.º — *relatório final* (and *relatório intercalar*) | 30 *dias úteis* from the end-of-impact notification |
| `gdpr-art33-cnpd.md` | CNPD | GDPR art. 33 | 72 h from awareness, where feasible |
| `gdpr-art34-data-subjects.md` | the people whose data is affected | GDPR art. 34 | without undue delay |
| `recipients-art48.md` | customers (recipients of the service) | RJC art. 48.º | without undue delay; free; plain language |
| `internal-holding-statement.md` | all staff | — | first hours |
| `press-holding-statement.md` | media, on request | — | ready before the first call |

`RJC` = *Regime Jurídico da Cibersegurança*, approved in the annex to
Decree-Law 125/2025 and operationalised by *Regulamento* CNCS n.º 756/2026.

Conventions used in every template:

- `{{FIELD}}` — replace with a fact. If you do not know it, write
  **"unknown at the time of writing"** and when you expect to know. Never guess.
- Facts and hypotheses go in **separate** sentences, and hypotheses are labelled
  as such ("our current assessment is…").
- All times in UTC with the `Z`, and the local time in brackets where a reader
  outside the response team will read it.
- Every external message has an **owner** (who signs) and an **approver**
  (who authorised it), recorded in the response log.

The CNCS notifications are submitted on **MyCiber**; their format, procedure and
taxonomy are set by a CNCS *instrução técnica* (RJC art. 41.º n.º 4). The CNPD
has its own breach-notification form. These skeletons follow the minimum content
the law requires — map them onto the official forms, do not send them instead,
and **check the current CNCS *instrução técnica* and CNPD form** before you rely
on any field list here.

# *Notificação do fim de impacto significativo* — {{ENTITY}} — {{INCIDENT_REF}}

> GUIDANCE — RJC art. 43.º n.º 1: without undue delay and **within 24 hours
> after the significant impact ends**. Decide — and record — the moment the
> impact ended, with the evidence (service restored, users working again). It
> matters twice: it starts this 24-hour clock, and the **date you send this
> notification starts the final report's 30 *dias úteis*** (art. 44.º n.º 1).
> If the incident was resolved within 2 hours of detection, this is the only
> notification due (art. 41.º n.º 2).

| Field | Content |
|---|---|
| Initial notification / update: sent at, references | {{ }} |
| Significant impact ended at | {{YYYY-MM-DD HH:MM Z}} — evidence: {{ }} |
| This notification sent at | {{YYYY-MM-DD HH:MM Z}} (deadline {{impact end + 24 h}}) |
| Final report due (30 *dias úteis* from this notification) | {{YYYY-MM-DD}} — computed with `clocks.py`, checked by {{ }} |

## Minimum content (art. 43.º n.º 2)

**(a) Update of the information in the initial notification**, if any:
{{ }}

**(b) Brief description of the measures adopted to resolve the incident:**
{{ }}

**(c) The impact at the moment the significant impact ended:**
- (i) users affected by the disruption: {{ }}
- (ii) duration of the incident: {{from … to …, in UTC}}
- (iii) geographical distribution, including cross-border impact: {{ }}
- (iv) **estimated time for full recovery** of the services: {{ }}

> GUIDANCE — "end of significant impact" is not "incident closed". Say what is
> still going on (e.g. identity rebuild, monitoring) and why it is no longer
> significant impact.

---
Approved by: {{ }} · Submitted by: {{ }} at {{HH:MMZ}} · MyCiber reference: {{ }}

# *Notificação inicial* to the CNCS — {{ENTITY}} — {{INCIDENT_REF}}

> GUIDANCE — RJC (annex to DL 125/2025) art. 42.º n.º 1: sent **as soon as the
> entity concludes that there is, or may come to be, a significant incident**,
> without undue delay and **within 24 hours of that conclusion** — unless that is
> incompatible with mitigating or resolving the incident. Submitted on the CNCS
> platform, **MyCiber** (art. 40.º n.º 6). "May come to be" is the point: you
> send what you know, marked as preliminary. The format, procedure and taxonomy
> (categories of cause and effect) come from a CNCS *instrução técnica*
> (art. 41.º n.º 4) — **check the current one** and map this skeleton onto the
> platform's fields. Exception: if the incident is resolved within 2 hours of
> detection, only the end-of-impact notification is due (art. 41.º n.º 2).

| Field | Content |
|---|---|
| Entity | {{legal name, NIF}} · category: *entidade essencial / importante / pública relevante* · sector |
| Concluded there is / may be a significant incident at | {{YYYY-MM-DD HH:MM Z}} — who concluded it, on what basis |
| This notification sent at | {{YYYY-MM-DD HH:MM Z}} (deadline {{+24 h}}) |
| If later than 24 h: why | {{the only exception in art. 42.º n.º 1: incompatible with mitigation/resolution}} |

## Why we consider it significant (art. 40.º n.º 3 and n.º 4)

> GUIDANCE — the RJC parameters, applied to YOUR service: (a) users affected,
> (b) total users of the disrupted service, (c) duration, (d) severity of the
> disruption, (e) scale of the economic and social impact; plus the thresholds
> of the CNCS *instrução técnica* and the EU implementing acts (art. 40.º n.º 4).
> One line per parameter, with numbers or "unknown, being assessed".

| Parameter | Assessment |
|---|---|
| (a) Users affected | {{ }} |
| (b) Total users of the service | {{ }} |
| (c) Duration so far | {{ }} |
| (d) Severity of the disruption | {{ }} |
| (e) Economic and social impact | {{ }} |

## Minimum content (art. 42.º n.º 2)

**(a) Representative for contact by the CNCS** (if different from the
*ponto de contacto permanente*, art. 32.º): {{name, phone, email}}

**(b) Start of the incident** — or, if it cannot be determined, its detection:
{{YYYY-MM-DD HH:MM Z}} · {{start / detection}} · confidence {{low/medium/high}}

**(c) Brief description**, with the category of cause and the effects according
to the CNCS taxonomy, and detail where possible:

> GUIDANCE — facts in one paragraph, hypotheses labelled in another. No cause
> you have not established. "Suspected malicious act (ransom note found)" is a
> fact about what you saw.

{{FACTS}}

{{CURRENT ASSESSMENT — labelled as such}}

**(d) Estimated impact:**
- (i) users affected by the disruption: {{ }}
- (ii) duration: {{ }}
- (iii) geographical distribution, **including cross-border impact**: {{ }}
- (iv) other relevant information: {{measures taken so far, with times; whether personal data may be involved}}

## Other notifications (art. 40.º n.º 5 and n.º 7)

Notified or to be notified separately: CNPD {{yes/planned/no}} · Polícia
Judiciária / Ministério Público {{ }} · other {{ }}. (These are not replaced by
this notification; the platform may allow simultaneous submission under a
protocol between the authorities — art. 40.º n.º 7.)

## Next

Update of this notification, if necessary, by {{aware + 72 h, UTC}} (art. 42.º n.º 3).

---
Approved by: {{name, role}} at {{HH:MMZ}} · Submitted by: {{name}} · MyCiber reference: {{ }}

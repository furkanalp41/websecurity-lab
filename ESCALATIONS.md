# ESCALATIONS

Jointly-edited by **newlab** (BUILDER) and **denetle** (AUDITOR). An escalation is
opened when the same finding recurs across two review exchanges without resolution,
or for a charter-level policy question, a critical security disagreement, or an
`-r3`-without-convergence batch. Neither session works the affected thread while its
escalation is open; unrelated batches continue.

## Format

One H2 per escalation:

```
## esc-NNNN — <one-line topic> — [OPEN | RESOLVED-<disposition>]
```

Followed by:

1. **Metadata** — opened_at (ISO-8601 UTC), batch_id, opener.
2. **Escalation JSON** — a fenced ```json block matching the `escalation` schema in
   `docs/collab-protocol.json` (escalation_id, topic, positions[], prior_rounds[], recommendation).
3. **Discussion** — the other session appends its analysis.
4. **Human decision** — left blank until the operator writes into it.
5. **Resolution** — closing line; header flipped to `RESOLVED-<disposition>`.

Handshake: opener appends the entry on side branch `chore/esc-NNNN`, opens a PR labeled
`escalation`, SendMessages the other session, then both `SendUserFile` this file to the
operator with `status: "proactive"` and a one-line caption. Work resumes only after the
operator writes the decision.

---

_No escalations yet._

# Security review — 2026-08-18 wave 3

Scope: a standard repository-mode review (Codex, with Daybreak Blue) of
`d26b892`. Seven findings: two medium, five low, all high confidence. Coverage
44/147 files; no live Windows/IIS/ADCS reproduction.

**Two were already closed at HEAD.** This scan and the earlier rescan examined
the same commit in parallel, so its F5 (CRL redirect same-host/DNS-rebinding)
and F7 (twin migration leaves duplicates active) are the rescan's F2 and F1,
fixed in `83abd62` and covered by
`tests/test_security_review_2026_08_18_rescan.py`. Nothing further was needed
for either; the fixes match both reports' remediation.

Of the five genuinely new findings, **four are fixed and one is deliberately
deferred**. Suite: 736 → **756 pytest + 1 skipped**, ruff and mypy clean.

## Finding 1 (medium) — disposition 21 was read as proof of revocation

The RA already refuses reason 8 (`removeFromCRL`) on the ACME revoke route, and
already refuses it as *CRL* evidence. The CA-side tooling did not.

`scripts/lib/RevocationLib.ps1` records what the Plan 004 lab spike established,
and it is the whole finding:

> a certificate placed on hold and then given reason 8 ends up "off the CRL and
> valid" while ADCS keeps its DB Disposition at 21.

So disposition alone cannot decide revocation — and two places treated it as if
it could:

- **`Revoke-Cert.ps1` / `Test-SerialRevokedAtCa`** returned `$true` for any
  disposition-21 row. That makes the caller exit **6** — "already revoked, go
  confirm to the RA" — which drains the serial off the RA's pending-revocation
  feed and records `revocation-ca-confirmed`. For a reason-8 row that is a
  containment failure written down as a success.
- **`reconcile_revocation.py`** classified disposition 21 as revoked, so a
  reason-8 certificate the RA had revoked reported **in sync**, and the whole run
  reported PASS.

**Fixed** on both sides, using the technique the script already trusts for
locale independence — restrict on the numeric value rather than parse a
localized column:

- `Test-SerialRevokedAtCa` adds a third query,
  `Disposition=21,Request.RevokedReason=8`. A match means the row is the
  un-revoke, so it returns `$false` and the caller re-revokes. Same fail-safe
  direction as the existing `Disposition=20` self-check: re-revoking a genuinely
  revoked certificate is harmless, skipping a live one is not.
- `Reconcile-Revocation.ps1` exports `Request.RevokedReason`, and the reconciler
  treats disposition 21 + reason 8 as **active at the CA**.
- A disposition-21 row with **no** reason is still revoked. An older export, or a
  CA that does not surface the column, must not turn every revoked certificate in
  the estate into drift.

The reason line is matched in the three shapes certutil emits
(`0x8 (8)`, `8`, and the schema name), because the export format is one of the
things no Linux test can prove.

## Finding 2 (medium) — "required off-box audit" only meant "configured"

`audit_offbox_required` asserted that a `SiemEmitter` had been *constructed* from
syntactically valid config. The emitter's own docstring recorded the reason —
a network reachability probe was deliberately optional so startup would not block
on it (C-2).

That decision is right for the optional case and wrong for the required one. A
revoked HEC token, a wrong index, or an endpoint answering 403 to everything
passed every check, so the RA started and issued certificates believing an
off-box audit trail was in force while nothing left the host — and that trail is
precisely the control meant to survive a compromise *of* this host.

**Fixed**, scoped to the required case so the optional path keeps its original
behaviour:

- `SiemEmitter.probe_offbox_delivery()` performs a real delivery. For HEC it
  POSTs a probe event and requires a 2xx. `create_app` calls it **only** when
  `audit_offbox_required` is set, and refuses to start on failure.
- For UDP syslog the probe reports success and **says what it did not prove** —
  UDP cannot acknowledge, so the honest answer is "the socket accepted the
  datagram", with a pointer to `syslog_proto=tcp` for an acknowledged path. A
  probe that implied more than it established would be the same defect in a new
  place.
- Delivery health is now counted, not only logged: `offbox_failures` (consecutive),
  `offbox_delivered`, `offbox_last_error`, with the first failure and every
  hundredth escalating to ERROR — the same shape as the backpressure counter
  beside it, so a total outage is visible without the log becoming the flood.

**Not implemented, and it is an owner decision rather than an oversight:** the
report also suggests durably spooling unsent events and *failing readiness or
sensitive actions* after a grace period without delivery. There is no readiness
endpoint to fail, and making a SIEM outage stop issuance is an availability
trade-off with real operational consequences — a HEC blip would halt certificate
renewal estate-wide. The startup probe closes the misconfiguration case, which is
the reachable one; the sustained-outage case now has counters an operator can
alarm on. Whether an outage should *stop issuance* is a call for the owner.

## Finding 4 (low) — the certsrv response cap ran after buffering

Every certsrv call was non-streaming, so `requests` had the whole body resident
before `_capped_body` looked at its size — including the declared
`Content-Length` check, which was equally late. The existing comment recorded
this as a deliberate trade, on the grounds that the transport is mutually
authenticated to the CA with channel binding.

The trade is defensible, but it was cheaper to close than the comment assumed.
`_NoRedirectSession` already exists precisely so the production factory can
change transport behaviour without touching the `HttpSession` protocol or any
test fake — so `stream=True` goes there, alongside `allow_redirects=False`.

**Fixed:**

- `_NoRedirectSession` streams. `_read_capped_body` refuses an oversized declared
  length **before reading a byte**, then reads incrementally and stops one byte
  past the cap. Call sites take the returned bytes instead of `.content`/`.text`,
  because with streaming enabled those would read the whole body and reintroduce
  exactly what this bounds.
- A response without `.raw` (the transport-only unit fakes) falls back to
  `.content`, so nothing in the test suite had to change shape.
- The Negotiate 401 challenge drain was `response.content` — unbounded, on the
  issuance path, before any enrollment-layer cap could see it.
  `_bounded_drain` reads at most 64 KiB and closes the connection rather than
  draining past it. The bytes are discarded either way; the point is that the
  peer no longer chooses how much memory that costs.

One test-side finding fell out of this: `_FakeResponse` let `text` and `content`
drift, so a fake that set only `text` had empty `content`. That was invisible
while the leg read `.text` for prose bodies and `.content` for binary ones. The
fake now derives one from the other, as a real response does.

## Finding 6 (low) — the confirmation flag committed before its audit event

`ca_crl_updated` was flipped and committed on one connection; the
`revocation-ca-confirmed` audit row was inserted afterwards on another. That flag
is what *removes* the serial from `list_revoked_certificates`, so a crash or an
audit-insert failure in between left the certificate gone from the retry feed
with no event ever recorded — and the route's idempotence check returns early on
that same flag, so no retry could repair it. The evidence that a CA-side
revocation had been confirmed was permanently absent, which is the one thing the
route exists to record.

**Fixed** with `Store.confirm_ca_revocation_with_audit`: one `BEGIN IMMEDIATE`
covers the CAS update and the audit insert, mirroring the existing
revoke-plus-audit precedent. Either the serial stays pending and retryable, or it
is confirmed *and* audited. SIEM fan-out moved after the commit — it is
best-effort by design and must not hold the write open.

## Finding 3 (low) — unbounded audit growth: deliberately deferred

An unauthenticated allowlisted peer can obtain nonces and submit invalid-EAB
`newAccount` requests indefinitely; each rejection inserts a durable audit row,
and nothing bounds cumulative growth.

The finding is correct. It is deferred rather than fixed, for reasons worth
stating rather than leaving as silence:

- **The remediation is a feature, not a patch.** It asks for monitored
  archival/retention with reserved disk capacity, per-source limits on failed
  account creation, and safe aggregation of repeated denials preserving counts,
  timestamps, and tamper-evident continuity. That is a retention subsystem with
  its own security properties — pruning audit evidence is exactly the operation
  an attacker would want — and designing it under time pressure at the end of a
  fix wave is how the last two waves' regressions happened.
- **Retention is already documented as operator-owned.** `docs/operations.md`
  covers it deliberately without shipping an executable pruner.
- **The prerequisites are real.** The peer must pass the mandatory network
  allowlist and sustain the load; the nonce bucket rate-limits the cheapest step.

Tracked as **WI-014** so it is not lost. The honest summary is that the RA has
no audit retention story in code, and that is a known gap rather than a new one.

## Verification

`tests/test_security_review_2026_08_18_wave3.py` — 20 tests over the four fixed
findings. Each mutation-checked: the reason-8 exclusion reverted (5 fail); the
HEC probe made unconditionally successful (2 fail, including the startup gate);
the bounded reader forced back onto `.content` (2 fail); the confirm/audit
transaction split back into two (1 fail).

Suite: 756 pytest + 1 skipped, ruff clean, mypy clean over 31 source files.

**Both PowerShell fixes are unproven wiring.** `Test-SerialRevokedAtCa`'s new
`Request.RevokedReason=8` restrict clause and the export's new column are written
from the documented ADCS schema, and neither the clause nor certutil's actual
output format for that column can be verified from Linux. The reconciler's parse
side *is* covered, across three plausible output shapes. Per the project's
standing convention this is stated rather than implied: **the certutil
interaction for finding 1 needs the live re-proof before it is trusted.** That
debt now includes disposition/reason export behaviour on top of everything
already listed in `docs/pre-pilot-checklist.md` §A.

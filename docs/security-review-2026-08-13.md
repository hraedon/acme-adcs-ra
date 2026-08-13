# Security review — 2026-08-13

Scope: an external static scan of the full repository at `1aa55a5` (v1.8.0)
produced ten findings — nine medium, one low. This document records the
independent validation of each, the remediation, and what remains unproven.

Baseline at review time: v1.8.0, 524 tests passing, `ruff` and `mypy --strict`
clean, 66 Pester tests passing.

**Every finding reproduced.** Before changing any code, each was turned into a
failing test or a direct measurement against the shipped build; none was taken
on the scanner's word. Two were materially different from their one-line
summaries once reproduced, and one carried a second instance the scan did not
name (see *Corrections to the scan* below).

## Method

The scan was explicitly source-only and offline ("No application, tests,
PowerShell, Windows, ADCS, or network-dependent validation was executed"). That
makes it a set of hypotheses, not results — so each was executed:

| Finding | How it was reproduced | Evidence |
| --- | --- | --- |
| 1 — forged CA confirmation | POSTed the confirm endpoint with the admin token, no CA in the loop | `200`, `ca_crl_updated: true`, pending list drained 1 → 0 |
| 2 — unbounded HEC queue | 5 000 events at a dead HEC endpoint | queue depth 4 987, `SimpleQueue`, unbounded |
| 3 — non-atomic issuance audit | fault-injected `record_audit` after the cert row | 1 certificate row, **0** `certificate-issued` events |
| 4 — cleartext admin token | read `Sync-Revocations.ps1`'s URL handling | no scheme check before `Invoke-RestMethod` with the Bearer header |
| 5 — off-box audit fail-open | `audit_offbox_required=True` + empty HEC config | config accepted, `emitter.enabled=False`, app started |
| 6 — rejected-cert orphans | drove a full order through an EKU-violating template | 0 certificate rows, 0 pending revocations, serial absent from the audit event |
| 7 — invalid-nonce writes | bogus nonce against a held write transaction | blocked 5.01 s, then `database is locked` |
| 8 — OfficerRights activation | read the restart and verification control flow | `net start` exit code unchecked; readback printed, never asserted |
| 9 — weak credentials | constructed a config with a 1-char token and 1-byte key | both accepted |
| 10 — malformed JWS types | array EAB header; non-string nonce; non-ASCII payload | three distinct `500`s |

## Corrections to the scan

Recording these because the summary alone would have sent the fix to the wrong
place:

1. **Finding 4 is not a server-side issue.** The one-line summary ("admin token
   may traverse cleartext HTTP") reads as an RA configuration problem. The
   finding is actually in `scripts/Sync-Revocations.ps1`, which sends the
   maintenance Bearer token to whatever `-RaBaseUrl` it is handed. The fix
   belongs in the PowerShell client, not in `RAConfig`.

2. **Finding 10 has a third instance the scan did not name.** Besides the array
   EAB header and the non-string nonce, `_dummy_hmac` — the timing-equalisation
   helper on the *unknown-kid* path — did `f"{protected}.{payload}".encode("ascii")`
   on attacker-controlled input, so a non-ASCII EAB payload raised
   `UnicodeEncodeError` before any signature was checked. Fixed alongside.

3. **Finding 9 understates one consequence.** An EAB `mac_key` decoding to zero
   bytes was treated as a *present* key (`if mac_key is None`), so a configured
   empty key let anyone who knew the kid forge the binding with an empty HMAC
   key. That is an authentication bypass, not just weak-credential acceptance.

## Closed findings

### 1 — Medium: a general maintenance token could forge a CA-side revocation confirmation

`POST /acme/admin/revocations/{serial}/confirm` flipped `ca_crl_updated=1` on
the caller's word alone. Any admin-token holder — monitoring, ops tooling, a
stale runbook credential — could drop a **still-valid** certificate off the
retry queue and leave a `revocation-ca-confirmed` success audit behind for a
revocation that never happened. The RA never contacted the CA.

**Fixed**, three ways:

* **Separated authority.** The endpoint now requires a dedicated
  `ACME_RA_REVOCATION_CONFIRM_TOKEN` and **refuses the general admin token**.
  An unset confirm token disables the endpoint rather than falling back.
* **Honest labelling.** The audit event and response carry
  `verification: "agent-asserted"` or `"crl-verified"`. The trail no longer
  implies the RA observed something it did not.
* **Independent evidence (opt-in).** With `ACME_RA_REVOCATION_CONFIRM_CRL_URL`
  set, the RA checks the CA's published CRL — signed by the CA, readable
  without privilege, and the one check that does not rest on the calling
  agent's honesty. `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` makes it
  mandatory (fail closed). The CRL's signature is verified against the issuing
  CA certificate **from the certificate's own stored chain**, and an expired
  CRL is not accepted as evidence.

### 2 — Medium: slow HEC delivery created an unbounded in-memory audit queue

`ThreadPoolExecutor`'s default work queue is an unbounded `SimpleQueue`. With
two workers each able to block for the full 10 s `urlopen` timeout, and
unauthenticated account-creation denials able to generate audit events faster
than delivery, a slow or unreachable HEC endpoint turned the audit path into
memory exhaustion on an issuance-path host.

**Fixed:** the queue is bounded by `ACME_RA_SIEM_HEC_QUEUE_MAX` (default 1000).
Overflow drops the event **from the HEC sink only** — the durable record is the
audit table row, already committed — counts it, and logs the first drop and
every hundredth thereafter, so an outage is visible without the log becoming
the flood.

### 3 — Medium: certificate state and the mandatory issuance audit committed separately

Auditing every issuance is one of this project's hard rules, but the writes
were three independent commits: cert row, order transition, then audit. Fault
injection between them left a stored, serveable certificate with **zero**
`certificate-issued` audit events — exactly the silent issuance the rule exists
to prevent.

**Fixed:** `Store.record_issuance` writes the certificate row, the
processing→valid CAS, and the audit row in **one** transaction, choosing the
event (`certificate-issued` vs `finalize-enrollment-race`) from the CAS result
inside that transaction. SIEM fan-out happens after the commit and stays
fail-open. The issuance event now also carries the serial.

*Residual:* the scan also suggested a durable SIEM outbox so emission survives
a crash. Not implemented — that is a design change rather than a fix, and the
local audit table remains the authoritative trail. Recorded as a follow-up.

### 4 — Medium: the revocation sync agent could send the admin token over cleartext HTTP

`Sync-Revocations.ps1` accepted any `-RaBaseUrl` and attached the maintenance
Bearer token to it. Neither it nor `Register-MaintenanceTasks.ps1` rejected
`http://`, embedded credentials, or an unexpected authority — and a scheduled
task bakes that URL in, so a deployment typo would disclose the token on every
run, forever, with nothing in the task output to show it.

**Fixed:** `Assert-SafeRaUrl` (in `scripts/lib/SyncLib.ps1`, now dot-sourced by
the production script rather than being a test-only copy) validates the URL
**before any credential is attached**: https only, no embedded credentials, no
query, no fragment, no path beyond `/`. `-AllowInsecureUrl` is an explicit
opt-out for a loopback lab and still refuses cleartext to a non-loopback host.
`Register-MaintenanceTasks.ps1` validates the same way before registering.

### 5 — Medium: required off-box audit did not fail startup when the sink was unusable

`audit_offbox_required` validated only the sink *name*. An emitter that
disabled itself — empty `syslog_host`, a non-https or credential-bearing HEC
URL, an empty HEC token, a failed handler setup — still let `create_app`
install the disabled hook and start. The operator would believe the production
off-box audit gate was satisfied while the only audit evidence lived on the
host an attacker is assumed to control.

**Fixed:** `create_app` asserts the **constructed emitter**, not the configured
name, and refuses to start with an actionable message.

### 6 — Medium: rejected post-issuance certificates became untracked CA-side orphans

By the time the SAN, EKU, and CA-capability verifiers run, ADCS has already
issued: the certificate has a serial, is in the CA database, and is trusted
domain-wide. On rejection the RA recorded **nothing** — no certificate row, and
an audit event that did not even carry the serial. The dangerous certificate
the RA had just refused to honour was invisible to the RA's own revocation
workflow, leaving the operator a timestamp and a CA-database search.

**Fixed:** `Store.quarantine_certificate` records it in one transaction as a
`quarantined` certificate row carrying the serial, the ReqID, the bytes, and
the violations; flips the order to `invalid` (terminal); and writes the audit
row. Consequences, each independently tested:

* it is **queued for CA-side revocation** through the existing pull-agent loop
  (`list_revoked_certificates` includes quarantined rows), so no second
  mechanism is needed;
* `get_certificate_by_order` excludes quarantined rows, so a retried finalize
  cannot pick one up and serve it — every caller of that method treats a hit as
  "issuance succeeded, close the loop";
* `_certificate_response` serves only `valid`, making "never served" a property
  of the response builder rather than of its callers;
* the pending-revocations view reports `status`, so an operator can tell a
  routine revocation from a template misconfiguration.

The 500 response is unchanged: a template issuing outside policy is a
server-side fault.

### 7 — Medium: invalid nonces forced SQLite write transactions

A nonce arrives on an unauthenticated POST, before signature, account, or EAB
checks, so an unauthenticated peer chooses it. `consume_nonce` issued the
`DELETE` unconditionally, taking the single writer lock even for a nonce that
could not possibly match. Measured: with a concurrent write transaction open, a
bogus nonce blocked for the full 5 s `busy_timeout` and then raised
`database is locked` — surfacing as a **500**, not a `400 badNonce`. The WI-016
limiter covers `newOrder` and the token bucket covers `new-nonce`; neither
covers this path.

**Fixed:** a `SELECT` fast path rejects unknown/expired nonces as a read (WAL
readers proceed alongside a live writer), and only a nonce that exists reaches
the `DELETE`. Single-use is unchanged — the `DELETE`'s `rowcount` is still the
authority, so two concurrent consumers of the same valid nonce still produce
exactly one winner. Post-fix the same measurement completes in 0.3 ms.

### 8 — Medium: OfficerRights provisioning could report success without reloading the CA restriction

The CA reads `OfficerRights` at service start, so until `certsvc` has actually
restarted, a restriction written to the registry is **not in force**. On the
`Restart-Service` failure path the script ran `net stop` / `net start` without
checking either exit code, then printed the readback without asserting anything
and exited 0. It could therefore report success with the CA stopped, or with
the restriction present on disk but not loaded — the operator believing a
compromised officer was bounded to one template when it was not.

**Fixed:** `net start` failure is fatal; the service must report `Running`; the
process start time must have advanced (proving a real recycle, with a
documented fallback when a non-elevated caller cannot read it); and the readback
now **asserts** that the target officer's ACE is present (add) or absent
(`-Remove`) and that the ACE count matches what the script built. Any failure
exits non-zero. Separately, `Get-OfficerRightsBytes` now reads the registry
provider **first** — the `certutil -getreg` path recovers bytes by regex-scanning
formatted console text, a lossy parse that should not be what a security control
verifies itself against.

### 9 — Medium: load-bearing EAB and admin credentials accepted empty or trivially weak values

No minimum format or entropy validation existed. A one-character admin token
was accepted. Worse, an EAB `mac_key` decoding to zero bytes was treated as a
present key, so a known kid could authenticate with an **empty HMAC key**.

**Fixed:** `RAConfig` enforces at load time — EAB MAC keys must be valid
base64url decoding to ≥ 32 bytes, admin and confirm tokens ≥ 32 characters,
kids non-empty and untrimmed. These floors accept every credential
`scripts/eab.py` generates (`secrets.token_urlsafe(32)`) and reject hand-typed
ones. `allow_weak_credentials` is an explicit opt-out for lab and CI fixtures.
The runtime path also now treats a zero-byte key as absent
(`if not mac_key`), as a second line of defence.

### 10 — Low: malformed JWS field types caused uncaught exceptions

Three unauthenticated `500`s, all from attacker-controlled JSON used according
to expected type without a structural check:

* a decoded EAB protected header that was valid JSON but **not an object**
  reached `.get` → `AttributeError`;
* a truthy **non-string nonce** (object or array) reached SQLite parameter
  binding → `ProgrammingError`, on every JWS-authenticated route;
* a **non-ASCII** EAB payload reached `_dummy_hmac`'s ASCII encode →
  `UnicodeEncodeError` (not named by the scan).

**Fixed:** EAB `protected`/`payload`/`signature` must be strings and the
protected header must be a JSON object; nonces must be strings at the protocol
layer, with a defensive type guard in the store as well; `_dummy_hmac` encodes
in UTF-8, which cannot fail and is equivalent for timing equalisation.

## Verification

* **524 → 573 Python tests**, plus 66 → 81 Pester tests. All green, with
  `ruff` and `mypy --strict` clean.
* **Every new test was mutation-checked.** Each fix was reverted in turn and
  the corresponding tests confirmed to fail — 11 Python mutations and one
  PowerShell mutation, all caught. Two mutations initially survived; both were
  inadequate mutations rather than vacuous tests (the nonce type check has two
  independent guards, so removing one is masked by the other), and were
  rewritten until they bit.
* Two pre-existing tests asserted the **old** finding-6 behaviour ("no cert row
  is created") and were updated to the new contract, deliberately and visibly.

## Proof gaps — what this review did NOT establish

> **Update, 2026-08-13 (later the same day): gaps 1, 2 and 3 are now closed by a
> live lab re-proof** against a real ADCS CA — see the v1.9.0 entry in
> [`pre-pilot-checklist.md`](pre-pilot-checklist.md#validation-log). It also
> found **two defects that only exist off Linux**, one of them in this review's
> own finding-8 fix: `Set-OfficerRights.ps1` aborted on a *successful*
> single-officer provisioning (Windows PowerShell 5.1 gives a bare
> `[pscustomobject]` no `.Count`; pwsh 7 gives it 1, so the Pester suite was
> green), and `Sync-Revocations.ps1` aborted its whole batch on the first failed
> revoke. Both are fixed and re-verified against the CA. **The lesson is gap 3's,
> sharpened:** the problem is not only Windows-only *APIs*, it is Windows
> PowerShell 5.1 *language semantics* that Linux `pwsh` silently differs on — a
> green cross-platform Pester run is not evidence about the CA host.

Stated plainly because the changes touch the issuance and revocation paths:

1. **No live ADCS validation.** All of this was validated on Linux against
   fakes. Per the project's own re-entry rules, the issuance leg changed
   (`record_issuance`, quarantine, the certificate response gate), so this
   earns a live lab re-proof against a real CA before deployment —
   `docs/live-reproof-runbook.md`. **Not done.**
2. **The CRL evidence path has never met a real ADCS CRL.** It *is* tested
   end-to-end against genuinely signed CRLs served over a real socket — DER and
   PEM bodies, a serial present, a serial absent, an expired CRL, a CRL signed
   by the wrong key, a missing issuer in the chain, and a garbage body, each
   producing the intended verdict. But those CAs are synthetic. ADCS CRL
   specifics (delta CRLs, the CDP layout, publication cadence) are unexercised,
   so treat `revocation_confirm_require_crl_evidence` as unproven in production
   until run against the lab CA's published CRL. Note the operational coupling:
   a serial is not on the CRL until the CA next publishes, and on the default
   least-privilege path the agent cannot force a republish.
3. **The PowerShell changes were parse-checked and unit-tested on Linux
   `pwsh`, not run on a CA.** `Set-OfficerRights.ps1`'s new restart assertions
   (`Get-Service`, `Get-Process certsrv` start time) touch Windows-only
   surfaces that Pester on Linux cannot exercise.
4. **Deployment configuration remains operator-owned and unverified here** —
   the network allowlist, reverse-proxy limits, SIEM reachability, task ACLs,
   and monitoring. Unchanged from the 2026-08-11 review.
5. **Dependency CVE status was not re-checked online.** `pip-audit` runs in CI;
   no external advisory database was queried in this session.
6. **Multi-worker behaviour is still out of scope.** The nonce rate limiter and
   the HEC queue accounting are per-process. The supported deployment is a
   single process; a multi-worker deployment needs both re-reviewed.

## Breaking changes for operators

1. **`ACME_RA_REVOCATION_CONFIRM_TOKEN` is now required** for the CA-side
   revocation loop. Without it the confirm endpoint returns 401 and serials stay
   on the pending list. Pass it to `Sync-Revocations.ps1 -ConfirmToken` or via
   `ACME_CONFIRM_TOKEN`; `Register-MaintenanceTasks.ps1 -ConfirmToken` forwards
   it and warns when it is missing.
2. **Weak credentials now refuse startup.** Any EAB MAC key under 32 bytes or
   admin token under 32 characters must be regenerated
   (`python scripts/eab.py new`) or explicitly waived with
   `allow_weak_credentials` in a lab.
3. **`Sync-Revocations.ps1` and `Register-MaintenanceTasks.ps1` reject
   non-https RA URLs.** A loopback-http lab needs `-AllowInsecureUrl`.
4. **`audit_offbox_required` now fails startup** when the sink cannot actually
   emit, instead of starting with a disabled emitter.

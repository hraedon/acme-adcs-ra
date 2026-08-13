# Security review — 2026-08-14

Scope: an external static scan of the full repository at `06cd47c` (`v1.9.0-rc1`)
reported seventeen findings — three high, eleven medium, three low. This document
records the independent validation of each, the remediation, and what remains
unproven.

Baseline at review time: `v1.9.0-rc1`, 574 Python tests + 86 Pester passing,
`ruff` and `mypy --strict` clean.

**Every finding was reproduced against the code before anything changed.** The
scan was explicitly source-only ("no live ADCS, Windows PowerShell 5.1, IIS,
Active Directory, or SIEM runtime was available"), which makes its findings
hypotheses rather than results — the same standing applied to the 2026-08-13
scan. Two findings turned out to be materially different from their summaries,
and one was half wrong.

## The two that blocked the release

### F3 — ACME reason 8 (`removeFromCRL`) was accepted and reached the CA

`_VALID_REVOCATION_REASONS` included 8 on the ACME route, `Revoke-Cert.ps1`
included it in `$validReasons`, and it flowed verbatim through the pending list
into `certutil -revoke <serial> 8`.

Reason 8 is the **inverse of revocation**. A `revokeCert` carrying it recorded a
*successful* revocation in the RA — 410 on the certificate, order flipped, serial
drained off the pending queue — while asking the CA to take the certificate back
off the CRL. The owner is told the certificate is contained; it stays live and
trusted domain-wide, and if it was on hold (reason 6), the hold is what gets
lifted.

**This is not inference.** The project's own Plan 004 lab notes record the CA-side
effect from the 2026-07 spike: a certificate "placed on hold and then
removed-from-CRL (reason 8) — ADCS keeps its DB `Disposition` at 21 historically
but **it is off the CRL and valid**."

**Fixed** in four places, because the RA is not the only caller: the ACME route,
`Revoke-Cert.ps1`, and `RevocationLib`'s shared reason list — the last of which is
what protects a deployment whose store still holds a reason-8 row written before
this fix. Reason 6 (`certificateHold`) remains accepted: a hold is strictly more
restrictive than valid, so it cannot be used to undo containment.

### F14 — post-issuance transport failures left live certificates untracked

The 2026-08-13 review fixed the three post-issuance *verifier* rejections. It did
not reach the window after `certfnsh.asp` returns "issued" with a ReqID: the leaf
fetch, the PKCS#7 chain fetch, and `_validate_chain_binds_to_leaf`. A failure in
any of those was wrapped as `EnrollmentTransportError`, and finalize recorded
`{"error": ...}` — **no serial, no ReqID** — then returned 503 leaving the order in
`processing`.

That is the same orphan class finding 6 exists to prevent, on a path finding 6
did not cover. `_validate_chain_binds_to_leaf` is a realistic trigger: the runbook
already warns that a subtly wrong chain validator breaks *every* issuance.

**Fixed.** `EnrollmentTransportError` carries `req_id`, `cert_pem`, and
`chain_pem`, set as soon as the CA commits to each. Finalize routes an issued
orphan to quarantine:

* **leaf in hand** → a `quarantined` row carrying the serial and ReqID, queued for
  CA-side revocation through the ordinary pull agent, exactly like a verifier
  rejection;
* **ReqID only** (the leaf fetch itself failed) → no bytes exist to store, so the
  ReqID is made loud in the audit row and the log, and the operator revokes by
  ReqID at the CA by hand.

Either way the order goes terminal and the response is 500 rather than the 503
that invites a retry.

## Corrections to the scan

1. **F2 is half wrong.** "Production installation executes an unauthenticated
   artifact" reads as though the installer fetches and runs an MSI on its own. It
   does not: it downloads only when the operator passes an `http(s)` URL to
   `-HttpPlatformHandlerMsi`, exactly as the README documents. The *other* half is
   a fair hit and was fixed — `pip install --upgrade <repoRoot>` re-resolved the
   dependency closure at install time, so the artifact deployed to an
   issuance-path host was not the closure CI tested.

2. **F16 is sharper than the docs admitted.** The unauthenticated GET forms were
   justified as "not an existence oracle, the URL is unguessable". True, and
   beside the point: they also answer for a certificate whose account has been
   *deactivated* or whose EAB kid has been pulled from the allowlist. Kid eviction
   is supposed to be complete and is re-checked on every authenticated request — a
   URL captured beforehand still reads through the GET form.

3. **F12 restates a residual this project had already recorded**, and usefully
   extends it: the 2026-08-13 document noted that CRL issuer selection matched on
   subject DN alone, and the scan added that nothing pins the issuer *between*
   issuance and confirmation.

## The remaining findings

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| F1 | high | Cross-origin redirects could expose relayable gMSA Negotiate exchanges | Redirects refused in the production session factory |
| F2 | high | Non-reproducible install closure | `deploy/requirements.lock.txt`, hash-pinned, `--require-hashes` |
| F4 | medium | Signed CRL evidence replayable without a freshness policy | `nextUpdate` required, `thisUpdate` checked, absolute age ceiling |
| F5 | medium | Sync confirmed CRL publication while deliberately skipping it | Agent reports `crl_published` honestly; RA records it |
| F6 | medium | Enrollment responses buffered and parsed without size limits | Capped before parsing; residual documented |
| F7 | medium | Reclaim could race a live enrollment into double issuance | Minimum processing age before reclaim is permitted |
| F8 | medium | Concurrent `newAccount` could create duplicate accounts per key | Partial `UNIQUE` index; the route resolves a lost race |
| F9 | medium | Revocation automation inherited maintenance authority | Pending list accepts the confirm token; identical tokens refused |
| F10 | medium | Template verification passed unexpected enrollees | Exits 3 unless `-AllowAdditionalEnrollees` |
| F11 | medium | Synchronous CA I/O blocked the async request loop | Enrollment moved to `run_in_threadpool` |
| F12 | medium | Issuer identity not pinned across issuance and confirmation | Issuer selected by signature, not by name |
| F13 | medium | Security state changes could commit without their audit row | `Store.record_revocation` — one transaction |
| F15 | low | A non-positive HEC queue defeated the off-box audit gate | `siem_hec_queue_max` floored at 1 |
| F16 | low | Legacy GET bypassed ownership and eviction | Config switch; default unchanged pending the lab |
| F17 | low | A failed confirmation stranded a successful CA revocation | Counted; exit code reflects it |

### The two worth reading in full

**F1 — why the usual redirect protection did not apply.** `requests` strips the
`Authorization` header when a redirect crosses to another host. That does nothing
here, because `NegotiateAuth` sets no static header: it registers a *response
hook* that fires on any 401 and builds a fresh Kerberos token. A redirect to a
host answering `401 Negotiate` would therefore draw a freshly minted gMSA ticket
out of the RA, channel-bound to the real CA's certificate — the shape of a relay.
Nothing in `/certsrv/` legitimately redirects, so refusing costs nothing. It is
enforced in the production session factory rather than at each call site, so a
new call cannot forget it.

**F11 — why `async def` was the bug.** FastAPI runs `def` handlers in a
threadpool but `async def` handlers **on the event loop**. `finalize_order` is
`async def` and called the synchronous `requests`-based enrollment leg inline,
whose own default timeout is 30 s. Every finalize therefore stalled every other
request in the process for the duration — new-nonce, `revokeCert`, the admin
endpoints — and the supported deployment is a single process, so nothing absorbs
it.

## Verification

* **574 → 593 Python tests**, 86 → 88 Pester. All green, `ruff` and
  `mypy --strict` clean, PowerShell parse-checked.
* **Every new test was mutation-checked**, and every fix has a negative control
  so that "refuse everything" cannot pass.
* **Three mutations initially survived.** All three were caught and are worth
  recording, because two of them revealed genuinely weak tests rather than
  inadequate mutations:
  * the F14 finalize **dispatch** was not covered at all — the unit tests called
    the orphan handler directly, so `if exc.ca_issued:` could be replaced with
    `if False:` and everything stayed green. Fixed by driving a full authorized
    order through HTTP.
  * the F16 test asserted only a `401`, which both the disabled path and a
    genuine miss return. Rewritten to prove a *readable* certificate becomes
    unreadable.
  * the F13 mutation was inadequate rather than the test being vacuous
    (`record_audit` delegates to the patched method and still rolls the outer
    transaction back); replaced with one reproducing the original
    separate-commit structure.
* **A pre-existing flaky test was stabilised.** `TestHecQueueBound` relied on
  `.invalid` DNS *stalling* to pin its workers; a resolver that returns NXDOMAIN
  quickly lets them drain, so the drop count came in low. It failed once during
  a full run here. The workers are now pinned with an explicit barrier.

## One deliberate departure from the strict default

`allow_unauthenticated_resource_get` defaults to **True** — the existing
behaviour — rather than to the stricter False this project would normally pick.

The reason is evidential, not preferential: the docs record these routes as
retained "for compatibility with the clients this RA was proven against", which
is a claim of observed need, and nothing available here establishes whether
Certify the Web can do POST-as-GET. Flipping the default blind, immediately
before a lab re-proof, risks breaking the proven pilot client to close a
low-severity oracle.

**This is a lab question, and it is on the re-proof checklist.** Evidence in
favour of flipping it: the test harness now drives a complete order to issuance
with the GET form disabled, so the RA itself is complete without it. If the
pilot client does not need it, the default should become False.

## Proof gaps — what this review did NOT establish

1. **No live ADCS validation of any of it.** All seventeen fixes were validated
   on Linux against fakes. The issuance leg changed (the transport-orphan path),
   the revocation leg changed (reason 8, CRL freshness, confirm authority), and
   the deployment path changed (the pinned installer) — every one of which earns
   a live re-proof under this project's own rules. **Not done.**
2. **The reason-8 rejection has not been re-confirmed against the CA.** The
   CA-side effect is documented from Plan 004, but that was a different code
   path. The lab should confirm that a reason-8 `revokeCert` is now refused at
   the RA surface *and* that no reason-8 call reaches `certutil`.
3. **The transport-orphan quarantine has never run against a real CA.** It is
   the fix most in need of live proof, because provoking it means interrupting
   the RA between the CA's "issued" response and the chain fetch — and the whole
   point is what the CA is left holding.
4. **The pinned installer has not been run on Windows.** `--require-hashes` with
   `--only-binary :all:` is stricter than what the host did before; a
   platform-specific wheel gap would surface only there. The lock file was
   exported on Linux for Python 3.13.
5. **CRL freshness bounds are unexercised against ADCS publication cadence.** A
   CA publishing less often than the age ceiling would start failing evidence
   checks. The default is seven days; confirm it against the lab CA's actual
   cadence.
6. **Deployment configuration remains operator-owned**, unchanged from prior
   reviews: the network allowlist, reverse-proxy limits, SIEM reachability, task
   ACLs, monitoring.
7. **Multi-worker behaviour is still out of scope.** The nonce limiter and HEC
   queue accounting remain per-process.

## Breaking changes for operators

1. **Reason 8 is rejected.** Any tooling that submitted `removeFromCRL` through
   `revokeCert` or `Revoke-Cert.ps1` now gets a 400 / exit 3. There is no
   replacement: un-revoking is not a revocation operation, and it must be done
   deliberately at the CA.
2. **`deploy/requirements.lock.txt` is required by the installer.** An install
   from an incomplete copy now fails rather than silently resolving from the
   index. Regenerate it with
   `uv export --locked --format requirements-txt --no-emit-project --no-dev -o deploy/requirements.lock.txt`.
3. **`admin_token` and `revocation_confirm_token` must differ.** Identical values
   now refuse startup.
4. **`siem_hec_queue_max` must be ≥ 1.** Zero or negative now refuses startup.
5. **`Verify-TemplateEnrollment.ps1` exits 3 on unexpected enrollees.** Pass
   `-AllowAdditionalEnrollees` to accept them deliberately.
6. **The revocation agent should be given `-ConfirmToken` and no admin token.**
   The admin token still works for the pending-list read, but the point of the
   change is that the revocation host no longer needs it.

# Changelog

All notable changes to acme-adcs-ra are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] — 2026-08-13

> **Release candidate (`v1.9.0-rc2`).** Awaiting the full live lab re-proof on
> this commit; the `v1.9.0` tag follows it. See the open item in the
> [validation log](docs/pre-pilot-checklist.md#validation-log).

### Security — 2026-08-14 external scan (seventeen findings)

A second external scan, of `v1.9.0-rc1`. Every finding was reproduced before any
code changed; every new test was mutation-checked and has a negative control.
See `docs/security-review-2026-08-14.md`, which also records what it did **not**
prove and the one place the stricter default was deliberately not taken.

> ### ⚠️ Additional upgrade requirements
>
> **5. ACME reason 8 (`removeFromCRL`) is rejected.** It is the inverse of
> revocation and reached `certutil -revoke <serial> 8` verbatim, so a revokeCert
> carrying it recorded a *successful* revocation in the RA while asking the CA
> to take the certificate back off the CRL. Plan 004 confirmed the CA-side
> effect against the lab: the certificate ends up "off the CRL and valid".
> Tooling that submitted reason 8 now gets a 400 (or exit 3 from
> `Revoke-Cert.ps1`); there is no replacement.
>
> **6. `deploy/requirements.lock.txt` is required by the Windows installer.**
> Dependencies now install from a hash-pinned closure with `--require-hashes`,
> not a live resolve. An incomplete copy fails rather than silently resolving
> from the index.
>
> **7. `admin_token` and `revocation_confirm_token` must differ**, and
> **`siem_hec_queue_max` must be ≥ 1.** Both now refuse startup.
>
> **8. `Verify-TemplateEnrollment.ps1` exits 3** when principals outside
> `-ExpectedEnrollee` hold enroll. Pass `-AllowAdditionalEnrollees` to accept
> them deliberately.

- **Certificates orphaned by a post-issuance *transport* failure are now
  quarantined.** The 2026-08-13 review covered the three post-issuance verifier
  rejections but not the window after `certfnsh.asp` returns "issued" with a
  ReqID — the leaf fetch, the chain fetch, and the chain-binds-to-leaf check. A
  failure there recorded only an error string (no serial, no ReqID) and returned
  503 with the order left `processing`, leaving a live domain-trusted
  certificate untracked at the CA. The error now carries what the CA committed
  to, and finalize quarantines it; where only the ReqID is known, that is made
  loud in the audit row and the log instead.
- **The enrollment leg refuses redirects.** `requests` strips `Authorization`
  across a cross-host redirect, but that does not apply here — `NegotiateAuth`
  registers a 401 *response hook*, so a redirect to a host answering
  `401 Negotiate` would draw a freshly minted gMSA ticket out of the RA.
- **Finalize no longer blocks the event loop.** The handler is `async def`, so
  FastAPI runs it on the loop rather than in a threadpool; the synchronous CA
  call (30 s default timeout) stalled every other request in the process.
- **Revocation, its order transition, and its audit row commit in one
  transaction** (`Store.record_revocation`), matching `record_issuance`.
- **CRL evidence is freshness-checked and its issuer pinned by signature.** A
  signed CRL verifies for ever, so a CRL with no `nextUpdate` was accepted
  indefinitely and `thisUpdate` was never checked. Issuer selection matched on
  subject DN alone, which picks the wrong generation after a CA key renewal.
- **The revocation agent no longer needs the admin token** — the pending list
  accepts the confirm token, so the revocation host stops carrying authority to
  reclaim orders and drain nonces.
- **Reclaim refuses an order that may still be enrolling**, closing a
  double-issuance race its only check ("no certificate row") could not see.
- **One account per key**, enforced by a partial `UNIQUE` index; the route
  resolves a lost race by returning the winning account.
- **The sync agent reports `crl_published` honestly** instead of letting
  `ca_crl_updated` imply a publication the default least-privilege path
  deliberately skips, and **counts a failed confirmation** so the exit code
  reflects a CA/RA disagreement.
- Enrollment responses are size-capped before parsing.

### Fixed — 2026-08-14 (live re-proof of rc2)

- **`Set-OfficerRights.ps1` could not provision a CA that had no
  `OfficerRights` value — the default, and therefore the first-provisioning
  path.** It aborted with `Exception calling "Write" ... Buffer cannot be null`
  and wrote nothing, while the CA-side grant that precedes it *had* been made,
  so the CA looked half-configured. Cause: the 2026-08-13 fix for the
  single-element unwrap wrapped every return in `,$result`, which makes `,@()`
  arrive at the call site as a **one-element array holding an empty array** —
  so `@(Get-ExistingAces $bytes).Count` was 1 with no ACEs, and the phantom
  entry reached the ACE builder with a `$null` RawAce. The contract is now
  stated where it belongs: the function returns plainly and the call sites wrap
  in `@()` (both already did). `Set-OfficerRights.ps1` additionally drops
  entries with no ACE bytes before building. Found on the lab CA, 2026-08-14.
- **Two Pester tests asserted a shape the shipped code never uses.** They
  bound the result with `$result = Get-ExistingAces ...`, and assignment
  collapses a single-item pipeline back to the item — so the empty case looked
  correct while `@(...)` at the real call site did not. They now assert the
  call-site expression, and two count tests cover the empty and single-ACE
  cases. Reverting the library fix fails them.
- **`TestHecQueueBound` was flaky.** It relied on `.invalid` DNS *stalling* to
  pin its workers; a resolver returning NXDOMAIN quickly lets them drain, so the
  drop count came in under what the test expected. It failed once during a full
  run. The workers are now pinned with an explicit barrier, making the bound
  exact on any machine.

**Security hardening (2026-08-13 external scan).** Ten findings — nine medium,
one low — from an external static scan of v1.8.0. Every one was independently
reproduced against the shipped build before any code changed, and every new
test was mutation-checked. See `docs/security-review-2026-08-13.md`, which also
records what this review did **not** prove.

The live lab re-proof of these fixes then found **two further defects that Linux
CI structurally cannot see** — both Windows PowerShell 5.1 language semantics
that `pwsh` 7 silently differs on, one of them inside this review's own
finding-8 fix. They are in the **Fixed** section below and are the reason this
release is worth reading past the security summary.

> ### ⚠️ Upgrade requirements — read before deploying
>
> **1. `ACME_RA_REVOCATION_CONFIRM_TOKEN` is now required for the CA-side
> revocation loop.** Confirming a revocation asserts an external event the RA
> cannot observe, so it is no longer the same authority as general maintenance:
> the confirm endpoint requires its own credential and **refuses the admin
> token**. Without it, `POST /acme/admin/revocations/{serial}/confirm` returns
> 401 and serials remain on the pending list. Pass it to
> `Sync-Revocations.ps1 -ConfirmToken` (or `ACME_CONFIRM_TOKEN`);
> `Register-MaintenanceTasks.ps1 -ConfirmToken` forwards it.
>
> **2. Weak credentials now refuse startup.** EAB MAC keys must decode to ≥ 32
> bytes and admin/confirm tokens must be ≥ 32 characters. Regenerate with
> `python scripts/eab.py new`, or set `allow_weak_credentials` for a lab/CI
> fixture only.
>
> **3. The revocation scripts reject non-https RA URLs.** A loopback-http lab
> needs `-AllowInsecureUrl`.
>
> **4. `audit_offbox_required` now fails startup** when the configured sink
> cannot actually emit (previously it checked only the sink's name).

### Security

- **Revocation confirmations are no longer taken on faith.** The confirm
  endpoint requires a dedicated token, and every confirmation records
  `verification: "agent-asserted"` or `"crl-verified"` so the audit trail never
  implies the RA observed a CA-side event it did not. Optional independent
  verification against the CA's published CRL
  (`ACME_RA_REVOCATION_CONFIRM_CRL_URL`) can be made mandatory with
  `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE`; the CRL's signature is
  checked against the issuing CA certificate from the certificate's own stored
  chain, and an expired CRL is not accepted as evidence.
- **Certificates rejected by a post-issuance verifier are now quarantined
  rather than orphaned.** ADCS has already issued by the time the SAN / EKU /
  CA-capability checks run; the RA previously recorded nothing at all — not even
  the serial — leaving a live, unrevocable certificate at the CA. It is now
  recorded as `quarantined` (serial, ReqID, bytes, violations), the order goes
  terminal, and it is queued for CA-side revocation through the existing pull
  agent. It is never served: `get_certificate_by_order` excludes quarantined
  rows and the certificate response serves only `valid`.
- **Issuance and its mandatory audit row now commit in one transaction**
  (`Store.record_issuance`). Fault injection previously left a stored,
  serveable certificate with zero `certificate-issued` events. The issuance
  event now also carries the serial.
- **Invalid nonces are rejected by a read, not a SQLite write.** An
  unauthenticated peer could make every bogus nonce contend for the single
  writer lock; measured, a bogus nonce blocked for the full 5 s `busy_timeout`
  and then raised `database is locked` (a 500, not a 400). Single-use semantics
  are unchanged.
- **EAB MAC keys and admin/confirm tokens have enforced strength floors.** An
  EAB key decoding to zero bytes was previously treated as *present*, letting
  anyone who knew the kid forge the binding with an empty HMAC key.
- **The HEC audit queue is bounded** (`ACME_RA_SIEM_HEC_QUEUE_MAX`, default
  1000). A dead HEC endpoint previously let request-driven audit events
  accumulate without limit; overflow now drops from the HEC sink only — never
  from the local audit table — and is counted and logged.
- **`audit_offbox_required` asserts the constructed emitter**, so a deployment
  can no longer claim the off-box audit gate while emitting nothing.
- **Malformed JWS input returns ACME 4xx instead of 500.** Three
  unauthenticated crashes: a non-object EAB protected header, a non-string
  nonce reaching SQLite parameter binding, and a non-ASCII EAB payload reaching
  the timing-equalisation helper's ASCII encode.
- **`Sync-Revocations.ps1` / `Register-MaintenanceTasks.ps1` validate the RA URL
  before attaching the token** — https only, no embedded credentials, no query,
  fragment, or path. A scheduled task bakes the URL in, so a typo would have
  disclosed the token on every run.
- **`Set-OfficerRights.ps1` proves activation before reporting success.** The
  CA loads `OfficerRights` at service start, so a written-but-not-reloaded
  restriction is not in force. `net start` failure is now fatal, the service
  must be `Running`, the process must have actually recycled, and the readback
  asserts the target officer's ACE landed (or is gone, for `-Remove`) instead of
  merely printing it. `Get-OfficerRightsBytes` reads the registry provider
  first rather than regex-scanning `certutil` console text.

### Fixed

- **`Set-OfficerRights.ps1` aborted on a *successful* single-officer
  provisioning.** `Get-ExistingAces` returns an array, but PowerShell unwraps a
  single-element array across a function boundary, and a bare `[pscustomobject]`
  has **no `.Count` under Windows PowerShell 5.1** (pwsh 7 yields 1, which is
  why the Pester suite was green). With exactly one ACE — the default, documented
  single-officer deployment — the script reported an in-force restriction as
  "absent — unrestricted", then failed its own readback assertion and exited 1
  after correctly writing and loading the restriction. An operator, or any
  automation treating a non-zero exit as failure, would conclude the CA-side
  least-privilege control had not been applied. The library now always returns an
  array and both call sites wrap defensively. Found by the live lab re-proof of
  v1.9.0; the assertion itself shipped in v1.9.0 (2026-08-13 review, finding 8).

- **`Sync-Revocations.ps1` aborted the whole batch on the first failed revoke.**
  `& $pwshExe @revokeArgs 2>&1` turns the child's stderr into ErrorRecords, and
  under the script's own `$ErrorActionPreference='Stop'` the first one is a
  *terminating* error — so the per-serial "log it and continue" handling, the
  requester-mismatch abort (exit 5) and the partial-failure exit code (2) were
  all unreachable, and a single bad serial silently stranded every serial behind
  it while the script exited 1. The child invocation moved to
  `SyncLib.ps1::Invoke-ChildScript`, which suppresses `Stop` for the duration of
  the call. Pre-existing (not introduced in v1.9.0); it only bites when a revoke
  fails, which no previous re-proof had provoked. **Note:** this cannot be
  regression-tested on Linux CI — pwsh defaults
  `$PSNativeCommandUseErrorActionPreference` to `$false`, so a "does not throw"
  assertion passes with the fix reverted (verified by mutation). See the note in
  `tests/pester/Sync.Tests.ps1`.

- **`Assert-SafeRaUrl` never recognised an IPv6 literal loopback.**
  `[System.Uri].Host` renders IPv6 in bracketed form (`[::1]`), so comparing it
  against `::1` meant `-AllowInsecureUrl` silently did not apply to an IPv6
  loopback lab. Fail-closed, so not exploitable — but wrong, and it would have
  read as a mysterious rejection during a lab setup.

- **`__version__` reported `0.1.0`.** The literal in `acme_adcs_ra/__init__.py`
  had never been updated because nothing read it; it now derives from the
  installed distribution metadata, so it cannot drift from `pyproject.toml`
  again. A test asserts the two agree.

### Changed

- `scripts/lib/SyncLib.ps1` is now dot-sourced by `Sync-Revocations.ps1` rather
  than being a test-only copy, so the URL validation the Pester suite exercises
  is the code that actually runs.
- `/acme/admin/revocations/pending` entries carry `status`, distinguishing a
  client-requested revocation from a quarantined mis-issuance.

## [1.8.0] — 2026-08-11

**Security hardening (2026-08-11 pre-deployment review).** Thirteen findings
across the ACME front, the account lifecycle, the unauthenticated surface, the
enrollment leg's chain handling, and the deployment artifacts — twelve from the
review itself and one more found while reading real `certutil` output during the
live re-proof. See `docs/security-review-2026-08-11.md`.

> ### ⚠️ Upgrade requirement — read before deploying
>
> **`ACME_RA_BASE_URL` is now security configuration, not a display value.**
> Every JWS and EAB binding is validated against the URL derived from it rather
> than against the URL the request arrived on. Set it to the *exact* public
> origin clients use — scheme, host **and port**. If it does not match, every
> legitimate request is refused (fail-closed) from the first request after
> upgrade.
>
> A deployment where `base_url` was merely approximately right — the loopback
> host, the wrong port, `http` where clients use `https` — worked before this
> release and will not after it. That is the intended behaviour: the old
> permissiveness *was* the vulnerability.
>
> Two operator controls also move from recommended to **required**: an off-box
> audit sink (`ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with syslog or HEC) and the
> network allowlist in front of the unauthenticated nonce endpoint. See
> `docs/pre-pilot-checklist.md` §C/§E.

### Security
- **JWS and EAB URL bindings now pin to `base_url` (MEDIUM).** Both were
  previously derived from `str(request.url)` — i.e. from the client's `Host`
  header — so they only proved the client was self-consistent. An EAB minted for
  a different deployment verified here, which meant the 2026-08-07 "EAB
  cross-endpoint replay" fix was not actually closed. `kid` must now also start
  with this RA's configured account-URL prefix.
  **Operator impact: `ACME_RA_BASE_URL` is now load-bearing** — it must be the
  exact public origin, or every request fail-closes.
- **Accounts can be disabled (MEDIUM).** `account.status` and the account's EAB
  kid are re-checked on every authenticated request. Removing a kid from
  `eab_allowlist` previously stopped issuance but still let the account create
  orders, roll its key, and **revoke its own live certificates**. RFC 8555
  §7.3.6 deactivation is implemented as the client-side kill switch. Both
  rejections are audited (`account-deactivated`, `account-request-denied`).
- **Interactive API docs disabled (MEDIUM).** `/docs`, `/redoc` and
  `/openapi.json` published the full route inventory, including every
  `/acme/admin/*` endpoint, to any unauthenticated caller.
- **Off-box audit gate (MEDIUM).** New `audit_offbox_required` refuses startup
  unless audit events leave the host. The default `jsonl` sink writes next to
  the database, so a host compromise destroyed the audit trail and its only
  mirror together.
- **Issued chain bound to the issued certificate (LOW).** `certnew.p7b` is a
  separate fetch that was stored and served unvalidated; a chain certificate
  must now match the leaf's issuer *and* verify its signature.

### Fixed
- **Nonce-endpoint flood ceiling (MEDIUM).** `/acme/new-nonce` is
  unauthenticated and each call is a SQLite write, so a flood contended for the
  single writer with the issuance path. An in-process token bucket now bounds it
  *before* the write (`nonce_rate_limit_per_second`, default 20/s, burst 100).
- **Advertised resource URLs resolve (MEDIUM).** newOrder's `Location`,
  newAccount's `Location` and the account `orders` link all returned 404, so a
  conforming client that polls the order URL could not complete. Adds
  account-scoped POST-as-GET for order, account, orders-list, authorization and
  certificate resources, and RFC 8555 §6.3 empty-payload handling.
- **`certfnsh.asp` pending detection** now scans the comment/script-stripped
  body like every other step of the parser.
- **`keyChange` malformed `oldKey`** returns 400 instead of an unhandled 500.
- **Serial canonicalisation.** One `canonical_serial` helper on every path, so a
  `certutil`-shaped (zero-padded, lowercase) serial matches the stored form and
  the revocation-confirm callback cannot 404 into an endless re-revoke loop.
- **App version** is read from installed distribution metadata (it had drifted
  to `1.6.0` against a `1.7.0` release).
- **Serial form vs the ADCS database (found during the live re-proof).** ADCS
  stores the full byte string, so a certificate whose high-order byte is `0x0N`
  is recorded with a leading zero the RA's `format(n, 'x')` form never has, and
  `-restrict "SerialNumber=…"` is an exact match — the lookup would find 0 rows
  and `Revoke-Cert.ps1` would exit 4, silently stopping the automated revocation
  loop for that certificate. `Get-CaSerialForm` re-pads to even length;
  `Revoke-Cert.ps1` now dot-sources `scripts/lib/RevocationLib.ps1` (removing the
  test-only-copy drift risk noted in v1.6.0).

### Live re-proof
- **PASSED (2026-08-11)** against commit `db06c6f` on the lab RA host (ADCS CA,
  Mode A). 26 checks, 26 passed: the standing issuance proof (serverAuth-only
  EKU, SAN from the CSR, chain off the existing CA, policy denial, reason-7
  rejection) plus every new control — EAB/Host/kid rebinding, POST-as-GET
  resources, docs 404, nonce flood capped, account deactivation, and the
  revocation round-trip through `Revoke-Cert.ps1` and the confirm callback.
  The chain-binding check accepted the real CA's `certnew.p7b` (the check that
  no unit test could validate). Account eviction was proven with a control
  confirming the allowlist had actually reloaded. See
  `docs/security-review-2026-08-11.md`.

### Changed
- `deploy/iis/web.config` sets the off-box audit sink and an explicit global
  order ceiling, and documents that the network allowlist is required rather
  than recommended.
- The no-signing-key guardrail's importlib allowlist admits
  `importlib.metadata` (data-only, like `importlib.resources`), with two new
  negative controls asserting `importlib.machinery` still trips the detector.

## [1.7.0] — 2026-08-08

**Security hardening (2026-08-07 review), no new feature surface.** Closes
nine findings across the issuance leg, the ACME/JWS front, rate limiting,
and the dependency closure. Live re-proven against ADCS on the lab. The
issuance path is behaviourally unchanged for legitimate requests.

### Security
- **CA-capable CSR/cert rejection (HIGH).** A dangerously drifted template
  returning `CA=true` or signing key usage while carrying serverAuth EKU is
  now rejected at CSR intake (`_reject_ca_capable_csr_extensions`) **and**
  independently on the issued certificate (`_issued_cert_ca_capability_violations`)
  before it is recorded or served. Reinforces the no-signing-key-ever invariant.
- **CN bound to SAN set.** The template takes the subject from the CSR, so a
  CSR/issued-cert Common Name must be a member of the requested DNS SANs,
  closing the legacy-CN second identity path (`_reject_unrequested_common_names`).
- **certsrv response bound to CSR key.** The production enrollment leg now
  compares `SubjectPublicKeyInfo` bytes and the subject CN against the
  authorized SAN set, failing closed on a mismatch
  (`_validate_issued_certificate_binding`).
- **Algorithm exactness.** RS/ES alg names are exact-matched (no `startswith`),
  EC algorithms are curve-matched to their key, and RSA account keys require
  ≥2048 bits. Eliminates algorithm-confusion and weak-key acceptance.
- **EAB URL binding.** The EAB protected-header `url` must equal this RA's
  `newAccount` endpoint, preventing cross-endpoint/environment replay.
- **HEC HTTPS enforcement.** The SIEM HEC sink enables only for HTTPS URLs
  without embedded credentials, so its bearer token cannot be sent in plaintext.

### Fixed
- **Rate-limit TOCTOU.** Order count-and-insert is now one `BEGIN IMMEDIATE`
  transaction (`create_order_with_authz`), so a parallel burst cannot all
  observe a below-limit count and race past the ceiling.
- **JWS body streaming cap.** Unauthenticated request bodies are bounded by
  `max_jws_body_size_bytes` (default 64 KiB), enforced on declared
  `Content-Length` and while streaming, before JSON/base64 decoding.
- **Type-confusion hardening.** Every JSON-decoded protected header, payload,
  and JWK is now checked to be a JSON object.
- **Dependency:** `cryptography` floor raised to ≥50.0.0 (PYSEC-2026-3552).

### Added
- `docs/security-review-2026-08-07.md` — the review itself.
- `tests/test_issuance_security_bindings.py` — regression tests for the
  CA-capable, CN-binding, and key-binding checks.

### Changed
- `max_jws_body_size_bytes` config knob (default 65536) added to `RAConfig`.

### Live re-proof
- **PASSED (2026-08-08)** against commit `5d30937` on the lab RA host (ADCS
  CA, Mode A). Core 12 cases + 3 new CSR-rejection checks. CA DB confirmed
  requester = the enrollment gMSA, template = `ACME-ServerAuth`. See
  `docs/pre-pilot-checklist.md` validation log.

## [1.6.0] — 2026-07-24

**Hardening + validation sweep (Plan 007), no new feature surface.** The
issuance path is behaviourally unchanged.

### Fixed
- **Finding E-1 (enrollment-side blast radius) — remediated (WI-035).** The
  enrollment gMSA held `Machine`-template enroll rights via Domain Computers
  membership, so a compromised gMSA that *bypassed* the RA was not ACL-bounded to
  `ACME-ServerAuth`. Remediated by moving the gMSA off the Domain Computers enroll
  path (`primaryGroupID` change); verified live three ways (template ACLs, the
  gMSA's Kerberos token, an issuance regression). It now enrolls only
  `ACME-ServerAuth`. See `docs/revocation-scope-validation.md`.

### Added
- **PowerShell test coverage (WI-037).** The pure logic of the operator scripts
  is extracted into dot-sourceable `scripts/lib/*.ps1` and covered by a Pester
  suite (61 tests) that runs on the Linux CI runner under `pwsh` — including a
  **golden-bytes** regression test for the `OfficerRights` SD/ACE builder and the
  scheduled-task action-string builder. **Deploy the whole `scripts/` directory
  including `scripts/lib/`** (the officer/registration scripts dot-source it).
- **Live re-proof runbook (WI-038)** — `docs/live-reproof-runbook.md`: the
  repeatable ADCS-integration re-proof (issuance + EKU + both revocation
  topologies), its cadence, and the standing note that **green CI ≠ ADCS-verified**
  (cloud CI cannot reach a CA).
- **Two-identity topology — proven live end-to-end (WI-036).** A dedicated
  revoker gMSA (a *separate* identity from the enrollment gMSA) revoked an
  `ACME-ServerAuth` cert at the CA and confirmed it back to the RA, with the WI-022
  requester check active and the enrollment gMSA holding **no** officer rights
  throughout (compromise independence). *Operator note:* create the revoker gMSA
  with explicit AES Kerberos etypes (`-KerberosEncryptionType AES128,AES256`) —
  without them RC4 is added and, if blocked on the DCs, the account is unusable.

### Changed
- **Deterministic CI (WI-039).** CI installs via `uv sync --locked` (respects
  `uv.lock` for all deps); `ruff`, `mypy`, and Pester are pinned. A dependency
  bump is now a deliberate, reviewed `uv lock` change, not a surprise drift.

## [1.5.0] — 2026-07-23

**Automated CA-side revocation + self-enforced serverAuth.** Builds on 1.0.0's
issuance path (behaviourally unchanged) by closing the revocation loop the RA
previously left to a manual operator step, and by making the serverAuth-only
guarantee self-enforcing at finalize. Landed via Plans 004–006. The automated
revocation loop — both the recommended two-identity topology and the opt-in
single-identity (`-LocalMode`) topology — was **live-reproven end-to-end on the
lab (2026-07-23, WI-028)**: base issuance + EKU verification, and the full
round-trip (RA `revokeCert` → CA-side pull agent → CA revoke → RA confirm) with
the WI-022 requester check and the WI-025 template-scoped officer restriction
both active, the least-privilege bound intact (CRL republish denied to the
officer identity), and the confirm loop closing (`ca_crl_updated=true`).

### Added
- **WI-026 — post-issuance EKU verification.** Finalize now inspects the *issued*
  certificate's Extended Key Usage and fails closed (500, audited as
  `finalize-issued-cert-eku-mismatch`, no cert recorded or served) unless it is
  exactly `serverAuth`. This self-enforces the cardinal "blast radius bounded to
  spoofing internal TLS" guarantee, which previously rested solely on ADCS
  template configuration — a template that ever gained clientAuth/PKINIT/anyEKU
  (or issued a no-EKU all-purpose cert) would otherwise silently break it. Sibling
  to the MED-1 SAN check (`finalize.py::_issued_cert_eku_violations`). Validated
  against a real lab ACME-ServerAuth cert (EKU = serverAuth only → passes) plus
  unit coverage for clientAuth/anyEKU/no-EKU rejection; the dev/CI `fake_cert.pem`
  fixture is regenerated as serverAuth-only to match.
- **`-PublishCrl` opt-in for the automated revocation loop.**
  `Sync-Revocations.ps1` / `Register-MaintenanceTasks.ps1` now default to
  least-privilege (revoke at the CA; let the CRL refresh on its scheduled
  publication — the officer identity holds no Manage-CA/CRL-publish right) and
  expose `-PublishCrl` to force an immediate republish where CRL freshness is
  worth granting the identity Manage-CA (an explicit, recorded trade-off — see
  threat-model §E; strongly discouraged in single-identity).

### Fixed
- **Live re-proof of the single-identity revocation path (2026-07-23, on the lab CA).** Provisioned the enrollment gMSA as a template-scoped officer
  and drove the full loop as that identity; confirmed it revokes an
  `ACME-ServerAuth` cert at the CA while the least-privilege bound holds (CRL
  republish denied — needs Manage-CA). The pass surfaced and fixed the defects
  below; CA returned to a pristine baseline afterward.
- **`Revoke-Cert.ps1`: `certutil` argument order.** `-config` was placed *after*
  the `-revoke`/`-CRL` verb, so `certutil` mis-parsed it as positional
  ("Expected no more than 2 args, received 4") and no revoke could complete.
  `-config` now precedes the verb.
- **`Register-MaintenanceTasks.ps1`: gMSA task logon type.** Tasks were
  registered with the default `LogonType=Interactive`; a gMSA never logs on
  interactively, so the task registered but never ran. Now uses
  `LogonType=Password` (or `ServiceAccount` for well-known SIDs).
- **`Register-MaintenanceTasks.ps1`: `-RequesterName` pass-through.** The
  revocation-sync task did not forward `-RequesterName`, so the committed
  `WORK-DOMAIN\…` placeholder made the WI-022 requester check reject every
  revoke. It is now a parameter, forwarded into the task action.
- **`Register-MaintenanceTasks.ps1`: validation false-negative.** The
  post-registration check queried `Get-ScheduledTask -TaskName "\folder\name"`
  (a form that never matches), reporting "registration failed" and exiting 1
  after a successful registration. Now queries by `-TaskName` + `-TaskPath`.
- **`Set-OfficerRights.ps1`: OfficerRights written as REG_SZ.** The primary
  `certutil -setreg <hex>` path stored the blob as a *string* on some builds
  (observed on Server 2025), yielding a malformed, fail-closed value that breaks
  all officer operations. The blob is now written as `REG_BINARY` via the
  registry provider with a raw-bytes readback verify.
- **All `.ps1` scripts: encoding.** Em-dashes/`§`/`→` in the (UTF-8, no-BOM)
  scripts broke Windows PowerShell 5.1 parsing when a non-ASCII char landed in a
  string literal. Normalised to ASCII (`--`, `section`, `->`).

## [1.0.0] — 2026-07-15

Promotion of 1.0.0-rc1 to final. **No issuance-path source changes** since the
lab-proven commit `c283d81` (15/15 E2E cases green, CA database confirms gMSA
requester) — everything between rc1 and this release is documentation, CI, and
release mechanics. The re-proof that gated rc1 gates this release identically.

### Added
- Monthly scheduled CI run — a rot canary for a parked project (dependency
  CVEs via `pip-audit`, Python/runner drift) so decay surfaces as a failed-run
  email rather than at re-entry.

### Changed
- Project status: **parked at 1.0** — feature-complete for its charter, no
  active development planned. `README.md` / `AGENTS.md` document the
  maintenance posture and re-entry pointers. A production pilot remains gated
  on the operator-owned sections of `docs/pre-pilot-checklist.md`, which is
  unchanged.
- The known MED-1 limitation (post-issuance verification covers SANs but not
  EKU; the serverAuth-only guarantee rests on template configuration) is now
  tracked as work item **WI-021** instead of living only in a reflection.

## [1.0.0-rc1] — 2026-07-14

First release candidate. An ACME Registration Authority for ADCS: speaks ACME
(RFC 8555) on the front, holds **no signing key**, forwards CSRs to the existing
ADCS issuing CA over the Web Enrollment surface as a passwordless gMSA. Lab-proven
against commit `c283d81` (15/15 E2E cases green, CA database confirms gMSA requester).

### Added
- **ACME server (RFC 8555 subset):** directory, newNonce, newAccount with **EAB**
  (External Account Binding), newOrder, authorizations + challenge handling,
  finalize (CSR acceptance), certificate retrieval, revokeCert, and keyChange
  (RFC 8555 §7.3.5 account-key rollover).
- **EAB-gated front:** each authorized ACME client gets a high-entropy kid + MAC
  key + SAN scope. The challenge is intentionally a no-op (enterprise trust model:
  EAB + network allowlist + SAN scope is the whole authorization surface).
- **Deterministic SAN-scope policy:** fail-closed — an account with no `san_scopes`
  entry has an empty allow-list and every SAN is denied; subject-only issuance is
  rejected. DNS name validation at order creation (RFC 1123) rejects malformed
  identifiers early.
- **Channel-bound gMSA enrollment:** submits CSRs to `/certsrv/certfnsh.asp` via
  SPNEGO/Negotiate with RFC 5929 `tls-server-end-point` channel binding (in-tree
  `negotiate_auth.NegotiateAuth` over `pyspnego`), authenticated as the service's
  ambient gMSA identity. Works against `/certsrv/` hardened with EPA=Require.
- **Post-issuance SAN verification (MED-1):** the issued cert's SANs are checked
  against the order's authorized set, not just the CSR. A misconfigured template
  that appends an unauthorized DNS SAN or any non-DNS SAN (email, IP, URI) causes
  finalize to fail closed (500 + audit, no cert recorded or served).
- **Deterministic revocation CAS (MED-2):** the `revokeCert` route's CAS
  (compare-and-swap) returns a deterministic `won_cas` signal — no timestamp-
  inference race on concurrent revocation.
- **Out-of-band revocation (WI-010):** `revokeCert` records the revocation in the
  RA store only (cert → revoked, order → revoked, GET → 410 Gone) with an honest
  audit event (`revocation_scope=ra-store-only`, `ca_crl_updated=false`). The
  operator closes the loop with `scripts/Revoke-Cert.ps1` (CA officer, not the
  gMSA). Reason 7 (RFC 5280 "unused") is rejected by both the RA and the script.
- **Revocation reconciliation (WI-017):** read-only `scripts/Reconcile-Revocation.ps1`
  + `scripts/reconcile_revocation.py` compares the RA store against the CA database
  and reports drift in three buckets (in-sync, revoked-in-RA-but-active-at-CA,
  revoked-at-CA-but-valid-in-RA).
- **In-app per-account order rate limiting (WI-016):** deterministic, store-backed
  rate limit on order creation keyed by EAB kid, with per-kid overrides and a
  global backstop. Returns RFC 8555 `rateLimited` (429) with `Retry-After`.
- **EAB lifecycle tooling (WI-011):** `scripts/eab.py` mints high-entropy kid +
  MAC key, supports rotation, and includes an audit subcommand that lists every
  kid with its SAN scope and last-used timestamp (no MAC keys printed).
- **SIEM audit:** every issuance, policy-denial, enrollment-failure, account
  creation, and revocation is recorded in the RA SQLite store unconditionally
  and emitted to a JSONL sink (optional syslog/HEC). Fail-open applies to
  emission, not to the local audit record.
- **Operator enablement artifacts:** `scripts/install-windows.ps1` (IIS +
  HttpPlatformHandler, app pool as gMSA), `scripts/Register-MaintenanceTasks.ps1`
  (nonce GC + expired-order sweep), `docs/operations.md` (EAB lifecycle, network
  allowlist, rate limiting, admin token + reclaim runbook, monitoring/SLOs,
  retention/archival, revocation runbook, backup/restore).
- **Architecture tests:** no-signing-key scan (positive + negative controls) and
  no-signing-dependencies scan assert the RA never invokes a signing primitive
  in the issuance path.

### Security hardening (post-review)
- **M-1:** reason 7 rejected by `revokeCert` and `Revoke-Cert.ps1` (certutil
  rejects it; prevents a silent break in the out-of-band revocation loop).
- **M-2:** CAS-guarded pending→ready transition (expired pending orders stay
  pending until the sweep moves them, not silently promoted).
- **M-3:** CAS-guarded cert revocation with deterministic `won_cas` signal.
- **MED-1:** post-issuance SAN verification (issued cert SANs checked against
  the order, not just the CSR; non-DNS SANs rejected).
- **MED-2:** deterministic `won_cas` signal replaces timestamp-inference.
- **LOW-1, LOW-2, LOW-4:** expiry guard in `_maybe_ready_order`, UNIQUE index
  on certificates.order_id (graceful migration), and other robustness fixes.

### Stability contracts (from 1.0.0-rc1)
- **ACME API surface:** the directory endpoints, JWS validation, EAB binding,
  and `revokeCert` response shape (200 OK with non-normative
  `out_of_band_revocation` hint when `ca_crl_updated=false`) are the frozen
  public API. The `out_of_band_revocation` hint is extra (ignored by standard
  ACME clients per RFC 8555 §7.6); removing it or changing `ca_crl_updated` to
  `true` requires a future in-band revocation capability (a deferred, explicit
  privilege decision — see `docs/threat-model.md` §E).
- **Audit event types:** the `event_type` strings in `audit_log` are stable
  for SIEM ingestion. New event types may be added; existing ones are not
  renamed or removed.
- **Config env vars:** `ACME_RA_*` env vars are stable. New vars may be added
  with defaults; existing vars are not renamed.

### Known limitations
- **CA-side revocation is out-of-band.** The RA records revocation in its own
  store only; the CA CRL is not written until an operator runs
  `scripts/Revoke-Cert.ps1`. The audit honestly records `ca_crl_updated=false`.
  A standard ACME client reads 200 as "revoked" while relying parties still trust
  the cert until the CRL is republished — this is a documented, decided
  trade-off (threat-model §E) to keep the gMSA least-privileged.
- **Single-backend CBT assumption.** The channel-binding token is derived from
  a side-channel TLS probe of the `/certsrv/` host. Multi-backend topologies
  (NLB/ARR) are unsupported without reworking CBT derivation.
- **Challenge is a no-op.** The enterprise trust model (EAB + network + SAN
  scope) replaces domain-control proof. This is deliberate, not a gap.
- **No in-band CA revocation.** The gMSA holds Enroll rights only, not CA-officer
  rights. In-band revocation is a deferred, explicit privilege decision.

### Read-only / defensive boundary
acme-adcs-ra is **not** a read-only tool. It is in the certificate-issuance path
and holds a standing ADCS enrollment identity. The read-only / air-gapped /
flag-don't-probe conventions that govern cert-watch and adcs-lens **do not
apply**. The compensating disciplines are the hard rules in `AGENTS.md`: no
signing key, deterministic policy, passwordless, least-privilege template, audit
everything.

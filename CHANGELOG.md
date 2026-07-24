# Changelog

All notable changes to acme-adcs-ra are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

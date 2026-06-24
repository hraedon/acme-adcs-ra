# Threat Model — acme-adcs-ra

**Status:** post-WI-1 (enrollment proven on the lab 2026-06-20), pre-production-
pilot. Living document —
re-review on any change to the issuance path, the gMSA, the template scope, or
the dependency set.

This is an ACME **Registration Authority** for ADCS. It mints real certificates
and holds a standing enrollment identity. Worst case is *mis-issuance* or *leak
of that identity* — not "wrong analysis." The read-only family conventions do
not apply.

> **✅ WI-1 CONFIRMED (2026-06-20) — the enrollment round-trip issues a real
> cert on the lab CA. Revocation still has no `/certsrv/` endpoint (by design —
> see below).**
>
> - **Enrollment (`CertsrvEnrollmentLeg`)** is **live-validated**: the deployed
>   RA (IIS app pool running as the gMSA) authenticates to `/certsrv/` over SPNEGO
>   **with channel binding** (`negotiate_auth.NegotiateAuth` over `pyspnego`, so
>   it works against EPA=Require), POSTs the CSR to `certfnsh.asp`, and gets back
>   a **serverAuth-only** cert (SAN from the CSR) issued off the existing CA and
>   **chaining to the existing root**, with requester = `gMSA-acme-ra$`. The leg
>   tolerates the CA's real response formats (`certnew.cer` returned as
>   `text/html`; `certnew.p7b` returned as PKCS7 wrapped in
>   `-----BEGIN CERTIFICATE-----` markers — see `docs/spike-runbook.md`).
> - **Revocation (`CertsrvRevocationLeg`)** is an **honest `NotImplementedError`
>   stub.** ADCS Web Enrollment exposes **no revocation endpoint** (Microsoft
>   Learn enumerates only request-cert / retrieve-CA-cert / retrieve-CRL;
>   `magnuswatn/certsrv` has no `revoke()`; `acme2certifier` returns "not
>   supported"). A fictional `certrev.asp` form that appeared in one draft was
>   removed. The real mechanism is `certutil -revoke` or `ICertAdmin2`
>   `RevokeCertificate`, which requires granting the gMSA **CA-officer
>   ("Manage CA") rights** — a blast-radius change that is an operator
>   decision (see §E) and is **out of scope until then**. The server's
>   `revokeCert` endpoint remains wired to this leg via `FakeRevocationLeg`
>   (dev) so the mechanism drops in without an ACME-surface change.
>
> Controls downstream of "ADCS issued a cert" (chain fetch, requester capture,
> audit fields) are now **live-verified**, not just unit-tested. The remaining
> gate before a production pilot is the §6 checklist (host hardening, network
> allowlist, rate limits, operational runbook) — not the enrollment physics,
> which is proven.

## 1. System & trust model

- **RA, not CA.** acme-adcs-ra holds **no signing key**. It terminates ACME
  (RFC 8555), authorizes the request, and forwards the CSR to the existing ADCS
  issuing CA via `/certsrv/` as a passwordless gMSA. The CA signs; the RA never
  does.
- **Enterprise trust, not public DV.** The gate is **EAB** (kid→MAC key, pinned
  to the authorized client) + **network allowlist** + **deterministic SAN-scope
  policy**. Domain-control challenges exist (RFC shape) but auto-satisfy under
  the enterprise-trust model — EAB is the *who-is-allowed* gate, not the
  challenge. **Any in-scope SAN can be issued without domain proof; the SAN
  scope is therefore the critical control.** Public DV is out of scope.
- **Blast-radius bound.** One **server-authentication-only** template; subject
  /SAN from the CSR; the gMSA holds Read+Enroll only. A compromise is bounded
  to **spoofing internal TLS services** — short of client-auth/PKINIT (domain
  takeover).
- **Pilot transport: Mode A only.** Web Enrollment on the CA itself; enrollment
  is local → no Kerberos constrained delegation. **Mode C** (separate enrollment
  host) introduces constrained delegation to `HOST/CA01`+`RPCSS/CA01` — a
  distinct threat class (misconfigured delegation → unconstrained; on-behalf-of
  surface) — and **requires a separate threat-model addendum** before use.
  Mode C2 (CES/WSTEP/SOAP) is documented only.

## 2. Assets

| Asset | Compromise impact |
|---|---|
| **gMSA enrollment identity** (`gMSA-acme-ra$`) | Enroll server-auth certs for any allowed SAN, for the lifetime of compromise. Highest-value asset. |
| **EAB MAC keys** (`RAConfig.eab_allowlist`, loaded from `.env`/env) | Rogue account creation within each kid's SAN scope. |
| **RA HTTPS server cert + private key** (IIS/uvicorn endpoint) | TLS termination; key compromise is its own incident (not the gMSA). |
| **SQLite DB file** (`acme_ra.db`) | Contains every issued cert PEM, every account JWK, the EAB kid map, the audit log. Loss = loss of the authoritative audit; theft = issuance history + account keys. |
| **`.env` / config** (EAB keys, SIEM HEC token, base_url) | Secrets at rest. |
| **SIEM JSONL sink** (`<db>.siem.jsonl`, next to the DB) | Emission log; same backup/perimeter as the DB. |
| **Reverse proxy / LB** (allowlist, TLS termination, `X-Forwarded-*`) | If misconfigured, the JWS URL binding and the source-IP allowlist are both wrong. |
| **Issued certificates** | Spoofable internal TLS identities. |

## 3. The cardinal invariant — no signing key, ever

The RA must never hold a CA/private signing key or sign a certificate. Enforced by:

- **Architecture test** (`tests/architecture/test_no_signing_key.py`): AST-scans
  `src/` for cert-minting primitives — `CertificateBuilder`, **any** `.sign()`
  call, pyOpenSSL, ctypes/marshal/pickle/runpy, `os.exec*`/`spawn*`, dynamic
  exec (`eval`/`exec`/`__import__`/`importlib.util`/`exec_module`), assignment-
  RHS aliasing (incl. tuple-unpack), wildcard imports, targeted `getattr`.
  **Scope:** catches *accidental* drift toward signing; **not** a defense
  against a determined adversary who controls the repo (that is code review +
  the gMSA/template scoping). The guard is paired with positive/negative
  controls so it cannot silently become a no-op.
- **Locked-dependency backstop** (`test_no_signing_dependencies.py`): asserts no
  signing-capable library (pyOpenSSL, asn1crypto, signxml) is declared in
  `pyproject.toml` or importable in the env. **Limitation:** name-level only —
  it does not pin versions or detect a backdoored `cryptography`. See supply
  chain (§3.1).
- The enrollment/revocation legs are **Protocols** with platform-gated real
  implementations; the RA only forwards CSRs.

### 3.1 Supply chain
- A **lockfile** (`uv.lock`) must be in use and committed for the pilot;
  dependencies reviewed for known vulns at pilot time.
- `cryptography`, `fastapi`, `pydantic`, `uvicorn` are on the issuance path
  (request parsing, settings); `requests` + `pyspnego` (SSPI via `sspilib`) are
  the win32 enrollment client — the in-tree `negotiate_auth.NegotiateAuth`
  replaced the single-maintainer `requests-negotiate-sspi`, which also broke on
  Python 3.14. **A CVE in any of these is a pilot-blocker.**
- Binary/native deps (SSPI, Kerberos) are pinned to a known-good version.

## 4. Adversaries → controls → residual risk

### A. Compromised RA host / gMSA  *(the load-bearing operational risk)*
- **Controls:** gMSA (no stored password); least-privilege Enroll-only on one
  server-auth template; **audit every issuance** (requester=`gMSA-acme-ra$` is
  visible in the ADCS CA database + the RA store + SIEM).
- **Host-hardening bar (non-negotiable pilot condition):** the RA host is
  tier-0-adjacent and must clear, at minimum, **all** of: no interactive logon
  except via PAW/jump box; Credential Guard on; LSA protection on; WDAC
  (application allow-listing) enforced; no browsing/general software; dedicated
  OU + dedicated service-account group; the gMSA installed on this host only;
  no other service running as the gMSA; LAPS-equivalent posture; network-
  segmented from the app servers it replaces. **If the host is not hardened
  beyond the app servers it replaces, the RA is merely a single high-value
  target and this control fails.**
- **Insider:** the RA host administrator is the most privileged insider for this
  control plane. Enforce **separation of duty**: the RA host admin is distinct
  from the CA host admin and from the EAB-allowlist custodian. gMSA key
  retrieval (adding the host to `PrincipalsAllowedToRetrieveManagedPassword`) is
  logged and alerted.
- **Residual:** the gMSA is a chokepoint **and** a target; this does not reduce
  to zero. Bounded by the server-auth-only EKU — no client-auth/PKINIT.
- **Admin surface (operator-owned):** maintenance endpoints under
  `/acme/admin/*` (nonce cleanup, expired-order sweep, stuck-`processing`
    reclaim) are gated by a single `admin_token` Bearer secret (`RAConfig`).
    The token is a high-value secret (a holder can reconcile a stuck order to
    `ready`, the one action that can enable a re-enroll) and MUST be rotated,
    ACL'd, and distributed with the same care as an EAB MAC key. The reclaim
    `ready` branch is the operator's double-issuance gate (confirm at the ADCS
    CA DB that no cert was issued first); the server cannot make that decision
    itself.

### B. Stolen/compromised EAB key
- **Controls:** EAB MAC verified **constant-time** (`hmac.compare_digest`); the
  binding must equal the account JWK (canonical compare, ignoring optional
  `alg`); the kid maps to a deterministic SAN scope; **failed account creation
  is audited** (`account-creation-denied`) to detect kid-space probing.
- **Kids must be high-entropy** (UUID / ≥128-bit random) — a kid guess is a
  meaningful probe event; operator-chosen, **not** a hostname or customer name.
- **Timing residual:** the unknown-kid path runs a dummy HMAC
  (`server._dummy_hmac`) so the known/unknown-kid wall-clock is comparable,
  closing the kid-*existence* timing side-channel. High-entropy kids remain the
  primary control (a kid guess is still a meaningful probe event that is
  audited as `account-creation-denied`).
- **Rotation:** a documented EAB rotation procedure (kid + MAC key + SAN scope)
  must exist before pilot.
- **Residual:** in-scope issuance is possible until the kid is rotated. Bounded
  by the SAN scope + server-auth EKU.

### C. Rogue ACME client (in/out-of-policy)
- **Out-of-policy SAN:** refused at `finalize` by deterministic `IssuancePolicy`
  (kid→SAN scope, case-insensitive per RFC 4343); audited as
  `finalize-policy-denied`. No issuance.
- **CSR hardening:** CSR signature verified; minimum key strength (RSA≥2048, EC
  P-256/384/521); **non-DNSName SANs rejected** (IPAddress/otherName/URI/
  RFC822Name/RegisteredID) — prevents scope expansion via SAN type. CSR
  identifiers must be ⊆ the order's identifiers (RFC).
- **Residual:** none beyond the configured SAN scope (the intended policy).

### D. ACME protocol attacks (replay, cross-endpoint, IDOR, alg confusion)
- **JWS:** **full-URL binding** (RFC 8555 §6.4 — relative/cross-host URLs
  rejected); nonce consumed **before** the URL check (bad-URL probes burn the
  nonce); **RS/ES-only** for account keys, **HS-only** for EAB (no alg
  confusion / no "HS256 with the server's public key"); ES raw R‖S→DER validated.
- **CSRF / cross-protocol:** ACME POSTs are `application/jose+json` (RFC 8555
  §6.1) and the body is a key-bound JWS signature. There is no browser-rendered
  surface; a same-origin attacker would still need the account key. CSRF is a
  non-issue *because* of JWS + EAB + the network allowlist — not because of a
  CSRF token.
- **IDOR (mutating endpoints):** every order/authz/finalize/revoke is scoped to
  the caller's account (kid→account from the JWS); cross-account → 404 (no leak).
- **Double-issuance:** atomic `ready`→`processing` CAS; a `processing` order is
  **never re-enrolled** (client told to poll via `Retry-After`); an existing
  cert is returned idempotently.
- **Proxy / Host-header footgun (deployment):** the JWS URL check compares the
  protected-header URL to `request.url`. **Behind a reverse proxy, uvicorn must
  run with `--proxy-headers` and `--forwarded-allow-ips` set to the proxy**, and
  `base_url` must be the *public* hostname — otherwise every legitimate JWS is
  rejected as a URL mismatch (fail-closed) on day 1. This is a deployment
  prerequisite, not optional.
- **Stuck-`processing` blast radius:** `processing_started_at` is recorded on
  the `ready`→`processing` CAS. *Auto*-recovery is intentionally absent for the
  no-cert case — blindly reverting an order to `ready` risks double-issuance if
  the CA accepted the first request and the RA crashed before recording the
  cert. Two reconciliation paths exist:
  - **Cert recorded, status flip missed** (crash window between
    `create_certificate` and the status flip): self-heals automatically.
    `finalize` detects the cert row and CAS-closes the loop to `valid`
    (`finalize-order-reconciled` audit); the admin `reclaim-processing`
    endpoint does the same. No re-enrollment, no operator judgment needed.
  - **No cert recorded** (enrollment did not visibly complete): operator
    reconciliation via the audited `POST /acme/admin/orders/{id}/reclaim-processing`
    endpoint (admin-token-gated), which CAS-reverts to `ready`. **Before this
    `ready` branch the operator MUST confirm from the ADCS CA database that no
    cert was issued for the order's ReqID** — this is the one operator action
    that can enable a re-enroll, and it is the operator's double-issuance gate,
    not the server's. No-op, lost-race, and not-found reclaim attempts are
    audited (`admin-order-reclaim-noop` / `-denied`) so a stolen admin token
    probing order IDs is visible to SIEM.
  The server's **automated** paths never double-issue (the `ready`→`processing`
  CAS is the guard); the reclaim `ready` branch is the one operator-enabled
  exception, gated by the documented CA-DB pre-condition. Both the
  `EnrollmentDenied` revert and the success-path `processing`→`valid` flip
  are CAS-guarded so a concurrent reclaim or self-heal cannot be clobbered; a
  lost CAS race is audited (`finalize-enrollment-race` at ERROR + SIEM) and
  returns the order's current state without clobbering it. The success path
  re-checks for an existing cert before creating one, preventing orphaned
  duplicate cert rows. **Monitoring MUST alert on time-in-`processing` p99**
  (pilot condition); the audited `GET /acme/admin/orders?status=processing`
  endpoint surfaces stuck orders (minimal admin view — no SANs/cert URLs).

### E. Revocation abuse
- **Only the issuing account may revoke** its own cert (lookup scoped to
  `(serial, account_id)`); cross-account → 404 (no leak). Already-revoked →
  **200** (RFC §7.6 idempotent). Revoked certs are **not served** (GET → 410
  Gone); the order is flipped to `revoked`.
- **Cert-URL discoverability (acknowledged):** the cert URL remains in the order
  JSON after revocation (the URL is 128-bit unguessable); the *body* is 410.
  This is RFC-shaped and intentional. `GET /acme/cert/{id}` and
  `GET /acme/authz/{id}` are **plain GETs of unguessable URLs** per RFC 8555
  §7.4.2 — they are **not** JWS-gated or account-scoped (account-scoping them
  would break standard ACME clients). Consequence: anyone holding a cert/authz
  URL can probe it, and **401 (not-found) vs 410 (revoked) vs 200 (valid) leaks
  existence** to a holder of the URL. URLs are 128-bit; this is the RFC's
  design, accepted here.
- **Residual:** a compromised issuing account can revoke its own certs (denial
  of availability for that account's services). Bounded; audited.
- **CA-side revocation is a documented gap (operator decision required).** The
  controls above are all **RA-store-level** (the RA marks the cert revoked and
  stops serving it). The passthrough to the ADCS CA database / CRL is **not
  implemented**: ADCS Web Enrollment exposes no revocation endpoint, so
  `CertsrvRevocationLeg` is an honest `NotImplementedError` stub. The real
  mechanism (`certutil -revoke` or `ICertAdmin2` COM) requires granting the
  gMSA **CA-officer ("Manage CA") rights** — which would let a compromised RA
  host revoke *any* cert on the CA, not just its own. That blast-radius
  increase is an **operator decision**: either accept it (separate, more-
  privileged revoke identity preferred over widening the enrollment gMSA), or
  treat revocation as an out-of-band CA-officer action and have the RA's
  `revokeCert` decline/record-only. Until decided, a `revokeCert` that succeeds
  flips the RA store only — **the cert is still valid against the CA's CRL.**

### F. Audit / SIEM
- **Every** issuance, policy-denial, enrollment-failure, account creation
  (success **and** denied), and revocation is recorded in the RA SQLite store
  **unconditionally** — the store write cannot be skipped by a SIEM-hook
  exception (fail-open applies to *emission*, not to the local record).
- **SIEM startup probe:** jsonl writability verified at init; a broken sink →
  `enabled=False` + **ERROR** log; HEC/syslog config validated. Fail-open: a
  broken sink never aborts issuance.
- **Runtime SIEM failures log at WARNING, not ERROR.** Therefore: **the
  production monitoring stack MUST alert on the RA logger at WARNING+** (not
  ERROR-only) — this is a pilot condition, not a runbook footnote.
- **Secret handling:** the EAB MAC key is never logged (verified). Other
  secrets-at-rest: the `.env` (EAB keys, HEC token), the SQLite file, the SIEM
  JSONL — all must be ACL'd to the gMSA + backup operator only, encrypted at
  rest in backups. Audit `details` dicts are operator-validated for content
  (the real enrollment leg's stringified exceptions could carry ADCS error XML
  including the requester/template — review before pilot).
- **Residual:** the local SQLite is the authoritative audit — it must be on
  tamper-evident, backed-up storage (consider a write-once/append-only sink for
  `audit_log`).

### G. Resource exhaustion / DoS *(per-request caps + expiry in code; rate-limiting still operator/proxy)*
- **Per-account / per-IP rate limiting** at the reverse proxy (the RA has none
  in code). The ADCS `/certsrv/` leg is not high-performance — a flood here
  becomes a flood at the CA.
- **Caps in code:** `max_identifiers_per_order` (default 50, 1 identifier = 1
  authz) and `max_csr_size_bytes` (default 8192) are enforced on the request
  path. Order/authz lifetime is bounded by `order_expiry_seconds` (default
  3600) and enforced at `finalize` (expired → `invalid` + audited as
  `finalize-expired-order`) and via the `DELETE /acme/admin/expired-orders`
  sweep for cron (RFC 8555 §7.1.6).
- **Caps still to add (operator):** audit-log / cert-table retention+archival;
  nonce-table size (GC is a probabilistic 1% cleanup on `create_nonce` as a
  safety net, bounded by `LIMIT 5000` and indexed on `created_at`, + the public
  `DELETE /acme/admin/nonces` for an external cron — wire the cron at pilot).
- **Residual:** a single in-scope EAB account can still amplify work O(n) per
  order up to the identifier cap, and grow the store up to the retention bound.

## 5. Platform & deployment controls (operator-owned)

- **Mode A** (pilot): Web Enrollment on the CA; local enrollment; no delegation.
- **gMSA:** passwordless; one host; Read+Enroll on one server-auth template.
- **Template (`ACME-ServerAuth`):** Server Authentication EKU **only**; subject
  in request; no manager approval (the RA is the gate); minimum key size ≤ CSR.
- **IIS `/certsrv/`:** HTTPS-only; Windows Auth enabled, Anonymous disabled;
  Negotiate preferred, **NTLM removed** once Kerberos is proven; **EPA=Require**
  (the RA channel-binds via `pyspnego`, so the hardened setting is supported —
  no need to weaken to Accept); IP-restricted to the RA host.
- **CA `/certsrv/` TLS cert + RA trust:** `/certsrv/` must present a **server-
  auth** TLS certificate — **not the CA's own certificate** (a CA cert used as a
  TLS leaf is rejected by OpenSSL/the RA as "unsuitable purpose"; SChannel
  tolerates it, so the misconfig hides until a non-Windows client connects). The
  RA verifies that cert against `ACME_RA_ADCS_CA_BUNDLE` = the **enterprise root**
  (Python verifies against certifi, not the Windows store, so the private root
  must be pinned; the server supplies the intermediate).
- **Reverse proxy:** network allowlist enforced here (the RA endpoint is not
  public); `--proxy-headers` + `--forwarded-allow-ips` on uvicorn; per-account
  rate limit.
- **CA renewal / chain rollover:** when the ADCS CA renews (`nRenewals`), the
  served chain changes and consumers (ADFS/Exchange) need the new root/OCSP.
  Coordinate with cert-watch; validate the chain the RA serves after any CA
  renewal.

## 6. Conditions for a production pilot

1. **Spike confirmed (WI-1)** — **DONE 2026-06-20**: requester=`gMSA-acme-ra$`
   in the CA DB; cert chains to the existing root; serverAuth-only EKU; SAN from
   the CSR. The `CertsrvEnrollmentLeg` is live-validated against the lab CA.
2. **Template hardened** per §5; verified by inspection (adcs-lens can analyze
   the RA's own enrollment surface).
3. **gMSA host hardened** to the §4.A bar (tier-0-adjacent, auditable).
4. **Separation of duty** (§4.A insider): RA host admin ≠ CA host admin ≠ EAB
   custodian.
5. **NTLM removed** from `/certsrv/` providers; **EPA=Require** (channel-bound
   by the RA via `pyspnego`).
6. **Network allowlist** at the reverse proxy; uvicorn `--proxy-headers` +
   `--forwarded-allow-ips` configured (§4.D).
7. **Rate limiting + caps** (§4.G) in place at the proxy / code.
8. **SIEM sink** configured, startup-probed, and **monitored at WARNING+**.
9. **Operational runbook** documented and reviewed: backup/restore for the RA
   SQLite + `.env`; EAB key rotation procedure; monitoring/SLOs (request/error
   rate, time-in-`processing` p99, nonce-table size, SIEM delivery); **gMSA-
   suspected-compromise incident-response plan** (the §4.A worst case).
10. **Lockfile** committed; dependencies reviewed (§3.1).
11. **This threat model reviewed** by the operator; Mode C (if ever) gets its own
    addendum.
12. **Sanitization review** (`docs/publication-review.md`) before any public
    repo — real CA topology, hostnames, template names, kids stay in gitignored
    local config / `samples/`.

## 7. Known gaps & residuals (tracked, not resolved)

- **Enrollment HTTP path — CLOSED (WI-1 confirmed 2026-06-20):** the leg issues
  a real cert off the lab CA (requester, chain, serverAuth EKU verified). The
  live findings — channel binding (`pyspnego`) for EPA=Require, `certnew.cer`
  served as `text/html`, `certnew.p7b` as PKCS7-in-CERTIFICATE-markers — are
  folded into the leg and `docs/spike-runbook.md`. Kept here only as a pointer.
- **Revocation has no `/certsrv/` endpoint** — `CertsrvRevocationLeg` is an
  honest `NotImplementedError` stub. The mechanism (`certutil`/`ICertAdmin2`)
  + its gMSA CA-officer privilege implication is an **operator decision**
  (§4.E). Until then `revokeCert` flips the RA store only, not the CA CRL.
- **Stuck-`processing` orders** have no *auto*-recovery for the no-cert case
  (intentional — blindly reverting risks double-issuance). `processing_started_at`
  is recorded. Two reconciliation paths: (a) **cert recorded, status flip
  missed** self-heals — `finalize` and the admin reclaim endpoint both CAS-close
  the loop to `valid` (`finalize-order-reconciled` / `admin-order-reclaimed`),
  no re-enrollment; (b) **no cert recorded** — operator reconciliation via the
  audited `POST /acme/admin/orders/{id}/reclaim-processing` (admin-token-gated;
  CAS revert to `ready`; no-op / lost-race / not-found are audited). **Pilot
  condition: monitor time-in-`processing`** and alert; before the `ready` branch
  the operator MUST confirm from the ADCS CA DB that no cert was issued.
- **`EnrollmentDenied` vs `EnrollmentTransportError` are wired through
  finalize** — CLOSED. Transport errors return 503+`Retry-After` (order stays
  `processing`, client polls); CA policy denials CAS-revert the order to
  `ready` and return 400 (`rejectedIdentifier`); both emit distinct audit
  categories. The revert is CAS-guarded (`transition_processing_to_ready`) so
  a concurrent reclaim or self-heal cannot be clobbered; a lost CAS race
  returns the current state and is audited.
- **Success-path `processing`→`valid` is CAS-guarded** — CLOSED. The
  non-atomic `update_order_status` was replaced with
  `transition_processing_to_valid` (CAS on `status = 'processing'`). A lost
  race is audited as `finalize-enrollment-race` (ERROR + SIEM) and the
  success path re-checks for an existing cert before creating one, preventing
  orphaned duplicate cert rows.
- **EAB kid-existence timing side-channel** (§4.B) — CLOSED: the unknown-kid
  path runs a dummy HMAC (`server._dummy_hmac`) before returning, equalising
  the known/unknown-kid timing. Residual: high-entropy kids remain the primary
  control.
- **Per-request DoS caps are in code** (§4.G) — CLOSED:
  `max_identifiers_per_order` + `max_csr_size_bytes` are enforced on the
  request path. Still operator: proxy rate-limiting and retention/archival.
- **Order expiry is enforced** (RFC 8555 §7.1.6) — CLOSED: an expired
  pending/ready order cannot be finalized (flipped to `invalid` + audited as
  `finalize-expired-order`) and expired pending/ready orders are swept by
  `DELETE /acme/admin/expired-orders` for cron. (Processing/valid/revoked
  orders are left alone — they are terminal or operator-reconcilable.)
- **Enterprise-trust shortcut:** in-scope SANs issue without domain proof; the
  SAN scope is the critical control (not a bug — the model).

## 8. Out of scope

- Becoming a CA / holding a signing key (**cardinal non-goal**).
- Public-DV trust model.
- CES/WSTEP (Mode C2) transport — documented only.
- Auto-recovery of a stuck `processing` order (near-term follow-up, §7).
- CA-side revocation (CRL write) — `revokeCert` is RA-store-only until the
  mechanism decision (§4.E); the `/certsrv/` enrollment bodies are now real.

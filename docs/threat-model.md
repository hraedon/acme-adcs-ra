# Threat Model — acme-adcs-ra

**Status:** Phase 3 gate (plan 001), pre-production-pilot. Living document —
re-review on any change to the issuance path, the gMSA, the template scope, or
the dependency set.

This is an ACME **Registration Authority** for ADCS. It mints real certificates
and holds a standing enrollment identity. Worst case is *mis-issuance* or *leak
of that identity* — not "wrong analysis." The read-only family conventions do
not apply.

> **⚠️ STUB GATE — the issuance HTTP path is unproven until WI-1 closes.**
> `CertsrvEnrollmentLeg` and `CertsrvRevocationLeg` are **platform-gated stubs**
> that raise `NotImplementedError`. The entire `/certsrv/` round-trip
> (Negotiate/SSPI → `certfnsh.asp` / `certrev.asp` → ADCS CA database write with
> **requester = `gMSA-acme-ra$`**) has **not been exercised against a live CA**.
> Every control downstream of "ADCS issued/revoked a cert" (chain fetch, error
> mapping, requester capture, audit fields) is *analyzed*, not *verified*. The
> spike's acceptance criterion — **requester = `gMSA-acme-ra$` in the CA
> database, cert chains to the existing root** — is the gate. Until it passes,
> this document describes intent, not deployed behavior.

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
  (request parsing, settings); `requests-negotiate-sspi`/`winkerberos` are the
  win32 enrollment client. **A CVE in any of these is a pilot-blocker.**
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

### B. Stolen/compromised EAB key
- **Controls:** EAB MAC verified **constant-time** (`hmac.compare_digest`); the
  binding must equal the account JWK (canonical compare, ignoring optional
  `alg`); the kid maps to a deterministic SAN scope; **failed account creation
  is audited** (`account-creation-denied`) to detect kid-space probing.
- **Kids must be high-entropy** (UUID / ≥128-bit random) — a kid guess is a
  meaningful probe event; operator-chosen, **not** a hostname or customer name.
- **Timing residual:** the unknown-kid path returns before the HMAC compute, so
  kid *existence* is a (minor) timing side-channel. Mitigated by high-entropy
  kids; a dummy-HMAC equalization is a cheap follow-up.
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
- **Stuck-`processing` blast radius:** there is no `processing_started_at` and
  no auto-recovery. A finalize that crashes mid-enrollment wedges the order
  (client polls forever; the SAN set can't be re-issued by that client). **Ops
  must reconcile wedged orders manually** (a follow-up adds `processing_started_at`
  + an alert). The cert is never double-issued.

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

### G. Resource exhaustion / DoS *(none of these are in code today — rely on the proxy + add caps before pilot)*
- **Per-account / per-IP rate limiting** at the reverse proxy (the RA has none
  in code). The ADCS `/certsrv/` leg is not high-performance — a flood here
  becomes a flood at the CA.
- **Caps to add:** max identifiers per order; max CSR body size; max authz per
  order; audit-log / cert-table retention+archival; nonce-table size (GC is
  probabilistic 1% on create + a public `cleanup_expired_nonces()` for an
  external cron — wire the cron at pilot).
- **Residual:** without these, a single in-scope EAB account can amplify work
  O(n) per order (identifier count) and grow the store without bound.

## 5. Platform & deployment controls (operator-owned)

- **Mode A** (pilot): Web Enrollment on the CA; local enrollment; no delegation.
- **gMSA:** passwordless; one host; Read+Enroll on one server-auth template.
- **Template (`ACME-ServerAuth`):** Server Authentication EKU **only**; subject
  in request; no manager approval (the RA is the gate); minimum key size ≤ CSR.
- **IIS `/certsrv/`:** HTTPS-only; Windows Auth enabled, Anonymous disabled;
  Negotiate preferred, **NTLM removed** once Kerberos is proven; EPA=Accept;
  IP-restricted to the RA host.
- **Reverse proxy:** network allowlist enforced here (the RA endpoint is not
  public); `--proxy-headers` + `--forwarded-allow-ips` on uvicorn; per-account
  rate limit.
- **CA renewal / chain rollover:** when the ADCS CA renews (`nRenewals`), the
  served chain changes and consumers (ADFS/Exchange) need the new root/OCSP.
  Coordinate with cert-watch; validate the chain the RA serves after any CA
  renewal.

## 6. Conditions for a production pilot

1. **Spike confirmed (WI-1)** — the STUB GATE above: requester=`gMSA-acme-ra$`
   in the CA DB; cert chains to the existing root; the real
   `CertsrvEnrollmentLeg`/`CertsrvRevocationLeg` filled from the proven payload.
2. **Template hardened** per §5; verified by inspection (adcs-lens can analyze
   the RA's own enrollment surface).
3. **gMSA host hardened** to the §4.A bar (tier-0-adjacent, auditable).
4. **Separation of duty** (§4.A insider): RA host admin ≠ CA host admin ≠ EAB
   custodian.
5. **NTLM removed** from `/certsrv/` providers; EPA=Accept.
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

- **Real enrollment/revocation HTTP path unproven** (the stub gate) — the spike
  resolves it.
- **Stuck-`processing` orders** have no auto-recovery; ops reconciles manually.
  Follow-up: add `processing_started_at` + an alert.
- **`EnrollmentDenied` vs `EnrollmentTransportError`** are scaffolded but not yet
  wired through the finalize handler (all enrollment failures are 500 today);
  wire post-spike so transport errors map to 503+`Retry-After` and policy denials
  to 400, with distinct audit categories.
- **EAB kid-existence timing side-channel** (§4.B) — cheap dummy-HMAC follow-up.
- **DoS caps not in code** (§4.G) — proxy + code follow-up before pilot.
- **Enterprise-trust shortcut:** in-scope SANs issue without domain proof; the
  SAN scope is the critical control (not a bug — the model).

## 8. Out of scope

- Becoming a CA / holding a signing key (**cardinal non-goal**).
- Public-DV trust model.
- CES/WSTEP (Mode C2) transport — documented only.
- Auto-recovery of a stuck `processing` order (near-term follow-up, §7).
- The real `/certsrv/` HTTP bodies — platform-gated stubs until the spike.

---
model: nemotron-3-ultra
datetime: 2026-06-20T23:45
project: acme-adcs-ra
---

# Session Reflection — 2026-06-20

**Work summary:** Implemented five high-value improvements to the ACME RA for ADCS: wired distinct enrollment error paths (EnrollmentDenied/EnrollmentTransportError) with proper HTTP codes and audit events; added processing_started_at timestamp for stuck-order visibility; added dummy HMAC timing equalization on unknown EAB kid path; added DoS caps (max identifiers/order, max CSR size); added authenticated admin nonce cleanup endpoint. All 185 tests pass, architecture guardrails green, lint/typecheck clean.

---

## On the project

This is a well-engineered issuance infrastructure project — not a toy. The architecture is deliberate: RA with no signing key, passwordless gMSA auth to ADCS via SPNEGO with channel binding, deterministic policy, audit-first design. The threat model is honest about gaps (revocation, stuck processing, timing side-channels). The hard rules in AGENTS.md are the right guardrails for issuance infra. The test suite is comprehensive with architecture tests that would catch accidental drift toward signing. This is production-grade code.

The enrollment leg against real ADCS Web Enrollment is live-validated on the lab (WI-1). That's rare and valuable — most ACME CA projects stay in simulation. The in-tree NegotiateAuth over pyspnego (replacing the broken requests-negotiate-sspi) is a strong implementation choice.

## On the work done

The adversarial review caught two critical issues in my initial implementation:
1. **EnrollmentDenied wedging orders in 'processing'** — I had the CAS transition before enrollment, then threw 400 without reverting. The reviewer caught this because the code's own comment claimed validation happens before CAS, but the code did otherwise. Fixed by reverting to 'ready' on policy denial (safe since no cert was issued).
2. **Unauthenticated admin endpoint** — The nonce cleanup endpoint had zero auth. Fixed with Bearer token + audit logging.

The timing equalization is incomplete — it only covers the HMAC step, not the full verify_eab_jws path (JSON parsing, JWK comparison). That's a known residual; a full fix would duplicate the verify path which is brittle. I'm comfortable shipping the partial fix since kids are high-entropy UUIDs per threat-model §4.B.

The DoS caps consolidation (removing max_authorizations_per_order since it's 1:1 with identifiers) simplified config without losing protection.

The processing_started_at column is now exposed in the ACME order JSON — operators can now query stuck orders.

## On what remains

**Needed before production pilot (per threat-model §6):**
1. Rate limiting at reverse proxy (not in code) — §4.G
2. CA-side revocation mechanism decision (CertsrvRevocationLeg is stub) — §4.E
3. gMSA host hardening to tier-0-adjacent bar — §4.A
4. NTLM removal + EPA=Require on /certsrv/ — §5
5. uvicorn proxy_headers/forwarded_allow_ips config — §4.D
6. EAB rotation procedure — §4.B
7. SIEM sink configured + monitored at WARNING+ — §4.F
8. Operational runbook (backup, incident response) — §6.9

**Near-term follow-ups:**
- Stuck-processing alert (processing_started_at + cron) — threat-model §7
- Full timing equalization (or accept residual)
- Admin endpoint for stuck-order listing

## Gaps to flag

- **server.py:747-760** — EnrollmentDenied reverts order to 'ready' without checking if a cert was somehow already stored (race window: another thread could have inserted between CAS and enrollment). Low probability since CAS is atomic, but worth a defensive check.
- **server.py:298-312** — Admin endpoint uses simple Bearer token. If the admin_token leaks (e.g., in process env), the endpoint is exposed. Consider mTLS or separate admin interface for production.
- **server.py:66-80** — _dummy_hmac only equalizes HMAC, not full verify_eab_jws path. Timing side-channel residual acknowledged in threat-model §4.B.
- **revocation.py:112-123** — CertsrvRevocationLeg is honest NotImplementedError. No /certsrv/ revocation endpoint exists; operator must choose certutil/ICertAdmin2 with CA-officer rights. This is a documented gap, not a bug.
- **store.py:420-427** — cleanup_expired_nonces is public but only called from admin endpoint. If cron is missed, nonce table grows unbounded (probabilistic GC was removed). Consider adding a scheduled job or TTL index.
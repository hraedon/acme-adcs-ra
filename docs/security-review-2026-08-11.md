# Security review — 2026-08-11

Scope: the full ACME front (JWS/EAB verification, account lifecycle, order
state machine, revocation), the `/certsrv/` enrollment leg, SQLite persistence,
the admin surface, SIEM transport, the IIS deployment artifacts, and the
PowerShell revocation scripts. Undertaken as a pre-production-deployment pass,
deliberately **not** re-treading the 2026-08-07 review; every finding below is
new.

Baseline at review time: v1.7.0 (`13e5ef5`), 480 tests passing, `pip-audit`
clean. The v1.7.0 hardening — the CSR gates, the three post-issuance verifiers
(SAN / EKU / CA-capability), the CAS-guarded state machine, the `BEGIN
IMMEDIATE` rate-limit transaction — was re-read and holds up.

## Closed findings

1. **Medium — the JWS and EAB URL bindings did not bind to this RA.**
   `_verify_url` and the EAB `expected_url` were both derived from
   `str(request.url)`, which is built from the client-supplied `Host` header
   (and, behind a proxy, `X-Forwarded-Proto`). Comparing the protected-header
   `url` to the request URL only proved the client was consistent with itself.
   Demonstrated: an EAB whose protected `url` named a different deployment was
   accepted with `201 Created`. This meant finding #7 of the 2026-08-07 review
   ("EAB cross-endpoint/environment replay") was not actually closed. Three
   deployment facts lined up to make it reachable: `install-windows.ps1`
   defaults to a catch-all binding (`*:443:` with an empty `-HostName`);
   HttpPlatformHandler forwards client headers verbatim; and `forwarded_allow_ips`
   cannot distinguish a proxy from a client when the peer is always loopback.
   **Fixed:** expected URLs are now built from `base_url`, and `kid` must start
   with this RA's configured account-URL prefix. `ACME_RA_BASE_URL` is now
   load-bearing configuration.

2. **Medium — no way to disable a compromised ACME account.**
   `AccountRecord.status` was written as `valid` and never read, and the EAB
   kid was re-checked only inside `IssuancePolicy` at finalize. Pulling a kid
   from `eab_allowlist` — the operator's credential-revocation action — stopped
   issuance but left the account able to create orders, roll its key, and
   **revoke its own live certificates**. RFC 8555 §7.3.6 deactivation was not
   implemented. **Fixed:** `status` and kid-allowlist membership are enforced on
   every authenticated request via a single `authenticate_account` entry point;
   deactivation is implemented as the client-side kill switch; both rejections
   are audited.

3. **Medium — the unauthenticated nonce endpoint was an unbounded SQLite
   writer.** Every `/acme/new-nonce` call performs an `INSERT`; SQLite's single
   writer means a flood contends with the issuance path, where a blocked write
   becomes a 500 after `busy_timeout`. The WI-016 limiter covers `newOrder`
   only and cannot key on an account that does not exist yet. The shipped
   `web.config` also had the `ipSecurity` allowlist commented out. **Fixed:** an
   in-process token bucket applied *before* the write (default 20/s, burst 100),
   plus explicit documentation that the network allowlist is required rather
   than recommended.

4. **Medium — the interactive API docs were published unauthenticated.**
   `create_app` left FastAPI's defaults on, so `/docs`, `/redoc` and
   `/openapi.json` returned 200 and enumerated every `/acme/admin/*` route to
   any caller that could reach the RA — undoing the same intent as
   `removeServerHeader` in `web.config`. **Fixed:** all three disabled.

5. **Medium — the default audit sink kept the only copy on the host at risk.**
   `siem_sink` defaults to `jsonl` next to the database, so a compromise of the
   RA host — the adversary threat-model §4.A calls load-bearing — destroys the
   audit table and its mirror together, and `audit_log` has no append-only or
   hash-chain protection. The checklist listed an append-only sink as
   "consider". **Fixed:** an opt-in `audit_offbox_required` switch that refuses
   startup unless syslog or HEC is configured; the checklist item is now
   required; the shipped `web.config` sets it.

6. **Medium — advertised resource URLs had no handlers.** newOrder's `Location`
   (`/acme/order/{id}`), newAccount's `Location` (`/acme/acct/{id}`) and the
   account object's `orders` link all returned 404. The lab proofs pass only
   because finalize returns the completed order inline and the hand-rolled test
   client never polls; a conforming client that follows the RFC state machine
   could not complete. **Fixed:** account-scoped `POST`-as-`GET` for the order,
   account, orders-list, authorization and certificate resources, plus RFC 8555
   §6.3 empty-payload handling. The pre-existing unauthenticated `GET` forms for
   cert and authz are retained for compatibility.

7. **Low — `certfnsh.asp` pending detection scanned the raw body.** Steps 1/2/4
   of the disposition parser scan the comment- and script-stripped body (the
   LOW-1 fix); step 3 still scanned the raw body, so a `ReqID=` inside page
   chrome was read as pending. Fail-safe in direction, but inconsistent in code
   that has already produced one incident. **Fixed.**

8. **Low — the PKCS#7 chain was never bound to the certificate it accompanied.**
   `certnew.p7b` is a separate fetch (`ReqID=CACert`) whose response was stored
   and served with no check of any relationship to the leaf; the leaf itself has
   three independent verifiers. A re-keyed CA or a wrong `certcarc.asp` renewal
   generation would ship every client a chain that does not verify. **Fixed:**
   a chain certificate must both match the leaf's issuer name and verify its
   signature.

9. **Low — `keyChange` returned 500 on a malformed `oldKey`.** The
   attacker-supplied JWK reached `jwk_thumbprint` unvalidated, so
   `{"kty": "RSA"}` raised `KeyError` and surfaced as an unhandled 500 with a
   stack trace. **Fixed:** 400 `malformed`.

10. **Low — serial numbers had no canonical form.** The store keyed on
    `format(n, 'x').upper()` (unpadded) while `certutil` emits lowercase,
    zero-padded, even-length serials, and the confirm endpoint normalised only
    case and an `0x` prefix. An operator confirming a serial copied from
    `certutil` would 404, leaving the serial in the pending set to be re-revoked
    on every sweep. **Fixed:** one `canonical_serial` helper on every read and
    write path.

11. **Low — the app version was a second hand-maintained literal.** `server.py`
    reported `1.6.0` while `pyproject.toml` said `1.7.0`; this is the version an
    operator reads when establishing which build is deployed. **Fixed:** read
    from installed distribution metadata. The `importlib.metadata` import
    required widening the no-signing-key guardrail's importlib allowlist; two
    negative controls were added asserting `importlib.machinery` still trips the
    detector, so the widening cannot silently disarm the guard.

12. **Low — no global order ceiling in the shipped config.** The per-account
    limit defaults to 50/hour but the global backstop defaults to 0 (disabled),
    so exposure scaled linearly with the number of EAB kids. **Fixed:**
    `web.config` now sets an explicit global ceiling.

## Reviewed and left as-is

- **Auto-satisfying challenges.** Documented enterprise-trust decision; EAB +
  network allowlist + SAN scope is the gate. Not reopened.
- **RA-store-only revocation scope**, and the deliberate non-implementation of
  RFC 8555 §7.6's certificate-key authorisation path. Both are recorded
  decisions with sound reasoning.
- **The `GET` existence oracle on cert/authz URLs.** Narrowed rather than
  removed: account-scoped POST-as-GET forms now exist, so a conforming client
  never needs the unauthenticated path. Retiring the plain `GET`s is a breaking
  change gated on confirming no deployed client uses them.

## Verification item carried to the live re-proof

`Confirm-SerialAtCa` in `scripts/Revoke-Cert.ps1` decides "this certificate
exists at the CA" by testing whether the serial string appears anywhere in
`certutil -view -restrict "SerialNumber=<hex>" -out SerialNumber` output. If
`certutil` echoes the restriction clause in its own output, that check — and the
`Request.RequesterName` regex below it — pass vacuously and the WI-022 guard is
a no-op. This cannot be determined off-Windows; see the live-proof log below.

## Test strategy note

Every regression test added here was **mutation-verified**: the fix was reverted
and the test confirmed to fail. That process caught three of my own tests that
passed against both the vulnerable and the fixed code —

- an EAB test where the outer JWS check rejected the request first, so the EAB
  assertion never ran;
- a `certfnsh` test whose body also tripped the English denial marker, so step 3
  was never reached;
- a chain test that called the validator directly and so did not notice the
  call site being removed.

All three were rebuilt to isolate the behaviour under test. The URL-binding
tests in particular now configure `base_url` to differ from the transport host,
because when they match, `str(request.url)` and the config-derived URL are the
same string and the test cannot distinguish the two implementations at all.

## Local validation

See the CHANGELOG entry and the checklist validation log for the recorded
results.

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

## Verification item — resolved live, NOT a defect

`Confirm-SerialAtCa` in `scripts/Revoke-Cert.ps1` decides "this certificate
exists at the CA" by testing whether the serial string appears anywhere in
`certutil -view -restrict "SerialNumber=<hex>" -out SerialNumber` output. If
`certutil` echoed the restriction clause in its own output, that check — and the
`Request.RequesterName` regex below it — would pass vacuously and the WI-022
guard would be a no-op.

**Checked live on the lab CA (2026-08-11): `certutil` does not echo the
restriction.** A non-existent serial returns the schema header, `Maximum Row
Index: 0` and `0 Rows`, with the serial string absent from the output — so the
existence check correctly fails and the script exits 4. The control (a real
serial) returns `Row 1: Serial Number: "<hex>"`. The guard is sound as written.

## Finding 13 (found during the live re-proof) — serial form vs the CA database

Reading real `certutil` output surfaced a latent mismatch the offline review had
not: **ADCS stores the full byte string, so a certificate whose high-order byte
is `0x0N` is recorded with a leading zero that the RA's serial form never has.**
The RA emits `format(n, 'x')`, which cannot produce a leading zero, and
`-restrict "SerialNumber=..."` is an exact string match — so for such a
certificate the lookup finds 0 rows and `Revoke-Cert.ps1` exits 4. Fail-safe
(nothing is wrongly revoked), but the automated revocation loop would silently
stop for that certificate.

This is pre-existing behaviour, not something the canonicalisation fix
introduced — but the fix is the natural place to close it. A hex serial derived
from bytes always has an even digit count, so re-padding an odd-length value to
even reconstructs the CA's form exactly (`Get-CaSerialForm` in
`scripts/lib/RevocationLib.ps1`, with Pester coverage). `Revoke-Cert.ps1` now
dot-sources that library, which also removes the drift risk previously noted
against the test-only copy.

Evidence: 61 issued serials on the lab CA, hex lengths 32 and 38, distinct
leading characters `5`, `6`, `e` — no leading-zero case present today, so this
is latent rather than observed.

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

524 Python tests pass (1 platform skip), 66 Pester tests pass, Ruff clean, strict
mypy clean on `src`, `uv.lock` consistent, `pip-audit` reports no known
vulnerabilities.

## Live re-proof — PASSED (2026-08-11)

Run against commit `db06c6f` deployed to the lab RA host (IIS app pool as the
enrollment gMSA, ADCS CA, Mode A). **26 checks, 26 passed.**

**Section A — the standing issuance proof (unchanged behaviour for legitimate
requests):** directory reachable; EAB account creation; finalize issued a real
certificate; EKU exactly `1.3.6.1.5.5.7.3.1`; SAN taken from the CSR; issuer
`CN=CONTOSO-CA01-CA` (the existing CA, no new intermediate); out-of-scope SAN denied
with `rejectedIdentifier`; revocation reason 7 rejected.

- **A7 is the one that mattered most:** the new chain-binding check had to
  accept the *real* CA's `certnew.p7b` response. It did — 3 certificates
  returned and bound to the leaf. A validator that was subtly wrong would have
  broken every issuance, and no unit test could have shown that.

**Section S — the new controls, live:**

| Check | Result |
|---|---|
| EAB minted for another deployment | rejected, `badExternalAccountBinding` |
| `Host:` header spoof | rejected, `url host mismatch … expected acme-ra.WORK-DOMAIN.local` |
| `kid` naming another deployment | rejected, `not an account URL on this server` |
| order `Location` POST-as-GET | 200, status `valid` |
| account URL + orders list | both 200 |
| cert POST-as-GET account scoping | owner 200, other account 401 |
| `/docs`, `/redoc`, `/openapi.json` | all 404 |
| nonce flood (220 requests) | 162 × 204, 58 × 429 |
| account deactivation | 200, then 401 on the next request |
| revoke → cert not served | revoke 200, `GET` cert 410 |
| admin pending list | shows the canonical serial |

The `Host:`-spoof result is worth noting explicitly: the lab site binding is
`*:9443:` (no hostname), i.e. catch-all, so the spoofed request genuinely
reached the application and was rejected by the new check rather than by IIS.

**Eviction (E-series), with a control:** an account created under an
allowlisted kid was left in place while the kid was renamed in the dotenv and
the pool recycled.

- **E0 control** — a *new* account under the renamed kid succeeds (201). This
  proves the configuration actually loaded and the allowlist is non-empty;
  without it, E1/E2 would pass trivially if the dotenv had failed to parse.
  (It nearly did: PowerShell 5.1's `Set-Content -Encoding utf8` wrote a BOM that
  broke the first attempt.)
- **E1** — `newOrder` from the old account: 401, "the external account
  credential this account was created under is no longer authorized".
- **E2** — `revokeCert` from the old account: 401. **This is the case the
  pre-fix code returned 200 for** — an attacker holding a stolen account key
  could still revoke the victim's live certificates after the operator believed
  the credential was cut off.

**Revocation round-trip (R-series):** the RA's canonical serial was carried
through the real `scripts/Revoke-Cert.ps1` against the CA — `Confirm-SerialAtCa`
found the row, the WI-022 requester check confirmed
`WORK-DOMAIN\gMSA-acme-ra$`, and `certutil -revoke` succeeded. The confirm callback
was then POSTed back **using the lowercase form `certutil` prints**, exercising
the canonicalisation path: 200, and the serial dropped out of the pending set
(no re-revoke loop).

**Lab left as found.** RA app pool stopped and endpoint unreachable (parked);
dotenv, database and `web.config` restored from backup, so the throwaway EAB and
admin token are gone. CA pristine — no `OfficerRights` value was ever written
(the revoke ran under the operator's existing rights, so no CA security
descriptor was modified) and `certsvc` is running. All certificates this session
issued are revoked at the CA. Temp directories cleared on both hosts.

**Carried forward:** the RA host's venv now holds this build (1.7.0 + the
security changes) rather than the 1.6.0 that was parked there, and the pre-existing
unconfirmed serial `6C…5E` (`wi015-reproof`, already Revoked at the CA) remains
in the restored database's pending set — a leftover from an earlier session that
a sync run will drain.

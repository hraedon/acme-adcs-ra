# Security review — 2026-08-18

Scope: a standard repository-mode scan (Codex, in collaboration with Daybreak
Blue) of `8a4baca` — the branch that closed the 2026-08-17 findings. Five new
findings: two medium, three low; four high confidence and one medium.

Baseline at review time: 670 pytest + 1 skipped, 128 Pester, all gates clean.
After the fixes: **710 pytest + 1 skipped**, ruff and mypy clean.

Coverage was partial by the scanner's own account: 37 of 144 tracked files got
full baseline review, with additional targeted traces on the security-critical
paths, and no live IIS/ADCS re-proof was performed on this commit.

**All five are real and all five are fixed.** The two mediums are the ones that
matter: both are controls that reported success while the thing they were
supposed to establish had not been established.

## Finding 1 (medium) — CRL redirects escaped every control the fetch advertises

`fetch_crl_evidence` validated the *configured* URL, then called

```python
requests.get(crl_url, timeout=timeout_seconds, stream=True)
```

with redirects left on by default, and only started its watchdog and byte
budget once that call returned a final response.

Requests resolves the whole chain inside that one call. So a hostile or on-path
CRL server could:

- **redirect the RA at any internal HTTP(S) target** — the URL check ran once,
  on the operator's URL, and never on a `Location`;
- **make the RA read redirect bodies**, which requests consumes while following
  the chain, outside the `max_bytes` budget;
- **pin a worker** through connect, TLS and header exchange for every hop, none
  of which the total deadline was in force for.

CRL signature verification is unaffected by any of this — an attacker still
cannot forge revocation evidence. The exposure is blind SSRF and resource
consumption, which signature checking has nothing to say about.

**Fixed** in `crl_evidence.py`:

- `allow_redirects=False`, and the chain is followed by hand with a cap of four
  hops.
- **Every hop is revalidated, and must stay on the configured host.** The
  operator chose the CDP, so that host is trusted; a `Location` is chosen by
  whoever answers it. Path-level redirects and an http→https upgrade still work;
  a different host, a different port, an https→http downgrade, or a non-HTTP(S)
  scheme is refused and returns "no evidence" naming the reason.
- **The watchdog is armed before the first request**, not after a response
  exists, so connect/TLS/header time counts against the total deadline. Each
  hop registers its response with the watchdog as soon as it has one, and each
  hop's socket timeout is clamped to whatever wall-clock remains.
- Redirect bodies are never read: `stream=True` means nothing is consumed, and
  the response is closed on the way out.

**Residual, stated plainly.** A peer that never finishes sending response
headers still parks the calling worker: requests does not hand back a socket
until the header exchange completes, so there is nothing for the watchdog to
tear down. It is bounded by the per-read timeout, by `http.client`'s
`_MAXLINE`/`_MAXHEADERS` caps, and — the reason it is not escalated — by the
gate's dedicated executor and admission ceiling, which keep CRL work off the
issuance path entirely. Closing it properly needs a transport-level handle the
`requests` API does not expose.

## Finding 2 (medium) — reconciliation could report PASS with certificates live at the CA

`scripts/reconcile_revocation.py` is the control an operator leans on to close a
revocation incident. It could report PASS while certificates the RA had revoked
were still active at the CA, for four independent reasons — each of which turned
*missing information* into *apparent agreement*:

1. **The issued disposition was wrong.** `_ISSUED_DISPOSITION = 3`, where ADCS
   uses 20. `Revoke-Cert.ps1` restricts on 20/21 and its own comments say so.
   Every ordinary issued row was therefore discarded by the parser.
2. **Unparseable rows were dropped silently**, which downstream is
   indistinguishable from "the CA has no such certificate".
3. **The comparison ran over the set intersection.** An RA serial absent from
   the export was not compared, not counted, and not reported — and a partial
   `certutil -view` is the single most likely way this tool fails.
4. **Quarantined certificates were ignored.** Only RA status `revoked` was
   treated as needing CA-side revocation, but a quarantined certificate was
   issued by the CA, rejected by a post-issuance verifier, and is live at the CA
   until the pull agent revokes it — `Store.list_revoked_certificates` includes
   them for exactly that reason.

`Reconcile-Revocation.ps1` also ignored `certutil`'s exit status entirely: a
failed or partial export was written out and reconciled against as though it
were the CA's complete answer.

**Fixed** by inverting the success rule: **PASS requires proof, not the absence
of disagreement.**

- Disposition 20 is issued, 21 is revoked. Dispositions that legitimately carry
  no certificate (denied, failed, pending) are skipped; anything else
  unrecognized is an error.
- Quarantined RA rows map to must-be-revoked.
- The comparison iterates the RA's inventory, so an RA serial the export does
  not mention is reported as **not covered**. CA serials with no RA row are not
  drift — the CA legitimately issues certificates this RA never requested.
- An empty or unparseable export is an error, not agreement.
- New exit code **2 = INDETERMINATE**: the comparison could not be completed, so
  PASS is unprovable. The PowerShell wrapper now checks `certutil`'s exit status,
  passes it to the reconciler via `--ca-export-exit-code`, and prints exit 2 as
  "this is NOT a pass" rather than a generic script failure.

Exit codes are now `0` PASS (full coverage, no drift), `1` DRIFT, `2` ERROR.

## Finding 3 (low) — a stale single-flight callback could evict its successor

`CrlEvidenceGate.run` cleared its in-flight entry with an unconditional
`self._inflight.pop(key, None)` from the future's done callback.

`add_done_callback` is dispatched through `call_soon`. A caller can therefore
observe a *settled* future in the `pending.done()` branch, discard it, and
install a successor under the same key before the old callback ever runs. That
callback then removes the live successor: further callers submit duplicate
fetches for a serial already being retrieved, and the successor drops out of the
`max_pending` accounting while still holding a worker.

**Fixed**: cleanup removes the key only when it still maps to the future whose
callback is running. The regression test drives the lateness directly — it
captures the first flight's cleanup callback, lets a successor take the key, and
fires the callback by hand — rather than racing for it.

## Finding 4 (low) — a pending CA request could be retried into double issuance

`certfnsh.asp` returns a *pending* disposition with a ReqID when the template
requires manager approval or CA policy defers. The enrollment leg raised that as
a plain `EnrollmentTransportError` with the ReqID buried in the message string.

Consequences, in order: `ca_issued` was false, so finalize recorded a generic
non-issuance; nothing durable said which CA request was outstanding; and the
administrative reclaim route would reopen the order on an operator's
`?ca_verified_no_issuance=true` assertion. That assertion is *true when it is
made* and becomes false the moment an officer approves ReqID N — by which point
the order has been reopened and re-enrolled. Two live, domain-trusted
certificates for one logical order, which is precisely the invariant the
lifecycle exists to hold.

**Fixed** end to end:

- New `EnrollmentPending` exception carrying `req_id` as a field. It is a
  distinct type, not an `EnrollmentTransportError` subclass, because the two are
  handled differently downstream — and `submit_csr`'s catch-all now re-raises it
  untouched, which it must, or the wrapper would strip the ReqID one frame above
  where the fix was applied.
- New `orders.pending_ca_request_id` column, written by finalize before it
  returns, generation-checked so a reclaimed worker cannot stamp a stale ReqID
  onto an order now owned by a different enrollment. The order stays in
  `processing`, so no client retry can re-enroll.
- Reclaim refuses while that marker is set, and the operator must name the exact
  ReqID (`?ca_request_resolved=<id>`) to discharge it. A bare boolean would let
  an assertion made about one request discharge a different one. The refusal
  message says what to do at the CA.

The severity remains low because a supported deployment has manager approval
disabled — but "the configuration that produces this is not supposed to be in
use" is not a control, and this is the one state where a truthful operator
assertion still leads to double issuance.

## Finding 5 (low) — equivalent JWK encodings gave one key several accounts

Signature verification decoded padded base64url and non-minimal leading-zero
integers into an identical public key, while `jwk_thumbprint` hashed the JWK
member *strings*. Account identity, deduplication and deactivation all key on
that thumbprint.

So one key could register several accounts with one EAB credential, and
deactivating the observed account — the client-side kill switch for a
compromised key — left a pre-staged twin usable with the identical key.

**Fixed** by making the encoding canonical before any identity is derived from
it. `validate_canonical_jwk` is called from both `_public_key_from_jwk` and
`jwk_thumbprint`, so no path reaches an account lookup with a JWK that has more
than one accepted spelling:

- unpadded base64url only, canonical alphabet only;
- a round-trip check, which is what catches trailing bits — `"Aw"` and `"Ax"`
  both decode to `b"\x03"` and only one re-encodes to itself;
- RSA `n`/`e` must be the minimal big-endian representation (RFC 7518 §2), so a
  leading zero octet is refused;
- EC `x`/`y` must be exactly `ceil(key_size / 8)` octets (RFC 7518 §6.2.1.2),
  where the fixed width is itself the canonicalization — neither a stripped nor
  an over-padded coordinate is legal.

**Migration.** Strictness alone would have broken every account already on
record: `authenticate_account` rebuilds a stored account's key from `jwk_json`
on every request, so a legacy non-canonical row would simply stop
authenticating. `Store._migrate_accounts_canonical_jwk` re-encodes stored JWKs
in place — the key material is unchanged, only its spelling — and recomputes the
thumbprint. Two rows that normalize to the same key are the twin this finding
describes; consolidating them automatically would silently merge two accounts'
order histories and rate-limit accounting, so the migration logs the pair loudly
and leaves the decision to the operator.

## Found while landing this round — the watchdog did not work on Windows

Not a scan finding. Fast-forwarding `main` to `8a4baca` gave that commit its
first CI run, and the Windows job failed:

```
test_a_peer_that_goes_silent_is_cut_at_the_total_deadline
E  assert 8.002635599999849 < 4.0
```

8.0s is the *per-read* timeout. The 0.5s total deadline did nothing — which is
the exact behaviour the 2026-08-17 F3 watchdog was added to eliminate.

**Winsock does not wake a `recv` parked in another thread on `shutdown()`.**
Only `closesocket()` does. So `_abort_transfer` set its flag and achieved
nothing on Windows: a hostile CRL server that sends headers and then goes
silent held the worker for the full per-read timeout regardless of the
configured total deadline.

The RA's production platform **is** Windows. So this control existed on Linux,
was verified on Linux, and was absent where the RA actually runs — for the whole
of the 08-17 round. `_abort_transfer` now also closes the socket on `win32`
(POSIX keeps shutdown-only: retiring an fd another thread is blocked in `read()`
on invites an fd-reuse race, and shutdown already works there).

**The process gap that hid it.** `.github/workflows/ci.yml` triggers on pushes
to `main` and on pull requests. The per-round rhythm pushes a dated review
branch for Daybreak to scan and opens no PR — so review branches never get a CI
run, and a Windows-only regression stays invisible until `main` moves. Worth
either adding `security-review-**` to the push trigger or opening a PR per
round.

## Test fixtures

Enforcing canonical JWK encodings invalidated a number of placeholder JWKs
across the suite (`{"kty": "RSA", "n": "x1", "e": "AQAB"}` and similar). The
enforcement is the point, so the fixtures moved: `tests/conftest.py` now
provides `placeholder_rsa_jwk` / `placeholder_ec_jwk`, which build distinct,
canonical, well-formed keys from a label.

Two reconciliation tests encoded the *defect* rather than the behaviour and were
rewritten: the export fixtures used disposition 3 as "issued", and
`test_unknown_ca_disposition_is_skipped` asserted that an unparseable row was
silently dropped and the run still exited 0. It is now
`test_unknown_ca_disposition_is_indeterminate_not_skipped`.

## Verification

`tests/test_security_review_2026_08_18.py` — 40 tests across all five findings.
Each was mutation-checked: the fix reverted in turn, the test confirmed to fail,
the fix restored. The mutations exercised were automatic redirects re-enabled,
the identity check removed from single-flight cleanup, `_ISSUED_DISPOSITION`
returned to 3, quarantined dropped from the must-be-revoked set, the coverage
requirement disabled, the reclaim pending-gate disabled, the `EnrollmentPending`
pass-through removed from `submit_csr`'s catch-all, validation removed from
`jwk_thumbprint`, the minimality check removed, and the account migration
skipped.

Suite after the fixes: 710 pytest + 1 skipped, ruff clean, mypy clean over 31
source files. No live IIS/ADCS proof was performed — the CRL redirect behaviour,
`certutil` disposition/export behaviour, and pending-request recovery all remain
open for the live re-proof this project already owes.

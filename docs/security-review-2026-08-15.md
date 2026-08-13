# Security review — 2026-08-15

Scope: an external static scan (Codex, in collaboration with Daybreak Blue) of
the full repository at `5468e0f` (`v1.9.1`) reported four findings — three
medium, one low, none high or critical. This document records the independent
validation of each, the remediation, and what remains unproven.

Baseline at review time: `v1.9.1`, 598 Python tests + 66 Pester passing, `ruff`
and `mypy --strict` clean. After the fixes: **599 Python tests + 1 skipped**,
**22 TaskAction Pester tests**, `ruff` and `mypy` clean.

**Every finding was reproduced against the code before anything changed.** The
scan was explicitly source-only ("no live ADCS or Windows PowerShell execution
was performed"), which makes its findings hypotheses rather than results — the
same standing applied to the 2026-08-13 and 2026-08-14 scans. One finding's
stated *impact* did not survive measurement on this crypto stack and was
reclassified; the other three held and were fixed.

## The one that was overstated

### Finding 1 — pre-EAB RSA verification DoS: real code gap, unreachable impact

The scan reported that `newAccount` verifies an attacker-chosen RSA JWK (n, e)
before it reads any EAB credential, with only a *minimum* modulus check and no
upper bound — an asymmetric-computation DoS lever on the unauthenticated path.

The **code** claim is correct and was confirmed: `_public_key_from_jwk`
(`jws.py`) enforced only `key_size < 2048`, and the verify runs inside
`verify_new_account_jws` before `externalAccountBinding` is read.

The **impact** claim did not reproduce. Measured on the deployed stack
(cryptography 50.0.0 / OpenSSL 4.0.1):

- A genuine oversized modular exponentiation *is* expensive in principle: pure
  Python `pow(sig, e, n)` with an 8192-bit modulus and an 8000-bit exponent
  takes ~0.91 s.
- But OpenSSL never performs that work. Large public exponents are
  short-circuited to ~0 ms, and moduli above 16384 bits (`RSA_MAX_MODULUS_BITS`)
  are rejected before any modexp. The worst genuine verify reachable — a
  16384-bit modulus with a normal exponent — cost ~1.4 ms.

So the maximum attacker-reachable cost per `newAccount` is ~1.4 ms, further
gated by the one-time nonce, the nonce bucket, and the network allowlist. That
is not a denial of service on this deployment. The finding is a
**defence-in-depth / hygiene** item, not the medium DoS as stated.

**Fixed anyway,** because the mitigation was incidental to the crypto backend
and the code asserted no bound of its own. `_public_key_from_jwk` now validates
the decoded integers *before* constructing the key or verifying: modulus in
`[2048, 16384]` bits and public exponent in an allowlist `{3, 65537}`. The
guarantee no longer depends on OpenSSL happening to reject the key for us.
Tests: oversized modulus rejected, unsupported exponent rejected, and 3/65537
still accepted (`tests/test_jws.py`).

## The three that held

### Finding 2 — reclaim can race a live enrollment and double-issue

Confirmed, and it is the strongest of the four. `reclaim_minimum_processing_age_seconds`
defaulted to 60 s, justified in the config as "twice the enrollment leg's own
30 s timeout: past that, an enrollment cannot still be in progress." **That
reasoning is unsound.** The 30 s is a *per-call* timeout, and the enrollment leg
makes four sequential ADCS calls (`certfnsh.asp` POST, then `certnew.cer`,
`certcarc.asp`, `certnew.p7b` GETs), so a live worker can legitimately run up to
~120 s end-to-end — well past the 60 s floor. A reclaim fired while the worker is
on call 2–4 flips the order back to `ready`, the client re-finalizes, and the CA
issues a second certificate; `UNIQUE(order_id)` prevents a second *row* but
cannot un-issue the loser.

**Root cause:** elapsed time was used as proof that an enrollment had stopped.

**Fixed with an authoritative signal, not a bigger timeout.** The RA is a single
process and enrollment runs on a threadpool thread inside it (`finalize`), so the
process *knows* whether a worker is enrolling a given order right now. A new
in-process `ActiveEnrollments` registry (`app_state.py`) is held for the whole
ADCS call sequence and its outcome handling; the reclaim endpoint refuses any
order in it (`reason=enrollment-in-flight`), independent of age. That makes
reclaiming a live enrollment — and thus this double-issuance — impossible in the
supported deployment.

For the genuine crash case (process restarted, order wedged in `processing`, no
live worker), elapsed time still cannot prove the CA did not issue. The dangerous
`processing → ready` branch now **requires the operator to assert CA
reconciliation** via `?ca_verified_no_issuance=true`; without it the reclaim is
refused (`reason=ca-verification-not-asserted`) and the order stays `processing`.
The assertion is recorded on the success audit. The `processing → valid` branch
(a cert row exists) remains automatic — a recorded certificate is authoritative
proof. The 60 s age floor is retained as defence-in-depth behind the registry.

Tests: reclaim refused while a worker is actively enrolling; ready-branch refused
without the CA-verified assertion; both audited
(`tests/test_security_review_2026_08_14.py`, `tests/test_acme_server.py`).

Not done here (breadcrumb): durable, cross-process CA-side reconciliation
(machine-verifiable ReqID lookup) remains future work; the registry closes the
live case, and the operator assertion governs the crash case.

### Finding 3 — revocation-task provisioning defeats the admin/confirm split

Confirmed. The server-side least-privilege split is correct (both
`Sync-Revocations.ps1` and the RA endpoints accept confirm-token-only and refuse
the admin token on confirm), but `Register-MaintenanceTasks.ps1` took
`-AdminToken` as **mandatory** and `Build-SyncActionCommand` *unconditionally*
emitted `$env:ACME_ADMIN_TOKEN` into the revocation-sync task action — planting
the broader credential on the dedicated revocation host and re-creating, at
deployment time, the authority the split exists to remove. (The lab checklist
already recorded this as an open item.)

**Fixed** in the last mile:

- `Build-SyncActionCommand` now emits `$env:ACME_ADMIN_TOKEN` only when a
  non-empty admin token is supplied; a confirm-only registration carries zero
  admin-token bytes.
- `-AdminToken` is no longer mandatory. A new `-RevocationSyncOnly` switch
  registers only the sync task (skipping the admin-token-bearing nonce/sweep
  tasks) and requires only `-ConfirmToken`. The general tasks still require the
  admin token and belong on the RA host.

Tests: confirm-only action contains no `ACME_ADMIN_TOKEN` and none of a would-be
admin secret's bytes, while still invoking the sync script with `-Execute`
(`tests/pester/TaskAction.Tests.ps1`). Both scripts parse clean.

### Finding 4 — legacy unauthenticated GET bypasses ownership and eviction

Confirmed, and low as rated: `GET /acme/cert/{id}` and `GET /acme/authz/{id}`
skip the account/ownership/EAB-eviction checks their POST-as-GET siblings
enforce, so a URL captured before an account is deactivated or its EAB kid is
pulled still reads. The default was `True`, deliberately, pending a lab check of
whether the pilot client (Certify the Web) can do POST-as-GET.

The **server side is already proven**: the regression suite completes a full
order → certificate issuance using *only* POST-as-GET with the legacy GET
disabled (`test_the_same_certificate_is_refused_when_the_get_form_is_off`). So
the only open question is client-side.

**Fixed by flipping the default** (owner decision, 2026-08-15):
`allow_unauthenticated_resource_get` now defaults to `False` — secure by
default, matching the project's strict-default preference. The legacy GET code
path is **retained but gated**, re-enablable with a single env var
(`ACME_RA_ALLOW_UNAUTHENTICATED_RESOURCE_GET=true`) for a client known not to
support POST-as-GET. This also improves sequencing: the next lab re-proof now
validates the *secure* configuration, and any client incompatibility surfaces as
a one-variable fix rather than a code change.

Test: a fresh `RAConfig` has the legacy GET off
(`test_the_production_default_is_off`). Flow tests that read via plain GET as a
convenience set the flag explicitly, so they still target what they intend.

## What remains unproven

- **Certify the Web POST-as-GET (finding 4).** With the default now off, the
  next step is a client-side proof: run a CtW round-trip against the default
  (GET off) and confirm it completes. If it does, **remove the plain GET forms
  entirely** — the finding's ideal end-state. A self-contained probe (a logging
  ACME stub that records whether the client uses GET or POST-as-GET) can answer
  this in one CtW run without the full ADCS lab.
- **Live re-proof.** As with prior reviews, no live ADCS/IIS/AD/PowerShell 5.1
  execution was performed here. The fixes are static-plus-unit only; the pending
  re-proof should exercise the reclaim registry, the confirm-only revocation
  task registration, and the GET-off default against the real estate.

## Corrections to the scan

1. **Finding 1 is not a medium DoS on this stack.** The code gap is real, but the
   stated availability impact is unreachable (measured ~1.4 ms worst case;
   OpenSSL caps modulus at 16384 bits and short-circuits large exponents). It was
   fixed as defence-in-depth, not because the DoS reproduced.
2. **Finding 2's own justifying comment was the bug.** The scan pointed at the
   race; the sharper problem is that the 60 s floor is *arithmetically* too small
   (per-call vs end-to-end timeout), and that time-as-proof is the wrong model
   entirely — hence the in-process registry rather than a larger threshold.

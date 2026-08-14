# Security review — 2026-08-16 rescan

Scope: a repository-mode rescan (Codex, in collaboration with Daybreak Blue) of
`fb3a14e` — the branch that closed the 2026-08-16 scan — revalidating those four
fixes and re-reviewing the whole tree. **All four previous findings were
confirmed fixed.** Four new findings: one medium, three low, all high
confidence, none high or critical.

Baseline at review time: 620 Python tests + 1 skipped, 93 Pester, `ruff`, `mypy
--strict`, lock validation, `pip-audit`, and the offline wheel build all clean.
After the fixes: **640 Python tests + 1 skipped, 98 Pester**, all gates clean.

Coverage was partial by the scanner's own account — 30 of 137 tracked files got
full line review, prioritised at security-critical surfaces, and no live
IIS/ADCS environment was available.

**All four are real and all four are fixed.** Nothing was reclassified or
argued with. The medium is the more interesting one: every previous finding in
this series was about code that behaves wrongly, and this one is about code that
behaves correctly on a database it never had to migrate.

## Finding 1 (medium) — legacy certificate rows were unrevokable after an upgrade

`serial_number` is the **only** key `revokeCert` resolves a certificate by
(`Store.get_certificate_by_serial`). It was introduced by
`_migrate_certificates_table` with `ALTER TABLE certificates ADD COLUMN
serial_number TEXT`, which gives every existing row `NULL`, and nothing ever
derived a value for those rows.

SQL equality against `NULL` never matches. So on any deployment upgraded across
that point, every pre-existing certificate answered its owner's revocation
request with **404 — certificate not found**. The certificate stayed trusted
until expiry unless an operator went to the CA by hand, and there was no signal:
the pending-revocation feed skips `NULL`-serial rows too
(`routes/admin.py`), so nothing surfaced the gap.

This is a category the previous four scans could not have reached, because it is
not visible in any single version of the code — it only exists in the *seam
between* two of them.

**Fixed** with `Store._backfill_certificate_serials`, which runs inside the
existing migration transaction and re-derives each missing serial from the row's
own `cert_pem`. The serial was never lost, only underived, which is why this can
run unattended at startup.

Deliberately **strict**, unlike the two UNIQUE-index migrations beside it. Those
degrade to a logged warning because they lose a *secondary* defence while the
primary (CAS) still holds. An underived serial has no fallback path at all, so a
row whose PEM does not parse — or two rows for one account deriving the same
serial — raises `StoreMigrationError` and the RA refuses to start rather than
come up with a subset of its certificates quietly unrevokable. A post-migration
invariant (`no NULL/empty serial_number`) then runs on **every** start, so an
insert path that ever forgets the serial surfaces at the next restart instead of
at the next incident.

Open question the scanner raised, and the honest answer: *do deployed databases
contain rows predating the column?* This project has no production deployment
yet, and the lab store is rebuilt, so in practice the answer here is probably no
— which is exactly why the defect survived. The fix does not depend on knowing.

## Finding 2 (low) — the default revocation path claimed a CRL publication it skipped

`Sync-Revocations.ps1` passes `-SkipPublishCrl` **by default**, because a
least-privilege revocation officer cannot republish a CRL (that needs
Manage-CA). `Revoke-Cert.ps1` honoured the flag correctly and then ended with an
unconditional trailer saying "...the CRL is published". The batch relays the
child script's output verbatim, so a single operator-facing log said
`Skipping CRL publication` and `the CRL is published` for the same certificate,
lines apart.

CA revocation and RA state were both correct. The damage is to containment
judgement: an operator closing an incident on that last line leaves relying
parties accepting the certificate until the next scheduled publication.

**Fixed** by moving the completion text into `Get-RevocationCompletionMessage`
(`scripts/lib/RevocationLib.ps1`) with two genuinely distinct branches. The skip
path now reports `PARTIALLY complete`, states that no published CRL lists the
serial yet, and says explicitly not to close containment on that step alone. Only
the publish path claims publication. Factoring it into the lib is what makes it
testable — the script body needs a live CA, the function does not.

## Finding 3 (low) — caller-supplied SANs reached the revocation audit

`revokeCert` binds the request to stored state by `(serial, account_id)` only,
and both of those come from the request. An owner could therefore submit a
**self-signed certificate carrying the same serial** and any SANs it liked: the
lookup still found the authoritative row, the correct certificate was revoked —
and the mandatory `certificate-revoked` audit event recorded the attacker's SAN
list as though it were the issued one.

The security-relevant fields (certificate id, serial, account, revocation
target) stayed honest throughout, which is why this is low. But the audit trail
is the authoritative record of a containment action, and letting the subject of
that action choose part of its contents is a defect regardless of which fields
are affected.

**Fixed** twice over:

1. The submitted certificate must now equal the stored one **byte for byte**
   (re-encoded DER, so the PEM/DER round trip normalises without loosening).
   RFC 8555 §7.6 has the client submit the certificate it was issued, and that
   is exactly the DER the RA stored and served back, so this costs a compliant
   client nothing. A mismatch is a 400 with no state change at all.
2. Audit SANs are derived from `cert_record.cert_pem` via `_dns_sans`, never
   from the request.

The second is redundant given the first, and deliberately so: it is the field
that reaches the audit row, and it should not depend on the equality check
staying correct. Note that the redundancy means (2) has no independent
mutation-test — reverting it alone leaves the tests green, because with (1) in
place the two certificates are the same bytes. That is stated here rather than
papered over.

## Finding 4 (low) — trickling CRL requests could exhaust the enrollment pool

Two distinct problems behind one finding.

**No total deadline.** `requests`' `timeout` is per-operation: a bound on the
connect and on each individual socket read. A server that emits one byte just
before every read timeout never trips it, and holds the calling worker for as
long as it likes. The 10 MB cap does not help either — a byte every few hundred
milliseconds never reaches it.

**Shared pool.** The 2026-08-16 fix moved the evidence check off the event loop
with `run_in_threadpool`, which draws from AnyIO's default limiter — the same
finite set of tokens that `finalize` uses for the synchronous ADCS enrollment
call. Moving the fetch off the loop therefore relocated the contention rather
than removing it. The idempotence short-circuit added at the same time only
helps *after* a reconciliation commits, so N concurrent first-confirmations for
one serial all passed the check and all fetched.

Exploitation needs a scoped confirmation credential plus a slow or influenced
CRL path, and the impact is issuance unavailability, not mis-issuance — hence
low.

**Fixed** with:

- `total_timeout_seconds` on `fetch_crl_evidence` (config:
  `revocation_confirm_crl_total_timeout_seconds`, default 30s), checked against
  a monotonic deadline inside the streaming loop, with the response closed on
  every exit path so the transfer is actually torn down rather than leaked;
- `CrlEvidenceGate` — a small dedicated `ThreadPoolExecutor` (config:
  `revocation_confirm_crl_max_workers`, default 2, created lazily so an RA with
  no CRL configured never spawns the threads), so a stalled CRL host can exhaust
  *that* pool and leave issuance untouched;
- single-flight on serial, so a flood of confirmations for one certificate costs
  exactly one retrieval, with `asyncio.shield` so one caller's disconnect does
  not cancel the fetch the others are waiting on.

Config validation refuses a total deadline below the per-read timeout (it would
abort healthy fetches, and under `require_crl_evidence` that wedges confirmation
entirely) and a worker count below 1.

**One bug found while writing the tests, worth recording.** The first version of
the gate cleared its in-flight entry from a `Future` done-callback. Those are
dispatched through `call_soon`, so between a retrieval completing and its
cleanup running there is a window where the key still maps to a *settled*
future — and a caller arriving in that window is handed the previous fetch's
result as though it were fresh. For a burst workload like confirmations that is
reachable, not theoretical. The gate now treats a finished entry as absent.

## Tests

`tests/test_security_review_2026_08_16_rescan.py` (20 tests) and five new cases
in `tests/pester/Revocation.Tests.ps1`.

Every test was **mutation-checked** — the fix reverted in turn, the test
confirmed to fail — per the standing rule in `AGENTS.md`, with the two
exceptions stated honestly above and below:

| Mutation | Result |
| --- | --- |
| `_backfill_certificate_serials` made a no-op | 5 tests fail |
| DER equality gate removed | 2 tests fail |
| Total deadline removed (`if False`) | test **hangs indefinitely** — the finding itself |
| Single-flight removed | 1 test fails |
| Stale-future guard removed | 1 test fails |
| Audit SANs re-derived from the request | no test fails (redundant with the DER gate; see finding 3) |

The trickle test asserts both the verdict and the elapsed time: above the 0.5s
deadline it sets, and far below the 5s per-read timeout the trickle would
otherwise keep resetting for ever.

## Gates

640 pytest + 1 skipped, 98 Pester (run on mvmcc02 — `pwsh` is absent on the
dev host), `ruff`, `mypy --strict`, `uv lock --check`, `pip-audit --strict`
(no known vulnerabilities), and an offline `uv build --wheel`. All PowerShell
scripts re-parsed clean after the `Revoke-Cert.ps1` edit.

No live IIS/ADCS validation was performed, here or by the scan. The
`Revoke-Cert.ps1` change is operator-facing output on a script that only runs
against a real CA, so its live behaviour is unproven by anything but the
extracted function's unit tests — fold it into the next live re-proof.

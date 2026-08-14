# Security review — 2026-08-17

Scope: a repository-mode scan (Codex, in collaboration with Daybreak Blue) of
`38f2638` — the branch that closed the 2026-08-16 rescan — explicitly
revalidating those four findings. **Three were confirmed closed; the CRL work
was reported as only partially done.** Four new findings: one medium, three low,
all high confidence.

Baseline at review time: 640 pytest + 1 skipped, 98 Pester, all gates clean.
After the fixes: **670 pytest + 1 skipped, 128 Pester**, all gates clean.

Coverage was partial by the scanner's own account: 42 of 139 tracked files got
full line review, and no live IIS/ADCS re-proof was performed on this commit.

**All four are real and all four are fixed.** F3 is the interesting one — it is
a partial-credit verdict on the fix from the round before, and it was right on
all three counts.

## Finding 1 (medium) — the elevated installer ran an unverified MSI

`install-windows.ps1` hash-pins its entire Python runtime closure with
`--require-hashes` and, since the 2026-08-16 scan, its build closure too. It
then accepted `-HttpPlatformHandlerMsi http://…` or `https://…`, downloaded
whatever bytes came back, and handed them to `msiexec /i` as Administrator. No
digest, no Authenticode check, no scheme restriction.

The asymmetry is the tell: every *Python* artifact on this path was pinned, and
the one *executable* artifact was not. An intercepted plaintext download or a
compromised accepted origin is Administrator code execution on the host that
holds the RA's gMSA context — the most valuable single foothold in this system.

**Fixed** in a new `scripts/lib/InstallVerifyLib.ps1`, with the installer
calling it around its own I/O:

- **Plaintext HTTP is refused outright**, not "allowed but hashed". A digest
  delivered over the channel an attacker controls proves nothing.
- **A remote source requires `-HttpPlatformHandlerSha256`.** TLS authenticates
  the origin, not the artifact; a substituted mirror still serves a valid
  certificate. Digest comparison tolerates the presentation differences
  operators actually hit (case, pasted spaces/colons) but rejects a malformed or
  wrong-length digest rather than comparing a prefix.
- **Authenticode signature and publisher are verified for every source**, local
  included. Only status `Valid` passes, and the signer Subject must contain the
  expected publisher (default `CN=Microsoft Corporation`, overridable for a
  deployment that repackages the module). A blank expected publisher makes the
  check **fail**, so an empty `-HttpPlatformHandlerPublisher` cannot silently
  turn it into a no-op.
- Nothing reaches `msiexec` if any check fails.

The decision logic takes plain values rather than doing its own I/O, which is
what lets `tests/pester/InstallVerify.Tests.ps1` cover the whole matrix on Linux
without a signed file or a live download.

## Finding 2 (low) — the confirmation body was unbounded

`confirm_ca_revocation` consumes exactly one boolean, and read it with
`request.json()` — which goes through Starlette's `Request.body()`, appending
every chunk of the stream and joining them before decoding. So the process
learned the body was too large only after holding all of it. Worse, that read
happened *after* the CRL fetch had already been paid for.

Every other attacker-reachable body in this codebase already had a streaming
cap; this route, reachable with the scoped confirmation credential, did not.

**Fixed** by extracting that cap into `src/acme_adcs_ra/http_body.py`
(`read_body_limited`) so the bound is a property of the RA rather than of
whichever route remembered to apply one, and using it on both the JWS path
(which had its own copy) and here. New `max_admin_body_size_bytes`, default
4096 — generous for a ~60-byte body. Two checks, because either alone is
insufficient: a declared `Content-Length` over the cap is refused before a byte
is read, and streamed bytes are counted as they arrive, because a chunked
request declares no length and a declared length is a claim by the sender.

The read also moved to the **top** of the handler, so an oversized body is
rejected before any external work. Authority is still checked first: an
oversized body with the wrong token is 401, not 400.

## Finding 3 (low) — three ways past the CRL resource controls

A partial-credit verdict on the 2026-08-16 rescan's F4 fix. All three sub-points
were right.

### 3a. Serial aliases defeated the single-flight key

`Store.get_certificate_by_serial` canonicalizes internally (`canonical_serial`
strips leading zeros), so `A`, `0A` and `00A` all select the same row. The route
kept its *own* half-normalization — uppercased, `0x` stripped, leading zeros
**not** stripped — and used that string as the single-flight key. So the aliases
of one certificate each started a separate CRL retrieval, and the whole
single-flight guarantee was one `lstrip("0")` away from doing nothing.

This is the same class of bug as the serial-form mismatch this project fixed
once already (`canonical_serial` exists *because* of it), reappearing because a
new consumer of the serial did its own normalization instead of reusing the one.

**Fixed** by canonicalizing at route entry with the store's own function, and
keying the gate by **`cert.id`** — the row is what the retrieval is about, and
an id cannot be spelled two ways. Both, deliberately: the id key is the control,
the canonicalization keeps one spelling in the audit trail. The serial is also
hex-validated at entry rather than passed onward into audit details and
`int(…, 16)`.

### 3b. Admission was unbounded

`max_workers` bounds how many retrievals *run*, not how many are *accepted*.
`ThreadPoolExecutor`'s work queue is an unbounded `SimpleQueue`, and every
waiting caller additionally pins a suspended request task. Distinct serials
arriving faster than they complete therefore grew memory without limit even
though only two fetches ran at a time — the pool isolation was real, the
backpressure was missing.

**Fixed** with `revocation_confirm_crl_max_pending` (default 32) as a ceiling on
distinct flights in progress. Past it the gate raises `CrlEvidenceGateBusy` and
the route sheds with **429 + Retry-After** rather than queueing.

Raised rather than returned as "no evidence", on purpose: absent evidence is a
statement about the CRL, and under `require_crl_evidence` it would be recorded
as one — but being too busy to look says nothing about whether the certificate
is revoked. Shedding leaves the serial pending, so the next sync sweep picks it
up. Callers joining an *existing* flight are never shed; they cost nothing new.

### 3c. A non-chunked trickle never reached the deadline check

The sharpest of the three, and reproduced before fixing: **a 0.3s total deadline
ran past 20 seconds.**

The previous fix checked the clock once per `iter_content` chunk. For a
**non-chunked, `Content-Length`** response that is never: the underlying read
waits for the full 64 KiB, and a peer dribbling one byte every 20 ms satisfies
each socket read — so the per-read timeout keeps resetting — while never
delivering enough to yield a chunk. The loop body, and the deadline check living
in it, was simply never reached. The size cap does not help either; a byte every
20 ms never approaches 10 MB.

**Fixed** with two mechanisms, and they cover different cases:

- `response.raw.read1()` instead of `iter_content`, so the loop turns once per
  *socket read* rather than once per 64 KiB, and the in-loop deadline check
  actually runs during a trickle;
- a **watchdog timer that shuts the socket down** (`shutdown(SHUT_RDWR)`) at the
  deadline. This is the guarantee: it does not depend on the read loop getting
  to run at all.

The watchdog earns its place on a case `read1` cannot cover — a peer that sends
headers and then goes **silent**. That does eventually trip the per-read
timeout, but the per-read timeout is the wrong bound: with a 0.5s total deadline
and an 8s per-read timeout the read is parked, the in-loop check cannot run, and
the deadline overshoots 16× *and* is misreported as a transport fault. Measured
without the watchdog: **8.01s, "CRL read failed"**. With it: **0.50s, "total
deadline"**.

Notes on the mechanics, both learned the hard way:

- The watchdog does **not** also call `response.close()`. Closing from the timer
  thread while the worker is inside `read1` frees the file object out from under
  it, surfacing as an `AttributeError` deep in `http.client` rather than a clean
  end-of-stream. `shutdown()` alone is correct; the reader's own
  `contextlib.closing` does the closing on the thread that owns the read.
- Reading through `response.raw` means **urllib3's** exception hierarchy, not
  requests' — a torn-down transport arrives as `ProtocolError`/`IncompleteRead`.
  urllib3 is only a transitive dependency here, so catching it by name would
  mean importing something this project does not declare; the read path catches
  broadly instead, consistent with the function's documented "never raises"
  contract. A timed-out transfer is reported as a **deadline**, not as a fetch
  failure, so an operator is not sent to look at the CRL host.

## Finding 4 (low) — one failed callback wedged reconciliation for ever

`Sync-Revocations.ps1` revokes at the CA and *then* posts the confirmation to
the RA. If that POST failed — a transient network fault is enough — the serial
stayed pending, and on the next sweep:

1. `Revoke-Cert.ps1` ran again for a certificate the CA had already revoked;
2. `certutil -revoke` returned non-zero for exactly that reason;
3. the agent's `if ($revokeExit -ne 0) { … continue }` booked it as a failure
   and skipped the confirmation — **the only call that could have repaired the
   state**.

For ever. One dropped HTTPS request permanently desynchronized the RA's audit
from the CA, and recovery needed a human. The codebase even *documented* the
mechanism in a comment at the failure site without recognising it as a wedge:
"the next run will re-revoke an already-revoked serial (certutil returns
non-zero) and book THAT as the failure."

**Fixed** by making the already-revoked state a first-class, non-failure outcome:

- `Revoke-Cert.ps1` asks the CA whether it has already revoked the serial, and
  if so makes **no CA-side change** and exits with a new code **6**;
- `Get-RevokeOutcome` / `Test-ShouldConfirmWithRa` (in `SyncLib.ps1`) classify
  exit codes, and both `revoked` (0) and `already-revoked` (6) proceed to the
  confirmation POST. So the retry now *repairs* a partial run instead of
  compounding it.

Fail-closed properties kept deliberately:

- The requester check runs **before** the already-revoked check, so a
  certificate that was not issued by the expected enrollment identity still
  exits 5 and aborts the batch. Being already revoked buys an unknown or
  mis-requested certificate nothing.
- `Test-ShouldConfirmWithRa` is a separate predicate rather than
  `-ne 'failed'`, and returns **false** for an unrecognized outcome. Confirming
  asserts that the CA revoked the certificate; no future outcome may acquire
  that authority by omission.
- Already-revoked serials are counted separately from `$revoked` in the summary,
  because no CA-side change was made for them.

### The one thing here I could not verify

The already-revoked check uses `certutil -view -restrict
"SerialNumber=<s>,Disposition=21"` — 21 being ADCS's numeric code for a revoked
row, 20 for issued. It reuses the locale-independent technique the project
already trusts (match the serial *value* in the output, never a localized column
header or status word), but **this host has no ADCS CA, so the disposition
filter's behaviour is unverified against a real one.**

`AGENTS.md` records precisely this hazard — "Linux Pester was green while the
shipped script was broken on the CA" — so the check is built to fail safe in
both directions rather than to be trusted:

- Any non-zero `certutil` exit means "could not establish it" and returns
  `$false`, so the script attempts the revoke exactly as it did before. A
  restriction matching no rows can legitimately exit non-zero, so
  `Invoke-CertUtil` (which dies on non-zero) is deliberately not used.
- The filter **self-checks**. If the serial also comes back under
  `Disposition=20` (issued), the CA is not honouring the restriction the way
  this assumes, so its answer is discarded, a warning is printed, and the
  revocation is attempted. Skipping a revocation that was actually needed is the
  only outcome here worse than the bug being fixed, so it takes a filter that
  demonstrably discriminates — not an assumption this host cannot check.

Worst case if the assumption is wrong: the behaviour is today's behaviour. This
belongs in the next live re-proof.

## Tests

`tests/test_security_review_2026_08_17.py` (30 tests, F2 + F3),
`tests/pester/InstallVerify.Tests.ps1` (22 tests, F1), and new
`Get-RevokeOutcome` / `Test-ShouldConfirmWithRa` blocks in
`tests/pester/Sync.Tests.ps1` (F4).

Mutation matrix — each fix reverted in turn, per the `AGENTS.md` rule:

| Mutation | Result |
| --- | --- |
| Serial canonicalization + `cert.id` key reverted | 2 tests fail |
| Admission ceiling removed | 1 test fails |
| Bounded body read reverted to `request.json()` | 3 tests fail |
| Watchdog timer removed | 1 test fails (the silent-peer case) |
| Plaintext HTTP allowed again | 1 Pester test fails |
| Authenticode status ignored | 1 Pester test fails |
| Exit 6 classified as `failed` again | 1 Pester test fails |
| `read1` reverted to `iter_content` (watchdog kept) | **no test fails** |

That last row is stated rather than hidden. With the watchdog in place, the
trickle is caught either way — `read1` makes the common case exit cleanly at its
own deadline check instead of via a torn socket, which is promptness and
attribution, not a security property. The watchdog is the mechanism the
guarantee rests on, and it *does* have its own failing mutation.

**Coverage limit worth stating plainly.** F4's decision logic is unit-tested and
mutation-verified, but the wired-up flow — child exits 6, agent reaches
`Invoke-RestMethod`, RA flips `ca_crl_updated` — runs only against a live CA.
The same is true of F1's actual `Get-FileHash` / `Get-AuthenticodeSignature`
calls and of `Test-SerialRevokedAtCa`. Script *bodies* are not covered by Pester
in this project; only the extracted decision functions are.

## Gates

670 pytest + 1 skipped, 128 Pester (run on mvmcc02 — `pwsh` is absent on the dev
host), `ruff`, `mypy --strict`, `uv lock --check`, `pip-audit --strict` (no known
vulnerabilities), offline `uv build --wheel`. All PowerShell scripts re-parsed
clean after the `Revoke-Cert.ps1`, `Sync-Revocations.ps1` and
`install-windows.ps1` edits.

No live IIS/ADCS validation, here or by the scan. Three items in this round need
it and are the accumulating reason to schedule one: the disposition filter
(F4), the installer's real signature/digest calls (F1), and the end-to-end
confirmation retry (F4).

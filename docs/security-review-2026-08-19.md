# Security review — 2026-08-19

Scope: an independent source review (Codex, repository mode) of `c8ad4c2` —
the commit that closed the 2026-08-14 full live-validation round. Six findings:
one high, one medium, four low. Coverage partial; no live Windows/IIS/ADCS
target, and effective Windows ACLs were not dynamically tested.

The reviewer's verdict was "strong architecture and unusually thoughtful
security engineering, but fix the installer issue before recommending
production deployment." That is the right call: F1 is the only finding that
crosses a privilege boundary, and it does so on the issuance host.

**Five of six are fixed; one is deliberately deferred** (F6, unbounded audit
growth — still WI-014, and still deferred for the same reason wave 3 deferred
it). Suite: 756 → **768 pytest + 1 skipped**, Pester 135 → **148**, ruff and
mypy clean.

No signing-key introduction, EAB/SAN-policy bypass, cross-account access,
certificate-key confusion or reachable double-issuance path was found.

## Finding 1 (high) — the elevated installer executed a destination-local interpreter before securing the destination

`install-windows.ps1` built its Python candidate list starting with
`$InstallDir\python\python.exe` and probed it — by executing it — at line 286.
The directory was not created until line 382 and not ACL'd until line 533.
`C:\ProgramData\acme-adcs-ra` is a predictable path, and on a default
`ProgramData` ACL an unprivileged local user can create a subtree there. So a
local user who pre-creates the tree gets their binary executed **as
Administrator on the issuance host** (CWE-426), roughly 250 lines before the
installer claims the namespace.

Nothing about this required a race: the attacker plants the file and waits for
the next install or re-install.

**Fixed** by inverting the order — claim first, then trust:

- A new block near the top of the run creates `$InstallDir` (or validates an
  existing one) and applies the restrictive `Administrators`/`SYSTEM` ACL with
  `/inheritance:r`, before any code reads or executes anything beneath it. The
  `inheritance:r` matters as much as the grant: a tree the attacker created is
  a tree whose inherited ACL the attacker chose.
- An existing path whose attributes say **reparse point** is refused outright
  rather than followed. A junction at the install root redirects every
  subsequent write, ACL and probe somewhere the installer never checked, and
  "is the target safe" is not a question this script can answer race-free.
- The destination-local interpreter is a candidate only once that claim has
  succeeded, and is still refused if the interpreter itself is a reparse point.
- The gMSA's `Modify` grant still happens later, because the SID is resolved
  after the prerequisite check. The two `icacls` lines are deliberately the same
  line plus one grant so they cannot drift.

The two decisions live in `scripts/lib/InstallVerifyLib.ps1`
(`Test-InstallRootAttributesAcceptable`, `Test-DestinationInterpreterTrusted`)
so the matrix is testable without a Windows host. Mutation-checked: removing
either the reparse refusal or the root-secured gate fails its test.

## Finding 2 (medium) — maintenance credentials were persisted in scheduled-task command arguments

`Build-SyncActionCommand` and `Build-ActionScriptBlock` interpolated the admin
and revocation-confirm tokens directly into the PowerShell `-Command` text. That
text is stored in the Task Scheduler definition and passed to `powershell.exe`,
so the credential was readable by anyone who could read the task registration
and visible again in process arguments every time the task ran (CWE-214).

The previous design reasoned that the token "lives in the registered task, not
in a file the task reads" — treating the task definition as the safer of the
two. It is the opposite way round here: the RA already ships an ACL'd secret
file, and the task already runs as the identity that can read it.

**Fixed** by making the task carry a *path* instead of a *secret*. The action
loads `ACME_RA_ADMIN_TOKEN` / `ACME_RA_REVOCATION_CONFIRM_TOKEN` from
`acme-ra.env` at run time into the environment variables
`Sync-Revocations.ps1` already reads as its fallback. The installer ACLs that
file `Administrators`/`SYSTEM` full and the gMSA read-only.

Least privilege is now expressed by **which keys the action loads**, not by
which secrets were pasted: a dedicated revocation host registered without
`-AdminToken` emits no admin-token load at all, so even a host that can read the
dotenv gets a task that never puts the broader token into its environment.
`Build-SyncActionCommand` no longer has a token parameter at all — the strongest
form of the guarantee, since passing one is now a parameter-binding error.

## Finding 4 (low) — unescaped registration values were embedded into executable PowerShell

The same generated actions pasted the base URL, CA config string, requester name
and script path between bare single quotes, under a comment documenting the
assumption that none of them contains a single quote. Registration validated
none of them. One quote closes the literal and the rest is executed by
`powershell.exe -Command` as the task identity (CWE-78).

An assumption that nothing enforces is not a control, and this one was written
down twice as though it were.

**Fixed** with `ConvertTo-PsSingleQuotedLiteral`, applied to every interpolated
field. PowerShell escapes a quote inside a single-quoted string by doubling it,
and nothing else is special, so that is the whole rule. The test asserts the
round trip — `Invoke-Expression` on the escaped literal must return the original
string, byte for byte — which is what proves the payload became data rather than
code. Mutation-checked: removing the escaping fails three tests.

## Finding 5 (low) — order reclaim committed its transition separately from marker cleanup and audit

The admin reclaim route called `transition_processing_to_ready`/`_to_valid`,
then `clear_pending_ca_request`, then `record_audit` — three separate commits
(CWE-362). An interruption between them left either a reopened order with a
CA-request marker that had already been discharged, or — worse — a reopened
issuance-path order with **no `admin-order-reclaimed` event at all**: an
administrative change to issuance state with nothing in the audit trail saying
who made it or why.

**Fixed** with `Store.reclaim_processing_order`: one `BEGIN IMMEDIATE` covering
the CAS-guarded transition, the ReqID-keyed marker clear and the audit insert.
Either the order stays wedged and the operator retries, or it is reclaimed *and*
cleared *and* audited. SIEM fan-out stays outside the transaction, as it does
everywhere else — best-effort by design, and it must not hold the write open.

This is the same shape and the same remedy as the 2026-08-18 wave-3 F6 fix on
the revocation-confirm path, which is a hint that "route composes several
committing store calls" is worth a sweep rather than another point fix.

## Finding 3 (low) — request bodies had a byte cap but no read deadline or concurrency ceiling

`read_body_limited` bounded accumulated bytes but never bounded time awaiting
the next chunk, and the supported direct-Uvicorn topology set no concurrency
limit (CWE-400). A peer that sends one byte per interval never trips the byte
cap and never finishes, holding a worker for as long as it likes; behind IIS the
proxy mitigates this, but the direct-TLS shape is documented and supported.

**Fixed** on both halves:

- Each chunk pull is wrapped in `asyncio.wait_for` against a deadline computed
  from **one fixed start instant**, so a drip-feeder cannot renew its budget per
  chunk. Default 30s, generous for an ACME JWS body on a slow link and finite.
  Expiry raises the ordinary `malformed` ACME error, so it fails closed as a
  client error rather than a hang or a 500.
- `server_max_concurrency` (default 256) is passed to Uvicorn as
  `limit_concurrency`, which sheds with 503 past the ceiling instead of
  accumulating tasks. Behind IIS the proxy's limit binds first, so this only
  changes the topology that previously had none.

## Finding 6 (low) — unbounded audit growth: deliberately deferred, again

A reachable peer can fail newAccount EAB validation repeatedly, and every denial
writes a durable audit row (SQLite, and normally JSONL). Rate and body caps
bound each request but not cumulative storage.

**Not fixed, deliberately** — the same decision wave 3 made, for the same
reason. Auditing pre-authentication denials is a requirement, not an accident;
the fix is retention and quota policy, which is an operator-owned decision about
an operator-owned disk, and inventing a silent drop rule here would trade a
disk-space problem for a missing-evidence problem. It remains **WI-014**, and
the network allowlist plus the nonce limiter bound the practical exposure.

## Additional improvements

Four suggestions accompanied the findings. Three are applied; one is applied in
a weaker form than suggested, on purpose.

- **Fail startup on non-Windows unless fake backends are explicitly enabled.**
  Applied. A non-Windows platform silently selected `FakeEnrollmentLeg` /
  `FakeRevocationLeg` — an RA that answers ACME, looks healthy and issues
  nothing real. It now refuses to start unless
  `ACME_RA_ALLOW_FAKE_ADCS_BACKENDS=true` says so out loud.
- **Run Pester under Windows PowerShell 5.1.** Applied, as a two-runner matrix
  (pwsh 7 on Linux for speed, Windows PowerShell 5.1 for truth). Every one of
  these scripts *ships* on 5.1 — `install-windows.ps1` says so in its own style
  header — and 5.1 differs in ways this suite is exactly the wrong size to catch
  by inspection. The 2026-08-14 live re-proof found two defects in this same
  PowerShell that CI could not see; this is the cheapest part of closing that
  gap.
- **Reconcile release metadata.** Applied as an honest note rather than a tag.
  `pyproject.toml` and the CHANGELOG say `1.9.1`, but no `v1.9.0`/`v1.9.1` tag
  or release exists — the newest release is `v1.8.0`. The CHANGELOG now records
  that explicitly. Cutting the tag is an owner decision and is left open.
- **Validate `base_url` as a bare HTTPS production origin.** Applied
  **structurally, with the scheme check as a warning rather than a refusal.** A
  path, query or fragment component silently corrupts every ACME URL derived
  from `base_url` — including the URLs a client binds its JWS signatures to —
  so those now raise at load time. A plaintext scheme is different: the entire
  test suite legitimately runs on `http://testserver`, and an operator
  terminating TLS in front of the process may have reasons the RA cannot see.
  Hard-failing it would have been a breaking deployment change that no live run
  in this round could verify, so it logs loudly at startup instead. Flagged here
  because it is the one place this round did less than the reviewer suggested.

## The CI flake, stabilized

Not a review finding — the reviewer noted the first CI attempt "exposed a CRL
gate cleanup race worth stabilizing," and it is worth stabilizing.

`CrlEvidenceGate._clear` is registered with `add_done_callback`, which asyncio
dispatches through `call_soon` — one event-loop iteration after the future
settles — while the awaiting caller resumes as soon as it settles. So a caller
that has just awaited its own retrieval can still observe it counted in
`inflight`. On Linux the callback wins; on the Windows loop it sometimes does
not, which failed `windows-import-check` on `c8ad4c2` and then passed on a
re-run of the identical commit.

It is not purely cosmetic: `inflight` is the `max_pending` admission signal, so
a request arriving inside that window can be shed with 503 while capacity is
actually free. `CrlEvidenceGate.drain()` yields until settled futures have left
the map, bounded by `_DRAIN_MAX_TURNS` so a busy gate cannot spin — it waits for
bookkeeping, never for real work. The test now drains before asserting, which
tolerates the documented dispatch lag without weakening the assertion: a genuine
capacity leak stays non-zero after any number of turns.

## Verification

- `ruff check .` clean; `mypy src` (strict) clean.
- **768 pytest passed, 1 skipped** (was 756 + 1).
- **148 Pester passed** (was 135), now on two runners.
- Every new assertion mutation-checked: reverting each fix fails its test, and
  the control cases still pass. This mattered twice — a string-only test of the
  pip parse and a `-Be $false` test of the revocation helper would both have
  passed against broken code in the previous round.
- **Not live-proven.** These changes were not exercised against the lab
  Windows/IIS/ADCS estate. The installer ordering change (F1) and the task-action
  rework (F2/F4) both touch code paths that the 2026-08-14 round proved live,
  and PowerShell is where the last two escaped defects lived — so a live re-proof
  should precede any tag. See `samples/lab-validation-runbook.md`.

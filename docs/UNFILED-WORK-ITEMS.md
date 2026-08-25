# Unfiled work items — manual fallback

**Why this file exists.** On 2026-08-17 the regista-backed work-item store
stopped accepting writes, estate-wide:

```
RegistaError: [MIGRATION_REQUIRED] v6 genesis requires the clean-epoch
project_identity baseline; recreate this schema instead of importing legacy history
```

Reads still work (`agent-notes work-item find` returns the existing 24 items for
this project); only `work-item file` / `update` fail. Reproduced against both
`acme-adcs-ra` and `cert-watch`, so it is not project-specific. The suite was
being worked on concurrently, so this was left alone rather than migrated —
recreating the authoritative store is an owner decision, not a mechanical fix.

**Re-checked 2026-08-18** — still failing, identically, for both
`work-item update` and `breadcrumb file`. Reads still work. So this file is
still the only tracker, and it has grown a second job: recording work that is
*finished* but cannot be marked finished anywhere else.

**Re-checked 2026-08-24** — still blocked, but the *error has changed*, so this
is no longer the same failure:

```
[MIGRATION_REQUIRED] Migrations pending: schema 'acme_adcs_ra' has applied
[1..44], missing [45, 46, 47, 48, 49, 50]. Run regista migrations before starting.
```

Reads still work — `agent-notes work-item find --project acme-adcs-ra` returns
all 24 items. The v6-genesis message is gone; what remains is six unapplied
migrations. That is a *mechanically* fixable state, unlike the genesis reset,
but the store is shared estate-wide and migrating it is an owner decision with
blast radius past this repo, so it was left alone again. Note the project
schema is `acme_adcs_ra` (underscores) — `--project acme-adcs-ra` is rejected
by the name validator, which is worth knowing before concluding the store is
down.

**Reconcile this file into regista once writes are restored, then delete it.**

---

## Status at a glance (2026-08-18)

| # | What | State |
|---|---|---|
| 1 | Syslog sends counted as delivered | closed 2026-08-17, filed here for the record |
| 2 | WI-014 second vector (`keyChange`) | **needs filing** — shipped as 14a, the tracker does not know |
| 3 | Privileged script tree unauthenticated | **CLOSED 2026-08-18** (code + tests + docs) |
| — | WI-015 `-SitePath` ancestor chain | **CLOSED 2026-08-18** — fell out of item 3's helper; **mark done in the store** |
| 4 | `ipSecurity` posture undocumented | **CLOSED 2026-08-18** (`SECURITY.md` → Recorded decisions) |
| 5 | WI-053 is stale | **needs closing in the store** — re-verified in code 2026-08-18 |
| 6 | WI-014 split | **needs filing** — 14a shipped, 14b built and unwired |
| 7 | Audit retention never runs | **open** — prerequisite (item 8) now cleared; three safety gaps remain |
| 8 | UDP probe satisfied `audit_offbox_required` | **CLOSED 2026-08-18** |
| 9 | TCP syslog connect unbounded | **CLOSED 2026-08-18** (acme-adcs-ra); cert-watch half open, see below |
| 10 | Sibling dot-source precedes the provenance gate | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 11 | No ancestor check on the state/runtime roots | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 12 | HEC token forwarded across redirects | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |
| 13 | `$env:windir` selects elevated executables | **CLOSED 2026-08-24** (code + tests + docs); needs filing in the store |

Everything marked CLOSED is in the working tree on
`security-review-2026-08-15-daybreak`, with tests, and needs no tracker entry
beyond a note that it happened. Everything marked **needs filing** is a
tracker-only action with no code left to write.

---

## Items to file

### 1. (bug, high) — CLOSED IN THE SAME PASS, file for the record

**Syslog send failures were counted as successful off-box audit delivery, and
the `audit_offbox_required` startup probe passed with the collector dead.**

Daybreak standard review 2026-08-17 (commit `7325cdb`) Finding 4 — confirmed by
execution. Fixed on branch `security-review-2026-08-15-daybreak`; full write-up
in `docs/security-review-2026-08-17-daybreak-standard.md`. Filed here only so
the store has the history when it comes back.

### 2. (risk) — APPEND TO EXISTING **WI-014**, do not open a new item

WI-014 currently reads as "unauthenticated `newAccount` denials grow the
mandatory audit database without bound". Daybreak Finding 1 is a **second vector
on the same root cause**: `routes/key_change.py` has no rate, quota or
cardinality check, and every successful rotation inserts a non-coalesced
`audit_log` row, so a valid or stolen account key can chain rotations
indefinitely.

Append to WI-014 rather than filing separately — one retention-plus-quota design
closes both, and splitting them invites two half-fixes.

### 3. (task) — APPEND TO EXISTING **WI-015** / **WI-053**

Daybreak Finding 3 (privileged maintenance automation executes an
unauthenticated script tree) is valid and better founded than the report knows:

- the installer does not install `scripts/` at all — `docs/operations.md:857`
  tells operators to hand-copy it to an unspecified location;
- round 7 measured `BUILTIN\Users:(Write)` on `C:\ProgramData`, which is exactly
  why the *code* root lives under `%ProgramFiles%` — the scripts tree has no
  equivalent requirement;
- the lab itself stages CA-officer scripts in `C:\Temp\ra-scripts`.

`Test-ObjectDaclTrusted` already exists; it is simply not applied to the
privileged script path.

**Measured live 2026-08-17.** `C:\Temp\ra-scripts` — the path the registered
revocation-sync task actually executes as the gMSA — carries
`BUILTIN\Users:(I)(CI)(AD)` and `BUILTIN\Users:(I)(CI)(WD)`, inherited from
`C:\Temp`. So an unprivileged local user can create files in the directory tree
a scheduled task runs privileged code from. That is no longer a design concern
awaiting evidence; it is a measurement. The same session watched
`Test-ObjectDaclTrusted` refuse `C:\Temp` as an *installer source* for exactly
this reason — the control exists and is simply not pointed at this path.

> **CLOSED 2026-08-18.** `Get-TreeTrustViolations` (in `InstallVerifyLib.ps1`,
> beside `Test-PathChainTrusted`) applies the installer's provenance rule to a
> whole tree — ancestor chain *and* every object beneath it, because the action
> dot-sources `lib\` siblings at run time. Either half alone passes a tree the
> other rejects; both halves are mutation-proven in
> `tests/pester/InstallVerify.Tests.ps1` (5 new tests, suite 368 green).
> `Register-MaintenanceTasks.ps1` refuses to register the revocation-sync task
> from a failing tree, with `-AllowUntrustedScriptPath` as the explicit lab
> override (same shape as `-AllowInsecureUrl`). `docs/operations.md` now says
> where to put the tree and why, in the same note that already told operators to
> copy it.
>
> **Residual, deliberately not done:** `Sync-Revocations.ps1` does not re-check
> the tree at *run* time. Doing so would load `InstallVerifyLib.ps1` — two
> `Add-Type` C# compiles — on a 15-minute cadence, and with registration now
> refusing untrusted trees the remaining exposure is a DACL loosened *after*
> registration, which needs administrator rights. Worth revisiting if the lib is
> ever split so the DACL primitives can be loaded on their own.
>
> **REVISITED AND TAKEN, 2026-08-24 — see item 10.** The stated condition was
> met: both `Add-Type` compiles are now on demand, so the library dot-sources in
> 321 ms rather than 1298 ms and neither compile is on the trust path. The
> second premise — "registration now refuses untrusted trees" — turned out to
> hold only on the `$registerSync` path and only *after* two siblings had
> already loaded, and never covered `-AllowUntrustedScriptPath` at all.
> `Sync-Revocations.ps1` now re-checks on every run.
>
> **WI-015 is a different path, and it is now closed too.** That item is the
> `-SitePath` ancestor-chain refusal for the *IIS site* tree — round 2 withheld
> it pending a live DACL baseline, and the baseline was surveyed on 2026-08-17
> (`C:\inetpub` chain clean; `C:\ProgramData\acme-adcs-ra` still reports two
> violations, so the check discriminates). Writing `Get-TreeTrustViolations` for
> the script tree produced exactly the chain-plus-contents shape WI-015 needed,
> so the installer's site-tree proof now calls it and the ancestor half ships.
> **Mark WI-015 done when the store accepts writes.**

### 4. (decision) — NEW, low effort

**Record the IIS `ipSecurity` posture explicitly in `SECURITY.md`.**

Daybreak Finding 2 re-reported the commented-out allowlist, which the
2026-08-11 review already adjudicated (token bucket as the compensating control;
allowlist documented as required and operator-owned in
`docs/operator-requirements.md:87`). This is the second independent reviewer to
raise it. A short "accepted, and why" note in `SECURITY.md` ends the cycle — or,
if the posture should actually change, that is a deliberate decision to take
rather than a finding to keep re-triaging.

> **CLOSED 2026-08-18.** `SECURITY.md` gains a **Recorded decisions** section
> carrying the disposition, why the installer does not enforce an allowlist (the
> IPs are per-deployment; `<ipSecurity>` needs a role service a first install may
> not have), where it *is* documented as required, the compensating controls in
> code (nonce token bucket, WI-016 order limits), and what would change the
> trade. The posture did not change — only its visibility. A reviewer who
> disagrees is now arguing with a decision rather than filing a finding.

### 5. **WI-053 IS ALREADY FIXED — close it**

Checked 2026-08-17. The item (filed 08-13) says `-AdminToken` is a mandatory
parameter and `Build-SyncActionCommand` always emits `$env:ACME_ADMIN_TOKEN`
into the revocation-sync action. Neither is true any more:

- **Code** — `-AdminToken` is a `[switch]`, and is required only when
  `$registerGeneral` (`Register-MaintenanceTasks.ps1:204`). `-RevocationSyncOnly`
  skips the general tasks entirely, so `-RevocationSyncOnly -ConfirmToken`
  registers the sync task with no admin authority on the host. The admin env is
  gated behind `-LoadAdminToken` (default `$false`), wired from
  `([bool]$AdminToken)`. `Build-SyncActionCommand` has **no token parameter at
  all** — tokens are loaded from the ACL'd dotenv at run time, so a value cannot
  reach the action even by mistake.
- **Test** — `tests/pester/TaskAction.Tests.ps1`, *"Omits the admin-token load
  entirely in confirm-only mode"*, asserts exactly the WI's ask. Suite 39/39
  green on pwsh 7.
- **Docs** — `docs/operations.md:419-425` and `:956` document
  `-RevocationSyncOnly -ConfirmToken`; `docs/pre-pilot-checklist.md:722`
  *requires* it. So the "documented way to deploy it", which was the item's
  actual complaint, is fixed too.

**Re-verified 2026-08-18** against the working tree: `-AdminToken` is still
`[switch]`, still gated on `$registerGeneral`, and `Build-SyncActionCommand`
still has no token parameter. The item is stale, not wrong-once. Attempting the
close is what proved the store is still refusing writes.

Closed by the 2026-08-15 review (`-AdminToken` made non-mandatory plus the new
`-RevocationSyncOnly` switch — see `docs/security-review-2026-08-15.md:114`) and
hardened by 2026-08-19 F2 in `71e7d8a` (tokens became dotenv loads). The tracker
entry is simply stale. Only residual: it sits in the D1–D7 officer/registration
class that has never been live-proven, so live assurance rides the lab session.

### 6. Split **WI-014** — parts one to three now shipped

> **Update 2026-08-17: 14a is closed; 14b is BUILT BUT NOT WIRED.** Retention
> exists (floor, gates, sweep, footprint, JSONL rotation, timestamp index) and
> 14a, the `keyChange` ceiling, shipped the same day — but **nothing calls the
> sweep** (item 7, found 2026-08-18). An earlier revision of this note said
> "WI-014 IS CLOSED"; that was wrong on the 14b half. Detail in the two bullets
> below.

Parts one and two are **done**: `audit_bounds.py` bounds each row's *size*
(attacker-chosen `kid` truncated with a SHA-256 of the whole), and
`audit_coalesce.py` bounds row *count* for five replayable denial classes within
a window, without deleting anything. What is left is two very different jobs
that should not share one item:

- **14a — BUILT 2026-08-17.** Bounds *repeatable successful* transitions:
  Daybreak F1's `keyChange` had no rate, quota or cardinality check, and the
  coalescer deliberately excludes successes. Shipped as
  `rate_limit_key_changes_per_window` (default 5, `0` disables), keyed per
  **EAB kid** so a leaked EAB cannot spread rotations across fresh accounts,
  and enforced **atomically** inside `update_account_key_with_audit` rather
  than count-then-check — the round-6 lifetime per-EAB account quota was the
  precedent followed. The denial (`key-change-rate-limited`) is coalesced so
  the ceiling does not simply move the growth to the refusal row; the success
  row stays uncoalesced because it is the counter. Seven tests in
  `tests/test_key_change_rate_limit.py`, each mutation-proven. See the
  CHANGELOG and `docs/operations.md` → *Key-rollover ceiling*.

  Nothing needs filing for this. It was descoped from the retention build
  deliberately, not forgotten: retention bounds the *storage* consequence, but
  an unbounded authenticated action is a rate-limiting defect in its own right
  and wanted its own change.
- **14b — BUILT 2026-08-17, NOT REACHABLE IN PRODUCTION.** The code, the floor,
  the gates and the self-audit are all real; `run_sweep` simply has no caller
  outside the tests, so a deployment that configures retention prunes nothing
  (**item 7**). Three deferred safety gaps must close before it is wired, and
  **item 8 is a hard prerequisite** — see the sequencing note. Everything below
  describes what was built, not what runs: the floor is `observed certificate validity + 14 days`
  (enforced, startup refused below it), and deletion is gated on
  `audit_offbox_required` *and* a live delivery probe, so the dangerous
  capability only exists where the local table is a buffer rather than the
  system of record. Local-only stays supported and never prunes. The sweep
  audits itself. See the CHANGELOG and `docs/operations.md`.

### 7. (bug, medium) — NEW. **Audit retention never runs.**

`run_sweep` (`audit_retention.py:190`) has **no caller outside the test suite**.
Verified 2026-08-18: no admin route, no entry in
`Register-MaintenanceTasks.ps1` (which registers nonce-cleanup and
expired-order-sweep, but nothing for retention), no lifecycle hook.

So an operator who follows `docs/operations.md` → *Built-in retention*, sets
`audit_retention_days` at or above the floor and turns on
`audit_prune_enabled`, gets a feature that is configured, validated at startup,
documented — and never executes. Nothing unsafe happens; the harm is the belief
that audit growth is bounded when it is not, which is the belief that stops
someone watching the disk.

Shipped by the 14b retention build (WI-014 part three). Options are a scheduled
task against a new admin route (the shape the other two maintenance jobs
already use), a lifecycle hook, or documenting it explicitly as library-only.

**Do not wire this before item 8 and the three deferred safety gaps below.**
See the sequencing note after item 9.

> **CLOSED 2026-08-23 by refusing the unsupported configuration, not by wiring
> unsafe deletion.** `RAConfig` now rejects `audit_prune_enabled=true`, and the
> composition root repeats the refusal for a mutated or validation-bypassed
> config. This removes the false operational claim while preserving
> `audit_retention_days` floor validation and footprint reporting. The library
> sweep remains unreachable until per-row off-box acknowledgement exists,
> deletion plus self-audit are atomic, and the sweep event is exported off-host.
> Tests mutation-prove both refusal boundaries.

### 8. (bug, medium) — NEW. **A UDP syslog probe satisfies `audit_offbox_required` with nothing listening.**

`SiemExporter`'s startup probe (`siem.py:560-581`) returns `True` for
`syslog_proto=udp` whenever the socket accepts the datagram, which it always
does. Reproduced by the scanner against an unused port: `enabled=True`,
`ok=True`, no collector.

The code is *candid* about it — the returned detail says in as many words that
"reachability is NOT proven" — but the **boolean** is what gates startup, and
the boolean says yes. `audit_offbox_required` exists to refuse to start unless
audit evidence leaves the box; on UDP it refuses nothing.

Mitigating: the shipped `web.config` selects TCP, so no shipped configuration
reaches this. Fix is small — make the UDP probe return `False` for this gate,
and require HEC acknowledgment or an explicitly accepted TCP check.

**This is the prerequisite for item 7.** See the sequencing note below.

> **CLOSED 2026-08-18.** The UDP branch returns `False`, and `RAConfig` refuses
> `audit_offbox_required` with `siem_syslog_proto=udp` outright, so the failure
> is an actionable startup message rather than a probe result nobody sees. No
> escape hatch: requiring off-box audit and demonstrating it over UDP are
> mutually exclusive, which is the whole finding. Covered by
> `tests/test_codex_scan_2026_08_18.py` — including the case that matters most,
> that a real UDP emitter is `enabled` (so it clears the earlier gate) and still
> cannot open `audit_retention.evaluate`'s deletion gate.
>
> Three existing tests encoded the old behaviour and were updated rather than
> deleted; the wave-3 one that asserted "True with an honest caveat" now asserts
> the refusal, since a refactor restoring the caveat would reopen this.
>
> **Item 7's prerequisite is therefore cleared** — but the three deferred safety
> gaps below are not, so item 7 stays shut.

### 9. (bug, low) — NEW. **TCP syslog connect is not bounded by the configured timeout.**

`_apply_send_timeout` (`siem.py:69-92`) runs *after*
`SysLogHandler.createSocket()` has already resolved and connected, so
`siem_syslog_timeout_seconds` bounds **sends only**. DNS resolution and the TCP
connect fall back to the OS default, so a blackholed collector can stall
service construction — or the single reconnect worker — well past the deadline
the operator configured.

The docstring only ever claimed to bound a send, so this is a gap rather than a
broken promise. Fix: create the socket, set the deadline, then connect, and
bound resolution plus establishment with one wall-clock deadline.

**Check cert-watch for the same shape** — it shares this handler's lineage and
is already recorded as having no TCP send timeout at all.

> **CLOSED 2026-08-18 for acme-adcs-ra.** `_RaisingSysLogHandler.createSocket`
> now resolves and connects under one wall-clock deadline covering every address
> the resolver returns, so a multi-homed target cannot multiply the wait.
> `getaddrinfo` takes no timeout and blocks in the OS resolver, so it runs in a
> daemon thread that is abandoned rather than waited on — documented in place,
> because leaking a thread is a real cost and the alternative is worse. Datagram
> and Unix sockets keep the stock path. The regression test measures the defect
> by wall clock: against a resolver stub that never answers, the pre-fix code
> took 30s and then connected happily.
>
> **cert-watch: CONFIRMED, NOT FIXED.** `src/cert_watch/siem.py:89` constructs a
> stock `SysLogHandler` with no timeout of any kind — so it has *both* defects,
> the missing send timeout already on record and this connect one. It also
> inherits the stock `handleError` swallow. cert-watch has no
> `audit_offbox_required` gate riding on that, so the consequence is a stall and
> a silent drop rather than a defeated control. Left alone deliberately: it is a
> different repo, and it had uncommitted work from a concurrent session at the
> time. `acme_adcs_ra/siem.py` is the reference fix, `_getaddrinfo_within`
> included. **A breadcrumb could not be filed — the store refuses those writes
> too — so this paragraph is the only record. It must reach cert-watch.**

### Sequencing note for items 7, 8 and 9

Items 7 and 8 are individually low-severity and were scored separately. They
interlock, and the order matters:

> Deletion is gated on `audit_offbox_required` **and** a live delivery probe at
> sweep time. Item 8 says that probe passes on UDP with no collector. So wiring
> up the sweep (item 7) while item 8 stands would make the UDP hole
> **load-bearing for deleting the only surviving copy** of audit rows.

Fix 8 first, then 7. **8 is now fixed (2026-08-18) and 7 is still shut** — the
three gaps below are what hold it, and they are the substantive half. The same review deferred three more must-fix-before-wiring
gaps on the same theme, all of which are only harmless today *because* nothing
calls `run_sweep`:

- retention can delete rows that were never delivered to SIEM — the
  delivery-watermark semantics need to exist before deletion is reachable;
- the `DELETE` and its `audit-retention-swept` row **commit separately**; they
  should be atomic, the same rule `record_issuance`, `create_account_with_audit`
  and `update_account_key_with_audit` already follow;
- the sweep event is never exported off-box, so a retention pass leaves no
  off-host trace — which is precisely the property that makes a sweep
  indistinguishable from an attacker's cleanup.

**Provenance for items 7–9.** Codex security scan of
`7325cdb`→`47bb9f7` (run `f0da0988`, sealed 2026-08-18T01:00:33Z): 3 findings,
all low severity and high confidence. Each was independently re-verified by
hand before being recorded here. The same run found **no issue** in the 14a
keyChange ceiling ("the prior unlimited-rotation vector is resolved") and **no
regression** in the `Revoke-Cert.ps1` certutil fix, though it had no live
PowerShell 5.1 or ADCS to execute against — that half is covered by the
2026-08-17 lab pass. Report and artifacts kept at
`samples/codex-scans/20260818-SvRVRx/` (gitignored: they name lab hosts).

Items 2 and 3 of that scan's predecessor run remain open and unchanged as
items 4 and 3 above.

---

## Standing validation debt (not work items, but do not lose them)

- ~~**Rverify, the sync/queue drain, and the officer-script class D1–D7 have
  never been executed**~~ — **DONE 2026-08-17** on tip `e7c4254`. All three ran
  live and passed, after the run found and fixed the defect that made the whole
  revocation loop inert (`838eeb2`). See the validation log in
  `docs/pre-pilot-checklist.md`.
- ~~**Phase L** (`Lqueue`/`Ldrain`, the stale-worker enrollment lease)~~ —
  **DONE 2026-08-24** on tip `f6badc9`, 22/22. It had not been skipped: no
  driver invoked it, neither blackhole mechanism could support queue-then-drain
  (the firewall rule does not block on this host and hardcoded a CA address that
  had moved; config mode needs a recycle that kills the queue), and `L5` aborted
  the phase on a client timeout that the bounded enrollment executor makes
  inevitable. All three fixed; `Ldrain` proved the stale worker abandons
  `before-submit` on a lapsed generation with exactly one certificate for the
  contested order.
- ~~**`01417b5`** (98-line Windows PowerShell 5.1 fix to `InstallVerifyLib.ps1`)
  has never been live-installed~~ — **DONE 2026-08-17**: the installer ran from
  `e7c4254` on the lab host and exited 0. Note it also *refused* a `C:\Temp`
  source tree on DACL grounds, which is the hardening working and which every
  earlier runbook deploy step now trips over.
- Branch `security-review-2026-08-15-daybreak` is **26 commits ahead of `main`
  with no PR open** (14a `e7c4254` and the revocation fix `838eeb2` are the two
  newest). `security-review-2026-08-18` and `-08-19` are fully merged and stale.
  This branch now carries a full live E2E pass; opening the PR is an owner
  decision, not a blocked one.

---

## Round 2026-08-24 (daybreak standard review at `0a47955`) — DECLARED BEFORE MUTATION

Four findings, reviewed and re-rated before any code was written. This section
is the pre-action declaration the steward path requires; the store cannot take
it (see the header). Severities below are **this repo's** rating, not the
reporting reviewer's, and two of them differ — the reasoning is recorded so the
disagreement is arguable rather than silent.

**Actor / lineage.** Implementation by Claude Opus 5 (`claude-opus-5`). The
findings came from a daybreak standard review — a different actor and lineage.
Independent review of the *fix* is still owed; see the closing note.

**Declared working set.** Nothing outside these paths:

- `scripts/lib/InstallVerifyLib.ps1`
- `scripts/install-windows.ps1`
- `scripts/Register-MaintenanceTasks.ps1`, `scripts/Sync-Revocations.ps1`,
  `scripts/Revoke-Cert.ps1`, `scripts/Set-OfficerRights.ps1`,
  `scripts/Reconcile-Revocation.ps1`
- ~~`scripts/lib/BootstrapTrustLib.ps1` (new)~~ — **not created.** Lazy type
  compilation achieved the same goal (a library cheap enough to dot-source at
  run time) with a far smaller diff, and a second file invites a second copy of
  a predicate — see `InstallVerifyLib.ps1:1680` for what that cost last time.
  Recorded here because the declared working set is the contract.

**Two paths were touched that the declaration did not list**, both recorded
here for the same reason:

- `scripts/lib/TaskActionLib.ps1` — `Build-SyncActionCommand` had to carry
  `-AllowUntrustedScriptPath` into the registered action. Not foreseeable until
  the run-time gate existed: without it, the documented lab flow registers a
  task that refuses on every run, so this is part of finding 10's fix rather
  than scope creep.
- `.gitignore` — `Invoke-Pester -CI` writes `testResults.xml` into the
  invocation directory, which showed up as untracked noise on every status.
- `src/acme_adcs_ra/siem.py`
- `tests/pester/*.Tests.ps1`, `tests/test_siem*.py`
- `CHANGELOG.md`, `docs/security-review-2026-08-24-daybreak-standard.md`, this file

**Declared acceptance checks.** Each must have a fresh result *after the last
edit*, not before it:

1. `pytest -q`
2. `ruff check . && ruff format --check .`
3. `mypy src/`
4. `pwsh -Command "Invoke-Pester tests/pester -CI"`
5. Mutation proof for every new test: revert the fix, show the test fails,
   restore. A test that cannot fail is not evidence.
6. For finding 12, a **live probe**: a local redirect server proving the
   `Authorization` header no longer reaches the redirect target.

**Known risks going in.**

- Findings 10, 11 and 13 are Windows-side. Linux Pester covers the pure decision
  functions; it **cannot** cover the live ACL and process behaviour (WI-050).
  Live assurance rides the outstanding lab session, same as the D1–D7 class.
- Finding 11 changes a **refusal** on the default install path. A wrong refusal
  aborts the upgrade of a live issuance host — the round-5 lesson. The predicate
  must pass `C:\ProgramData` and `%ProgramFiles%` or it is worse than the bug.
- Finding 13 touches assertions that currently *pin* the `$env:windir` spelling,
  so the tests move with the code. That is the change most likely to look green
  while covering nothing.

### 10. (bug, high) — sibling code is loaded before the provenance gate

**Rated high; the report also said high.** The one I would fix first.

`Register-MaintenanceTasks.ps1:199-200` dot-sources `lib/TaskActionLib.ps1` and
`lib/SyncLib.ps1` immediately after param binding. The script-tree provenance
gate is at `:269`. Two libraries have already executed as Administrator by the
time the gate is consulted.

The gate carries an honest caveat — *"the check is loaded from the very tree it
judges, so someone who can already write here can neuter it"* — and that caveat
is **not** what this is. Neutering the check requires rewriting
`InstallVerifyLib.ps1`; this requires only `SyncLib.ps1`, and the gate never
runs at all. Ordering, not self-reference.

Two further holes the report did not name:

- The gate is inside `if ($registerSync)`. Registering only the nonce/sweep
  tasks skips it entirely, while `:199-200` still load two siblings elevated.
  The justification — *"the nonce/sweep tasks execute nothing from disk"* — is
  true of the **tasks** and false of the **registration script**.
- **The worst instance is in a different file.** `Sync-Revocations.ps1:199`
  dot-sources `SyncLib.ps1` with no gate at all, and *that* is the script the
  scheduled task runs as the gMSA every interval, forever.
  `Revoke-Cert.ps1:130` (CA-officer context), `Set-OfficerRights.ps1:105` and
  `Reconcile-Revocation.ps1:97` are the same shape.

**Correction — the run-time gap was a decision, not an oversight.** Item 3's
closing note (above) records it explicitly: *"Residual, deliberately not done:
`Sync-Revocations.ps1` does not re-check the tree at run time"*, on two grounds
— loading `InstallVerifyLib.ps1` means **two `Add-Type` C# compiles** on a
15-minute cadence (verified: `:444` `ACMERA.AtomicDirectory`, `:1519`
`ACMERA.FinalPath`), and the residual exposure after registration refuses
untrusted trees is a DACL loosened later, which needs admin rights. An earlier
draft of this entry called it an oversight; that was wrong and is withdrawn.

The decision was sound on its own premises. What this round adds is that **one
premise does not hold**, and that the note's own escape hatch is now cheap:

- *The premise.* "Registration now refuses untrusted trees" is true only on the
  `$registerSync` path, and only *after* `:199-200` have already loaded two
  siblings elevated. On the nonce/sweep path the gate never runs. So the
  run-time check was traded away against a registration-time check that has a
  hole in front of it. Fix the ordering and the trade becomes defensible again
  — which is why the ordering fix is the one that matters most.
- *The escape hatch.* The note ends: *"Worth revisiting **if the lib is ever
  split so the DACL primitives can be loaded on their own**."* That is exactly
  what this change does. `Test-ObjectDaclTrusted`, `Test-PathChainTrusted`,
  `Get-TreeTrustViolations` and their dependencies touch neither compiled type
  (only `New-AtomicProtectedDirectory:513` and `Get-CanonicalPathString:1586`
  do), so they move to a new `lib/BootstrapTrustLib.ps1` that dot-sources with
  no `Add-Type` at all. `InstallVerifyLib.ps1` dot-sources it too, so there is
  exactly **one** definition of each predicate.

That last point is the reason for moving rather than copying. `:1680-1682`
records what a second copy cost last time — the installer's inline bootstrap
copy listed only the dead half of a rights mask and *"looked correct while
covering neither right"*. A duplicated predicate is how this file already got
burned once.

- *`-AllowUntrustedScriptPath` outlives its warning.* An operator who takes the
  documented lab override registers a task against a writable tree and gets a
  warning saying "re-register before pilot" — after which nothing ever checks
  again. A run-time gate is what makes that override self-correcting.

So: a legitimate re-find of the remainder of item 3 (one entry point of five,
with the fix placed after the load), plus the split that retires its stated
blocker.

### 11. (bug, medium) — no ancestor check on the state and runtime roots

**Report said high; rated medium here, and the framing is wrong at defaults.**

Confirmed: `Get-RootProvenance` inspects the root and its contents, never above
it, so `Initialize-SecuredRoot` claims `$InstallDir`/`$RuntimeDir` with no
ancestor check. `install-windows.ps1:1393` applies `Get-TreeTrustViolations` to
`$SitePath` with a comment making exactly the reviewer's argument.

But *"protected roots remain replaceable"* does not hold on the defaults.
Substituting an existing child needs `Delete` on the child or
`DeleteSubdirectoriesAndFiles` on the parent. `C:\ProgramData`'s Users ACE is
create-class only (`WD,AD,WEA,WA` — no `DE`, no `DC`) and `%ProgramFiles%` is
Users RX, so the attack does not work there. It works on a **non-default**
`-InstallDir`/`-RuntimeDir` under a parent that grants delete — which is not
hypothetical, because admin-created top-level folders inherit
`Authenticated Users:(OI)(CI)(M)` from `C:\`, and the lab is documented as
staging under `C:\Temp`.

**Why this stalled, and what unblocks it.** `install-windows.ps1:1385-1387`
records that the `$SitePath` refusal shipped once `C:\inetpub` was *measured
clean* — "the evidence this was waiting on". That evidence can never arrive for
`C:\ProgramData`, because `InstallVerifyLib.ps1:1790` records that it **FAILS**
`Test-PathChainTrusted`.

It fails on `WriteData`. On a directory that bit means *create a new entry*, not
*modify an existing child* — a false positive for this question.
`Test-AceEndangersBytes` is correctly named and is the right predicate for a
file about to be executed; it is the wrong predicate for an ancestor of a
protected root, where the dangerous bits are `Delete`,
`DeleteSubdirectoriesAndFiles`, `ChangePermissions`, `TakeOwnership`,
`GenericAll` and `GenericWrite` — and **not** bare `WriteData`/`AppendData`.

So the fix is a sibling predicate with the narrower mask, which passes
`C:\ProgramData` and still fails `C:\Temp`. Default-safe by construction, which
is the property the round-5 lesson demands.

### 12. (bug, low→medium) — the HEC token is forwarded across redirects

**Report said low; kept at low-to-medium.** Confirmed **by execution**, not by
reading: a local redirect server received `Authorization: Splunk <token>`
verbatim after a 302.

`urlopen` (`siem.py:757`) uses the default `HTTPRedirectHandler`, whose
`redirect_request` strips exactly `("content-length", "content-type")` and
copies every other header onto the new request — `Authorization` included,
cross-host. `http_error_302` permits redirect targets with scheme `http`,
`https` **or** `ftp`, so the https-only gate at `siem.py:335-340` is defeated
one hop deep and the token can leave in cleartext.

Two precisions the report did not have:

- **Only the token leaks, not the audit events.** `redirect_request` builds the
  new request without `data=`, and 301/302/303 downgrade POST to GET. Measured:
  method `GET`, empty body. Even 307/308 drop the body, and POST+307 raises
  rather than following. This is credential disclosure, not audit disclosure.
- Adjacent dead code: `if not (200 <= resp.status < 300)` at `:758` cannot fire.
  Non-2xx raises `HTTPError` and 3xx is followed automatically — which is
  precisely why a redirect leaves no trace in the logs.

Nudged above the reported severity for one reason: an HEC token lets an attacker
**forge audit into the SIEM**, and for this product the audit trail is the
thing being sold.

### 13. (bug, medium) — `$env:windir` selects executables that run elevated

**Report said high; rated medium here.** Real, and inconsistent with this
repo's own stated doctrine — but the precondition is controlling the
environment block of a process about to elevate, which generally means already
holding the launching context.

`InstallVerifyLib.ps1:17` derives `icacls.exe` from `$env:windir`, while
`Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and `Reconcile-Revocation.ps1`
resolve System32 from the runtime, and `Get-TrustedInboxModuleRoots:2336` goes
further still (machine-scope registry plus the folder API) with a comment
spelling out why the process environment cannot be trusted. Line 17 is simply
on the old pattern.

The report named the weaker half. Two additions:

- **The bare-name fallback is the sharper bug.** `else { 'icacls.exe' }` is PATH
  resolution — exactly what round-6 finding 3 removed elsewhere. Test `:1607`
  asserts the *installer* never invokes icacls by bare name; the *library* still
  can, whenever `windir` is **unset** rather than redirected. Unsetting is a
  lower bar than redirecting.
- **Double impact.** icacls output is not merely executed, it is the evidence
  `Get-RootProvenance` and `Assert-InstallTreeLocked` read. A substituted icacls
  forges the lockdown proof as well as running code.

**Decision: fix it completely rather than at line 17.** `install-windows.ps1`
has eight more `$env:windir` sites (msiexec, secedit, cmd, netsh, attrib,
appcmd, the handler DLL probe), and tests at `:1379` and `:1605-1607` *pin* that
spelling. Half-fixing the library while leaving the installer on the old pattern
is how this class keeps returning: the doctrine ends up split across two files
and the next reviewer finds whichever half they open first.

### 8. (observation, medium) — The lab CA's C:\ carries an APPLICABLE Authenticated Users Modify ACE

*Found live 2026-08-24 during the daybreak-branch validation (F10 gates).*
`CA01`'s `C:\` DACL includes `NT AUTHORITY\Authenticated Users:(M)` with
no inheritance flags (applicable to the root itself), alongside the normal
`(OI)(CI)(IO)(M)` twin. Every tree on that host has `C:\` in its ancestor
chain, so **no path on the CA passes the privileged-script tree gate** — the
officer scripts (`Set-OfficerRights.ps1`, `Revoke-Cert.ps1`,
`Reconcile-Revocation.ps1`) need `-AllowUntrustedScriptPath` on that host,
which is correct-but-loud (the refusal message says exactly what to do). The
RA host's `C:\` carries only Users create-class and needs no override.

Operator decision: either fix the CA's `C:\` DACL to the inherit-only default
shape (remove the applicable ACE), or accept that every CA-side privileged
script run carries the override. Not a product defect — the gate measured a
real escalation surface — but it should be a conscious choice, and the next
CA-host deploy should state it in `docs/operator-requirements.md`.

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

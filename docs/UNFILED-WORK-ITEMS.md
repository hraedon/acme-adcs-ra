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

**Reconcile this file into regista once writes are restored, then delete it.**

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

### 4. (decision) — NEW, low effort

**Record the IIS `ipSecurity` posture explicitly in `SECURITY.md`.**

Daybreak Finding 2 re-reported the commented-out allowlist, which the
2026-08-11 review already adjudicated (token bucket as the compensating control;
allowlist documented as required and operator-owned in
`docs/operator-requirements.md:87`). This is the second independent reviewer to
raise it. A short "accepted, and why" note in `SECURITY.md` ends the cycle — or,
if the posture should actually change, that is a deliberate decision to take
rather than a finding to keep re-triaging.

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

Closed by the 2026-08-15 review (`-AdminToken` made non-mandatory plus the new
`-RevocationSyncOnly` switch — see `docs/security-review-2026-08-15.md:114`) and
hardened by 2026-08-19 F2 in `71e7d8a` (tokens became dotenv loads). The tracker
entry is simply stale. Only residual: it sits in the D1–D7 officer/registration
class that has never been live-proven, so live assurance rides the lab session.

### 6. Split **WI-014** — parts one to three now shipped

> **Update 2026-08-17: WI-014 IS CLOSED.** Retention is built (floor, gates,
> sweep, footprint, JSONL rotation, timestamp index) and 14a, the `keyChange`
> ceiling, shipped the same day. Detail in the two bullets below.

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
- **14b — BUILT 2026-08-17.** Retention shipped, and the owner decision it was
  waiting on got made: the floor is `observed certificate validity + 14 days`
  (enforced, startup refused below it), and deletion is gated on
  `audit_offbox_required` *and* a live delivery probe, so the dangerous
  capability only exists where the local table is a buffer rather than the
  system of record. Local-only stays supported and never prunes. The sweep
  audits itself. See the CHANGELOG and `docs/operations.md`.

---

## Standing validation debt (not work items, but do not lose them)

- ~~**Rverify, the sync/queue drain, and the officer-script class D1–D7 have
  never been executed**~~ — **DONE 2026-08-17** on tip `e7c4254`. All three ran
  live and passed, after the run found and fixed the defect that made the whole
  revocation loop inert (`838eeb2`). See the validation log in
  `docs/pre-pilot-checklist.md`. What remains unproven is **phase L**
  (`Lqueue`/`Ldrain`, the stale-worker enrollment lease) — not attempted this
  session, now outstanding after three.
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

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
privileged script path. Wants the same live Windows session as the outstanding
revocation proof.

### 4. (decision) — NEW, low effort

**Record the IIS `ipSecurity` posture explicitly in `SECURITY.md`.**

Daybreak Finding 2 re-reported the commented-out allowlist, which the
2026-08-11 review already adjudicated (token bucket as the compensating control;
allowlist documented as required and operator-owned in
`docs/operator-requirements.md:87`). This is the second independent reviewer to
raise it. A short "accepted, and why" note in `SECURITY.md` ends the cycle — or,
if the posture should actually change, that is a deliberate decision to take
rather than a finding to keep re-triaging.

---

## Standing validation debt (not work items, but do not lose them)

- **Rverify, the sync/queue drain, and the officer-script class D1–D7 have never
  been executed** at any tip on this branch. Round 7 was blocked by what it
  diagnosed as a CA DCOM fault; that diagnosis was **retracted 2026-08-17** — it
  was the SSH logon session holding no Kerberos TGT (runbook §1). The work is
  unblocked and needs a lab session.
- **`01417b5`** (98-line Windows PowerShell 5.1 fix to `InstallVerifyLib.ps1`)
  landed after the round-7 live proof and has never been live-installed. CI's
  5.1 Pester job is green on it, but the round-6 and round-7 live runs each
  found installer defects that green Pester missed.
- Branch `security-review-2026-08-15-daybreak` is **24 commits ahead of `main`
  with no PR open**. `security-review-2026-08-18` and `-08-19` are fully merged
  and stale.

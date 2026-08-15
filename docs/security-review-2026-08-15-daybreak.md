# Security review — Daybreak 2026-08-15 (post-validation)

Scope: Daybreak's independent review of `f495092` — the tip the 2026-08-15
full E2E lab validation ran on, plus the two documentation commits after it.
Five findings: one high, four low (one of the lows the long-known WI-014).
The reviewer's verdict: "substantially stronger, but I still would not
recommend production deployment until the installer issue is fully closed."
No EAB/SAN-policy bypass, cross-account access, signing-key introduction,
certificate-binding failure, or reachable double-issuance path was found, and
the reviewer confirmed the E2E evidence itself is sound.

**Four of five are fixed; one is deliberately deferred** (WI-014, unbounded
audit growth — deferred again, for the same reason every round has deferred
it: it is a retention-policy decision on a security log, not a defect fix,
and silently truncating an audit trail is worse than the growth). Suite:
768 → **773 pytest + 1 skipped**, Pester 148 → **170**, ruff and mypy clean.

## Finding 1 (high) — the installer's ACL claim was bypassable: `/inheritance:r` removes only inherited ACEs

`scripts/install-windows.ps1:244` claimed the predictable `ProgramData`
install root with `icacls $InstallDir /inheritance:r /grant:r …`, then set
`installRootSecured = $true` and executed `$InstallDir\python\python.exe`
elevated. Microsoft documents (and the reviewer confirmed) that
`/inheritance:r` removes only *inherited* ACEs, so two attacker holds
survived the claim on a pre-created tree:

- **every explicit ACE the attacker set** — `Everyone:(OI)(CI)F` on a tree
  the local attacker pre-created keeps the planted interpreter/venv writable
  after the "securing" pass, and the elevated installer then runs it;
- **ownership** — an owner holds implicit WRITE_DAC, so an attacker-owned
  object can have its DACL rewritten back at any time, whatever we set it to.

`/grant:r` was no help: it replaces only ACEs for the trustees it names.

**Fixed** with a reset-then-prove sequence (all in
`scripts/lib/InstallVerifyLib.ps1`, called from both of the installer's ACL
passes):

1. `Reset-TreeToInherited` — `takeown /f <root> /r /a /d y` gives the
   **Administrators group** ownership of every object (takeown is the only
   primitive that works on a hostile tree: the attacker's DACL can deny us
   WRITE_DAC, but the elevated token holds SeTakeOwnership/SeRestore, which
   takeown enables itself); then `icacls <root> /reset /t` discards **every
   explicit ACE in the tree** and clears DACL protection, leaving every
   object a pure inheritor.
2. `Set-ObjectProtectedDacl` — `/reset` on the single object (same trap in
   miniature: the dotenv survives reinstalls and could carry a stale attacker
   ACE), then `/inheritance:r /grant:r` with exactly the intended grants.
3. `Assert-InstallTreeLocked` — reads the tree back (`icacls /save`) and
   **proves** it: root owner must be Administrators or SYSTEM; the root's
   DACL protected with exactly our trustees; no descendant protected (each
   inherits the root); no deny ACE, no empty DACL, no ACE — inherited or
   explicit — naming a trustee outside the allowed set. Any violation aborts
   the install listing up to ten offenders. "We ran icacls" is not evidence;
   the read-back is.

The decision core (`Test-AclDumpLocked`) is a pure function over the dump
text, unit-tested on Linux against fixture dumps shaped like the finding
itself. The redundant per-subdir grant on `python\` is gone by design — the
root's `(OI)(CI)M` propagates, and an explicit ACE down there would (correctly)
trip the verification.

Windows PowerShell 5.1 notes: `takeown /d y` is the English-locale letter
(on localized Windows the accepted letter can differ); the exit-code check
turns that into a loud abort rather than a silently partial reset. **This
change wants a live install run before the next release** — CI executes
neither takeown nor the read-back proof, and the 2026-08-14 round proved that
gap lets broken installers sit green on `main`. It is on the next re-proof's
list, ahead of the usual ordering.

## Finding 2 (low) — registration accepted the full token values on its one-time command line

Since 2026-08-19 F2 the scheduled tasks load their credentials from the
ACL'd dotenv at run time, so `Register-MaintenanceTasks.ps1` needed the token
*values* only as a boolean signal — but they were still `[string]`
parameters, so the one-time registration carried them through shell history
and the invoking process's argument list: the last place a secret still
traveled.

**Fixed** by converting `-AdminToken` and `-ConfirmToken` to **switches**.
They now declare *which key* the task loads from the dotenv; the script cannot
accept a secret value at all, and a pre-change invocation fails loudly at
parameter binding instead of silently continuing. Rotation guidance changed
with it: editing the dotenv is now the whole procedure — there is nothing to
re-register. `docs/operations.md` examples rewritten (including the stale
manual `New-ScheduledTaskAction` example that still embedded raw tokens);
AST-level Pester tests pin that the parameters stay switches and no
value-shaped example comes back.

## Finding 3 (low) — newAccount committed before its provenance audit

`routes/accounts.py:175` committed the account and only then wrote the
`account-created` row — the row that ties an account to the EAB kid that
minted it. A failure in the window left a live account with no provenance.

**Fixed** with `Store.create_account_with_audit`: account row + audit row in
one transaction, the same fix shape v1.9 applied to issuance
(`record_issuance`); the route fans the returned event out to SIEM after the
commit. The concurrent-duplicate path (RFC 8555 §7.3 idempotent retry) is
unchanged — the audit row rolls back with the account, because nothing was
created.

## Finding 4 (low) — keyChange committed before its audit

`routes/key_change.py:139` committed the rotation and wrote
`account-key-changed` afterwards. That row is the only record naming the
*new* key's thumbprint, so the window could leave a silently rotated key with
no trace of the rotation.

**Fixed** the same way: `Store.update_account_key_with_audit`, one
transaction, route emits the returned event.

**Fault-injection proof for both:** `tests/test_security_review_2026_08_15_daybreak.py`
installs a SQLite trigger that aborts every `audit_log` INSERT and asserts
the *state change rolls back with the audit row* — no account, no rotation,
old key still current. Mutation-verified in the repo's own discipline: with
the routes reverted to the two-commit ordering, both tests fail.

## Finding 5 (low, known) — unbounded audit growth from failed EAB requests: WI-014, still deferred

`routes/accounts.py:141` — every denied newAccount writes an audit row, and
nothing bounds the store/JSONL against unauthenticated request floods. This
is WI-014 and remains deliberately deferred: the fix is a retention policy on
a security log (what may age out, who proves SIEM receipt before local
deletion), not a code patch, and the wrong "fix" — silent truncation — would
be a bigger finding than the growth. The bounded-HEC-queue work (v1.9)
already caps the *SIEM* leg; the local-store growth is the open part.

## Not acted on here

- **The release-state mismatch** (source says 1.9.1, no immutable
  v1.9.1 tag exists on the releases page): correct and deliberate for now —
  the standing rule is that a tag is gated on a live re-proof of the exact
  commit, and this branch's installer change adds to that requirement. Tag
  after the next re-proof, not before.
- **The lab harness** (`samples/lab-harness/register2.ps1`, gitignored) still
  uses the pre-switch `-ConfirmToken <value>` form; it fails loudly if run
  as-is and must be updated at the next re-proof.

## Verification

- 773 passed, 1 skipped (pytest); 185 passed (Pester, incl. the new ACL-dump
  and credential-surface suites); ruff and mypy clean.
- Both new pytest atomicity tests mutation-verified against the vulnerable
  two-commit ordering (they fail against it).
- The installer change is exercised by text-level Pester on Linux; the real
  takeown/icacls/read-back sequence needs Windows and **is owed a live run**
  before the next release — same gap class as the 2026-08-14 installer
  defects, recorded on the next re-proof's list.

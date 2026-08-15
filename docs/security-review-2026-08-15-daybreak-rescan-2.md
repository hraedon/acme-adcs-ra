# Security review — Daybreak 2026-08-15 rescan (iteration 3)

Scope: Daybreak's re-review of `63529a6` — the second Daybreak-fix iteration.
Verdict: "Do not deploy this iteration yet." Four findings: one high, two
medium, one low (WI-014, now on its fourth consecutive review). The
persistent-venv fix and the non-racing junction case were confirmed fixed, and
the exact-tip CI run passed all eight jobs.

**All four are fixed here**, including WI-014 — which is not a reversal of the
three previous deferrals so much as a way round the thing they were refusing to
do. See Finding 4.

Suite: pytest 773 → **795 + 1 skipped**, Pester 184 → **218**, ruff and mypy
clean. Every new test is mutation-checked; the mutations are named below and in
each test's docstring.

**One thing this iteration does NOT have, and it matters:** a live Windows run.
Three of the four findings are in `install-windows.ps1`, and two of the fixes
change how the installer behaves against a *hostile* tree in ways CI cannot
exercise. See "What is still owed" at the bottom before tagging anything.

---

## Finding 1 (high) — a preplanted manifest authenticated a preplanted interpreter

The previous iteration made the elevated installer refuse to execute a
destination-local `python\python.exe` unless the whole tree's SHA-256s matched
`python.manifest.json`. Both files live in `$InstallDir`. On a **first**
install that directory is one a local low-privilege user can create in advance,
because `C:\ProgramData\acme-adcs-ra` is a predictable path.

So the attacker writes both. The manifest lists the hashes of the interpreter
sitting next to it, the pair is perfectly self-consistent, the ACL claim
preserves both, `Test-TreeManifestMatches` returns `Ok`, the planted binary
becomes the *preferred* launcher, and it runs as Administrator on an issuance
host. No race required.

The root cause is not the hash comparison — it is what the comparison proves.
It proves **consistency**. Provenance needs an anchor the attacker cannot
write.

**Fixed** with an out-of-tree anchor in the registry:

- `Set-TreeManifestAnchor` records the SHA-256 of `python.manifest.json`
  itself under `HKLM\SOFTWARE\acme-adcs-ra`, keyed by normalized install root,
  immediately after the manifest is written. `HKLM\SOFTWARE` is
  Administrators/SYSTEM-write by default — the local user who can pre-create
  `ProgramData\acme-adcs-ra` cannot pre-create this. The key is created with an
  explicit protected DACL rather than inheriting whatever `HKLM\SOFTWARE`
  happens to carry.
- `Get-TreeManifestAnchor` reads it back and **throws** if the key is not owned
  by Administrators/SYSTEM. An anchor an attacker could rewrite is worse than
  no anchor, because it looks like proof.
- `Test-TreeManifestAuthentic` is now the only gate the installer uses: the
  manifest file must match the anchor, *and* the tree must match the manifest.
  `Test-TreeManifestMatches` still exists as its second half and is still
  tested, but no call site in `install-windows.ps1` reaches it directly any
  more — a Pester test asserts that count is zero.
- **No anchor means no trust.** An unanchored `python\` tree is deleted (with
  its stale manifest) and rebuilt from an authenticated source. That is also
  what an upgrade from a pre-anchor install does, exactly once, at the cost of
  re-copying Python.

Mutation check: make `Test-TreeManifestAuthentic` ignore `-AnchorDigest` and
two tests fail, including the one named `THE FINDING: a preplanted interpreter
with its OWN matching manifest is refused`.

## Finding 2 (medium) — a raced junction still redirected privileged ownership changes

`Assert-NoReparsePoints` killed the *static* planted-link case, and `icacls`
was given `/L` everywhere it recursed. But the ownership step was
`takeown /f <root> /r`, and **takeown has no no-follow option**. A junction
inserted between the pre-walk and takeown redirected an elevated recursive
ownership rewrite outside the install tree — real damage to an external target,
which the post-walk could only detect, never undo. The single-object
`Set-ObjectProtectedDacl` calls (the install root, the dotenv, the manifest)
also omitted `/L`, so a raced *file* symlink could redirect those too.

**Fixed** by removing the last link-following privileged operation:

- `takeown` is gone. Ownership is claimed with
  `icacls <root> /setowner *S-1-5-32-544 /t /q /L`, which does take `/L`. A
  Pester test asserts `takeown.exe` appears in neither script, and that every
  `& icacls.exe` call in the library carries `/L`.
- `Set-ObjectProtectedDacl` carries `/L` on both of its calls; so does the
  site-path grant in the IIS section.
- `/c` is gone from every icacls call. It skips objects it cannot process,
  which is precisely the failure that must abort rather than continue. Results
  now go through `Test-IcaclsOutputClean`, which checks the exit code *and*
  the "Failed processing N files" summary.
- Ownership is claimed **before** the DACL reset, so the reset cannot be denied.

**A deliberate behaviour change, and the point of the fix.** Unlike takeown,
`icacls /setowner` does not force ownership — Microsoft's documentation says so
explicitly. It succeeds wherever the installer already holds `WRITE_OWNER` (a
directory it just created, a tree a previous install locked down, a file the
gMSA created inside it) and **fails on a tree a local attacker pre-created and
locked against us**. That case now aborts with an instruction to inspect and
remove the directory, instead of forcibly adopting a hostile namespace.
Refusing to install there is the correct outcome; silently claiming it is how
findings 2 and 3 existed.

Mutation check: restore takeown and drop `/L` from the reset — four tests fail.

## Finding 3 (medium) — the live-tree claim left attacker-owned descendants and retained handles

Two instances, one shape: multiple pathname-based passes over a namespace
someone else can still touch.

**Retained gMSA handles.** Windows evaluates access when a handle is *opened*,
not when it is used. A compromised app-pool worker holding a write handle
opened under the steady-state Modify ACL keeps that access straight through the
ownership/ACL reset — and could therefore rewrite interpreter bytes between the
hash check and the elevated execution of those bytes. The app pool was stopped
roughly 220 lines *after* the claim, and after the interpreter had already been
verified and run.

**Fixed:** the pool is stopped first, and proven dead. `Stop-AppPoolAndWait`
polls `appcmd list wp` until no worker for that pool remains, and throws on
timeout — "the pool says Stopped" is not evidence, because the worker lingers
while it drains. `Test-AppPoolWorkersGone` fails closed on output it cannot
parse. A Pester test pins the ordering: stop before claim, stop before hash.

**Attacker-owned descendants.** The read-back proof checked only the *root's*
owner. A descendant created between the ownership pass and the DACL pass stays
owned by whoever made it, and an owner holds implicit `WRITE_DAC` — so it can
rewrite its own DACL back at any time, while looking perfectly clean to a DACL
check because its inherited ACL is ours.

**Fixed:** `Assert-InstallTreeLocked` now calls `Get-TreeOwnerViolations`,
which walks every object (non-following; a reparse point throws) and checks
each owner against Administrators/SYSTEM. `Test-OwnerAllowed` fails closed on
an owner it cannot resolve. This is also what catches a child created between
the two passes.

Mutation check: move the pool stop back below the claim — the ordering test
fails.

## Finding 4 (low) — unbounded durable audit growth: WI-014, fixed rather than deferred a fourth time

An allowlisted peer needs no account and no valid EAB secret to make the RA
write durable evidence: generate an account key, fetch a nonce, send a
`newAccount` whose EAB will not verify, and one SQLite row plus one appended
JSONL record land on the issuance host's disk. Per request. With an
attacker-chosen `kid` inside.

Three waves deferred this, and **their reasoning was right**: the remediation
people reach for is a pruner, deleting audit evidence is the operation an
attacker most wants, and trading a disk-space problem for a missing-evidence
problem is not a fix. Retention stays operator-owned.

What changed is noticing that "bound the growth" and "prune the evidence" are
not the same requirement.

- **Nothing is deleted.** There is no pruner, and a test asserts `DELETE FROM
  audit_log` appears nowhere in `store.py` — so adding one becomes a review
  conversation rather than a quiet commit.
- **No attempt goes uncounted.** Within
  `audit_denial_coalesce_window_seconds` (default 60, `0` restores the old
  one-row-per-denial behaviour), repeats of the same denial *reason* update the
  row that is already committed: `denial_count`, `last_seen`, and a bounded set
  of digests of the distinct `kid`s offered. Because the counter is written to
  a durable row on every increment — not buffered until the window closes —
  even a hard crash keeps the tally.
- **The key excludes attacker-chosen data.** Coalescing on `(event_type,
  reason)` and not on `kid` or requester; keying on either would let a peer
  defeat the bound by varying one character per request. A test drives 300
  distinct kids and asserts one row.
- **Only the unauthenticated path is coalesced.** `COALESCED_EVENT_TYPES` is
  `{"account-creation-denied"}`. Issuance, revocation, admin action and
  anything an authenticated account did keep one row per event,
  unconditionally.
- **Field sizes are bounded at the durable sink**, not at each call site:
  values over 256 characters are truncated with a SHA-256 of the whole value
  appended (two rows for the same oversized kid still compare equal), and the
  `details` blob is capped at ~4 KB with the dropped keys named. `reason`
  survives the cap by construction.

Durable growth is now a function of elapsed time — at most one row per reason
per window — rather than of the attacker's request rate. 10,000 attempts across
ten windows cost ten rows and still report 10,000, which is the test.

The SIEM sink sees one event per window; the next window's event carries the
closed one's final tally in `previous_window`. SQLite is authoritative for an
in-progress count.

Mutations checked: default the window to 0 (two end-to-end tests fail); drop
the bounding call in `_record_audit_in_conn` (the field test fails).

---

## Verification

- `tests/test_security_review_2026_08_15_daybreak_rescan2.py` — 22 tests over
  Finding 4, each naming the mutation that breaks it.
- `tests/pester/InstallVerify.Tests.ps1` — 34 new tests over Findings 1–3:
  unit coverage for `Test-IcaclsOutputClean`, `Test-AppPoolWorkersGone`,
  `Test-OwnerAllowed`, `Get-TreePaths`, `Get-ManifestAnchorValueName` and
  `Test-TreeManifestAuthentic`, plus source-level assertions pinning the
  properties that only exist as *ordering* (anchor read before trust, pool stop
  before claim, ownership before reset, `/L` on every icacls call, no takeown).
- Suite: 795 pytest + 1 skip, 218 Pester, ruff and mypy clean.

## What is still owed

The open question from the report — a **live Windows installation proof** —
is still open, and this iteration widens it rather than closing it. Two of the
fixes change behaviour that CI provably cannot reach, on a project whose own
record says PowerShell has produced four escaped defects across two rounds
because the Windows CI job runs pytest and never touches the installer:

1. **`icacls /setowner` on a real hostile tree.** The claim above — that it
   succeeds on every legitimate tree and fails on an attacker-locked one — is
   read off Microsoft's documentation and the ACLs this installer sets. It has
   not been observed. If `/setowner` turns out to fail somewhere legitimate
   (an oddly-owned gMSA-created file, say), *every* install breaks, loudly.
   That is the fail-safe direction, but it is still a break.
2. **The `*S-1-5-32-544` star form with `/setowner`.** Accepted by every other
   icacls verb this script uses; not verified for this one. There is a
   translated-NTAccount fallback and a hard abort if both fail.
3. **The registry anchor path** — key creation, the protected DACL, the owner
   check on read — is Windows-only and unexercised on Linux.
4. The originally-requested adversarial scenario: pre-planted interpreter,
   matching malicious manifest, planted venv startup file, child junction, and
   race-oriented ACL checks, run end to end.

`samples/lab-validation-runbook.md` plus `samples/lab-harness/` are the
starting point; Pester 5.7.1 and Windows PowerShell 5.1 are on `mvmcitest01`.
**A live re-proof should precede any tag.**

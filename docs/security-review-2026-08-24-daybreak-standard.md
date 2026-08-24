# Security review — 2026-08-24, daybreak standard scan at `0a47955`

Four findings from a daybreak standard review, all four valid, all four fixed.
Two were re-rated on this side and one was re-scoped substantially. The
pre-action declaration, the working set and the acceptance checks are in
`docs/UNFILED-WORK-ITEMS.md` (the regista store still refuses writes).

**Reviewer:** daybreak standard review. **Implementation:** Claude Opus 5. Both
the finding and the fix therefore come from different lineages, which is the
separation the gate asks for — but the *fix* has not itself been independently
reviewed. That is the outstanding gate step, recorded honestly rather than
waived.

## Severity, and where this review disagrees

| # | Finding | Reported | Rated here |
|---|---|---|---|
| 10 | Sibling code loads before the provenance gate | high | **high** |
| 11 | No ancestor check on the state/runtime roots | high | **medium** |
| 12 | HEC token forwarded across redirects | low | **low→medium** |
| 13 | `$env:windir` selects elevated executables | high | **medium** |

The two downgrades are not softening. Finding 11's stated impact does not
reproduce on the default install (see below), and finding 13 needs an attacker
who already controls the environment block of a process about to elevate.
Recording the disagreement with reasoning is the point: the next reviewer should
be able to argue with a decision rather than re-file the finding.

Finding 12 went *up*, slightly, for a reason the reporting reviewer could not
have weighted: an HEC token forges audit **into** the SIEM, and audit is this
product's deliverable.

## The pattern

All four are the same shape, and it is worth naming because it predicts the
next one: **the repository already built the correct primitive, wrote down the
correct reasoning, and did not point it at every call site.**

- `Test-PathChainTrusted` / `Get-TreeTrustViolations` existed and were applied
  to the IIS site tree and the interpreter — not to the state or runtime roots.
- `Get-TrustedInboxModuleRoots` already refused to trust the process
  environment, in a comment that names the exact hazard — while the icacls
  resolution eight lines away still read `$env:windir`.
- The script-tree gate existed and was correct — and sat below two dot-sources.
- The HEC sink validated `https` at config time — and followed a redirect off
  it at request time.

That argues for coverage tests over point fixes, and several of the tests added
here are exactly that: `the shipped library no longer reads windir in
executable code`, `<Script> gates before dot-sourcing <Sibling>` across five
entry points, `has no Add-Type outside an Initialize-*Type function`.

---

## Finding 10 (high) — sibling code loaded before the provenance gate

`Register-MaintenanceTasks.ps1` dot-sourced `lib/TaskActionLib.ps1` and
`lib/SyncLib.ps1` immediately after param binding, ~70 lines above the
script-tree provenance gate. Two libraries executed as Administrator before
anything asked whether the tree was administrator-only.

The gate carried an honest caveat — *"the check is loaded from the very tree it
judges, so someone who can already write here can neuter it"* — and this is a
**different, weaker** problem than that caveat describes. Neutering the check
means rewriting `InstallVerifyLib.ps1`; the ordering meant writing `SyncLib.ps1`
alone sufficed and the gate never ran at all.

Two holes the report did not name:

- The gate was scoped `if ($registerSync)`. Registering only the nonce/sweep
  tasks skipped it entirely while still loading two siblings elevated. The
  justification — *"the nonce/sweep tasks execute nothing from disk"* — is true
  of the **tasks** and false of the **registration script**.
- `Sync-Revocations.ps1`, `Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and
  `Reconcile-Revocation.ps1` had no tree gate at all.

### The part that required overturning a prior decision

The missing run-time check in `Sync-Revocations.ps1` was **not an oversight**.
The 2026-08-18 round considered and declined it, on record, for two reasons:
loading `InstallVerifyLib.ps1` cost two `Add-Type` C# compiles on a 15-minute
cadence, and the residual exposure once registration refuses untrusted trees is
a DACL loosened afterwards, which needs admin rights.

That reasoning was sound. What this round adds is that **one premise fails and
the other has an escape hatch the note itself named**:

- *The failing premise.* "Registration refuses untrusted trees" held only on the
  `$registerSync` path, and only after `:199-200` had already loaded two
  siblings unchecked. The run-time check was traded against a registration-time
  check with a hole in front of it. It also never covered
  `-AllowUntrustedScriptPath`, which registers against a writable tree *by
  design* and then warns into the void — nothing ever re-checks, so the
  documented "re-register before pilot" advice has no enforcement behind it.
- *The escape hatch.* The note closed with *"worth revisiting if the lib is ever
  split so the DACL primitives can be loaded on their own."*

**The compiles are now on demand.** `Initialize-AtomicDirectoryType` and
`Initialize-FinalPathType` compile on first use; only
`New-AtomicProtectedDirectory` and `Get-CanonicalPathString` need them, and
neither is on the trust-checking path. Measured dot-source cost:

```
before: 1298 ms
after:   321 ms      (pwsh 7.6, Linux; the direction, not the number, transfers
                      to Windows PowerShell 5.1 where Add-Type is slower still)
```

So the objection is **retired rather than overruled**, which matters: the
earlier decision does not have to have been wrong for this one to be right.

This also explains why the primitives were *not* split into a new
`BootstrapTrustLib.ps1`, as the declaration originally proposed. Lazy
compilation achieves the same goal with a far smaller diff, and — decisively —
a second file invites a second copy of a predicate. `InstallVerifyLib.ps1:1680`
records what that cost last time: the installer's inline bootstrap copy listed
only the dead half of a rights mask and *"looked correct while covering neither
right"*.

### What changed

- `Assert-PrivilegedScriptTreeTrusted` — one implementation, called from all
  five privileged entry points, **before** any sibling load. `InstallVerifyLib`
  loads first because it *is* the check; the residual self-reference is
  unchanged and documented, but the blast radius narrows from "any sibling" to
  "this specific file".
- `Sync-Revocations.ps1` re-checks at run time, every run.
- `-AllowUntrustedScriptPath` propagates from the registrar into the built task
  action (`Build-SyncActionCommand`). Without that, the documented lab flow
  would register a task that always refuses — a fix that breaks the case the
  override exists for is not a fix.

**Windows-only, by correctness.** `Get-TreeTrustViolations` reads ACLs via
`Get-Acl`, which does not exist on Linux pwsh, so an ungated version refused
*everything* off Windows — caught immediately by three Sync tests dying on a
refusal that listed every ancestor up to `/projects`. A gate that fails closed
on a platform with no such ACLs is not stricter, it is broken.

## Finding 11 (medium) — no ancestor check on the state and runtime roots

Confirmed: `Get-RootProvenance` inspects the root and its contents, never above
it. `install-windows.ps1` already applies `Get-TreeTrustViolations` to
`$SitePath` with a comment making the reviewer's argument verbatim.

**The reported impact does not reproduce on the defaults.** Substituting an
existing child needs `Delete` on the child or `DeleteSubdirectoriesAndFiles` on
the parent. `C:\ProgramData` grants Users create-class rights only
(`WD,AD,WEA,WA` — no `DE`, no `DC`); `%ProgramFiles%` is Users RX. The attack
lands on a **non-default** `-InstallDir`/`-RuntimeDir` under a parent that
grants delete — not hypothetical, since admin-created top-level folders inherit
`Authenticated Users:(OI)(CI)(M)` from `C:\`, and the lab is documented as
staging under `C:\Temp`.

### Why it stalled, and what unblocked it

`install-windows.ps1:1385` records that the `$SitePath` refusal shipped only
once `C:\inetpub` was measured clean — *"the evidence this was waiting on"*.
That evidence could never arrive for `C:\ProgramData`, because
`InstallVerifyLib.ps1:1790` records that it **FAILS** `Test-PathChainTrusted`.

It fails on `WriteData`. On a directory that bit means *create a new entry*, not
*modify an existing child* — a false positive for this question.
`Test-AceEndangersBytes` is correctly named and is right for a file about to be
executed; it is the wrong predicate for an ancestor of a protected root.

`Test-AceEndangersChildContainer` asks the narrow question instead:
`Delete | DeleteSubdirectoriesAndFiles | ChangePermissions | TakeOwnership |
GenericAll | GenericWrite`, and deliberately **not** `WriteData`/`AppendData`.

```
C:\ProgramData   Users:(CI)(WD,AD,WEA,WA)         -> PASSES  (create-only)
%ProgramFiles%   Users:(RX)                       -> PASSES
C:\Temp          Auth Users:(OI)(CI)(M)           -> FAILS   (M carries Delete)
```

Default-safe by construction. The test *"PASSES the C:\ProgramData shape"* is
load-bearing: if it goes red, the default install starts refusing itself, which
is the round-5 lesson (a wrong refusal aborts the upgrade of a live issuance
host). The mutation proof adds `WriteData` back to the mask and that test is
one of the two that fail.

`Get-AncestorSubstitutionViolations` runs in `Initialize-SecuredRoot` **before**
`Get-RootProvenance`, so a substitutable parent is the only violation reported
rather than being buried under consequences. Both roots are covered by the one
call site, because both are claimed through that function.

## Finding 12 (low→medium) — the HEC token crossed redirects

Confirmed **by execution**: a local redirect pair received
`Authorization: Splunk <token>` verbatim after a 302.

`urllib`'s `HTTPRedirectHandler.redirect_request` strips exactly
`("content-length", "content-type")` and copies every other header onto the new
request. `http_error_302` permits `http`, `https` *or* `ftp` targets, so the
config-time https guarantee (`siem.py:335-340`) was worth precisely one hop.

Two precisions beyond the report:

- **Only the token leaks, not the events.** `redirect_request` builds the new
  request without `data=`, and 301/302/303 downgrade POST to GET. Measured:
  method `GET`, empty body. 307/308 also drop the body, and POST+307 raises
  rather than following. Credential disclosure, not audit disclosure.
- The `if not (200 <= resp.status < 300)` branch could not fire — non-2xx
  raises, 3xx was followed — which is *why* a redirect left no trace in the
  logs. It is kept rather than trimmed, because a handler change that made a
  3xx returnable would otherwise be recorded as a successful delivery, and the
  boolean is the control.

Fixed with an opener that refuses redirects outright. The refusal surfaces as an
ordinary `HTTPError`, so `audit_offbox_required`'s startup probe fails loudly
instead of the RA starting on a leaked token.

## Finding 13 (medium) — `$env:windir` selected elevated executables

`InstallVerifyLib.ps1:17` derived `icacls.exe` from `$env:windir` with a bare
`'icacls.exe'` fallback, while `Revoke-Cert.ps1`, `Set-OfficerRights.ps1` and
`Reconcile-Revocation.ps1` resolved System32 from the runtime and
`Get-TrustedInboxModuleRoots` used machine-scope registry plus the folder API,
with a comment spelling out why the process environment cannot be trusted.

Two additions to the report:

- **The bare-name fallback was the sharper bug.** `else { 'icacls.exe' }` is
  PATH resolution, reached by *unsetting* windir rather than redirecting it — a
  lower bar. Test `:1607` asserted the *installer* never invoked icacls by bare
  name; the *library* still could.
- **Double impact.** icacls output is not merely executed, it is the evidence
  `Get-RootProvenance` and `Assert-InstallTreeLocked` parse. A substituted
  icacls forges the lockdown proof as well as running code.

**Fixed completely rather than at line 17.** `Get-TrustedSystem32Path` resolves
from machine-scope `windir` then the folder API, requires a drive-absolute
Windows path, and **throws** on Windows rather than falling back — a fallback
that restores PATH resolution is the bug with a longer code path. All nine
installer sites (msiexec, secedit, cmd, netsh, appcmd, attrib ×2, the handler
DLL probe) moved onto it, and the three test assertions that *pinned* the
`$env:windir` spelling were rewritten to pin the new one. Half-fixing the
library while leaving the installer on the old pattern is how this class keeps
returning.

The platform-detection block moved above the icacls resolution, because the
resolver is gated on `$script:InstallVerifyIsWindows` and PowerShell executes a
dot-sourced file top to bottom.

---

## Evidence

Every check re-run after the last edit, not before it.

| Check | Result |
|---|---|
| `pytest -q` | 931 passed, 1 skipped |
| `ruff check .` | clean (`ruff format` is **not** a repo gate — CI runs `ruff check`, `mypy src`, `pytest -q`) |
| `mypy src/` | clean |
| `Invoke-Pester tests/pester -CI` | **457 passed, 0 failed, 4 skipped** (baseline 424) |
| HEC redirect live probe | token withheld from the redirect target |

### Mutation proofs

A test that cannot fail manufactures confidence in the next reviewer. Each fix
was reverted in place and the suite re-run:

| Mutation | Detected by |
|---|---|
| `Get-TrustedSystem32Path` reads `$env:windir` again | 2 tests fail |
| `WriteData` added back to the container mask | `PASSES the C:\ProgramData shape`, `is strictly narrower…` |
| Sync gate moved back below the dot-source | `Sync-Revocations.ps1 gates before dot-sourcing lib/SyncLib.ps1` |
| `Add-Type` restored to top level | 3 tests fail |
| `Assert-PrivilegedScriptTreeTrusted` made to return unconditionally | 2 tests fail |
| Ancestor check moved after `Get-RootProvenance` | `refuses before Get-RootProvenance…` |
| `urlopen` restored in `siem.py` | leak assertion fails **with the token in hand** |

**Three** vacuous or misleading tests were caught during this pass, all in the
new code, all fixed. That rate is itself the finding: a test written against a
working fix cannot distinguish "passes because the code is right" from "passes
because it asserts nothing".

1. The
`Test-AceEndangersChildContainer` cases initially defined their rights constants
in the `Describe` body, which Pester 5 evaluates during discovery in a different
scope from the `It` blocks. `$FR` was `$null` at run time, `[int]$null` is `0`,
and every mask assertion would have passed vacuously. It surfaced only because
the tests were written to fail first.

2. The behavioural gate tests drove the platform by assigning
   `$script:InstallVerifyIsWindows` from an `It` block — a different scope from
   the one the function resolves — so the Windows branch never ran and the test
   reported "no exception thrown" against a perfectly good gate. Fixed by making
   the platform an `-IsWindowsHost` parameter, which is also what this library's
   own design philosophy asks for (decision logic takes plain values so Linux
   Pester can drive it).
3. Those same tests relied on `Get-Acl` being *absent* off Windows to force a
   refusal. It is not reliably absent: this test file installs
   `function global:Get-Acl` stubs in several `Describe`s and at least one
   outlives its block, so a later `Describe` inherits whatever the last stub
   returned. Each case now installs its own ACL — which is strictly better, since
   the refusal is driven by a specific bad DACL rather than by a missing cmdlet,
   and therefore exercises the verdict rather than the error path.

A companion test — *"PASSES a tree only administrators can write"* — was added
for the opposite failure: a gate that always threw would satisfy every refusal
test and be unusable in production.

## What this round did not do

- **No live Windows validation.** Findings 10, 11 and 13 are Windows-side;
  Linux Pester covers the pure decision functions and cannot cover live ACL or
  process behaviour (WI-050). Assurance rides the outstanding lab session, with
  the D1–D7 class. In particular `Get-AncestorSubstitutionViolations` has never
  been run against a real `C:\ProgramData` ACL — the shapes it is tested against
  are transcribed from the round-7 survey recorded in this repo, not measured
  fresh.
- **The fix is unreviewed.** Independent review by a third lineage is the
  outstanding gate step.
- **The regista store still cannot record any of this.** Six migrations are
  pending on the shared schema; migrating it has estate-wide blast radius and is
  an owner decision.

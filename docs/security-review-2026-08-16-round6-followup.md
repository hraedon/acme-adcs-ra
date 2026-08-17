# Security review — round-6 follow-up (2026-08-16)

Scope: an internal review of the round-6 fixes themselves (`e4ec6aa`), before
the tip is re-validated and handed back to Daybreak. Round 6 rewrote the
installer's trust boundary around three construction rules; this pass asks
whether the new code keeps them. Four defects, one of which is the same class of
bypass round 6 was written to close.

Source verification after the changes: 816 pytest passed, 1 skipped; 285 Pester
passed, 1 skipped; ruff and mypy clean. **This is not a live Windows proof.**
The native cases owed are listed at the end.

## The pattern worth naming

Three of the four are in code that round 6 *added*, and two of those are
PowerShell evaluating to something other than what it reads as: a static member
that does not exist resolving to `$null`, and a variable assigned in a scope that
is not the one where it is used. This is the fifth and sixth escaped defect of
that family in this repository. The language does not fail loudly on either.

## Finding 1 (high) — the bootstrap's write-mask covered neither WRITE_DAC nor WRITE_OWNER

`install-windows.ps1`, `Assert-BootstrapObjectTrusted`. The round-6 gate — the
one that runs before any sibling code is dot-sourced, and the whole answer to
round-6 finding 2 — built its dangerous-rights mask from
`FileSystemRights::WriteDacl` and `::WriteOwner`.

**Those members do not exist.** The enum spells them `ChangePermissions`
(`0x40000`) and `TakeOwnership` (`0x80000`). PowerShell resolves a missing static
member to `$null`, `[int]$null` is `0`, and `-bor 0` is a silent no-op, so both
terms vanished from the mask.

Consequence: an allow ACE granting a named non-administrator nothing but the
right to rewrite the DACL and take ownership — `icacls <path> /grant user:(WDAC,WO)`
— returned "trusted". That principal then grants itself full control over
`InstallVerifyLib.ps1`, `src\`, or `deploy\`, which the elevated installer
dot-sources and builds from. It is round-6 finding 1 (named writer ACEs bypassing
provenance) reachable through the fix for round-6 finding 2.

The library's own `Test-AceEndangersBytes` listed **both** pairs, so it was
correct — and carrying the dead half there is what made the bootstrap copy look
right by resemblance. Fixed in both places; the dead spellings are gone
repository-wide, and a test asserts no shipped file names them again.

The test evaluates the *value* of the shipped mask expression, lifted out of
`install-windows.ps1` through the PowerShell AST, rather than matching its text.
A text assertion would have passed against the defect.

## Finding 2 (high) — the bootstrap never inspected `scripts\` or `scripts\lib\`

Same gate. The ancestor loop walks **upward** from the release-tree root, and the
input list names the helper *file*. Nothing ever looked at the two directories
between them.

`DeleteSubdirectoriesAndFiles` on a parent is delete-and-recreate on the child
**whatever the child's own DACL says**, so a non-administrator holding it on
`scripts\lib\` can replace `InstallVerifyLib.ps1` in the window between the check
and the dot-source. Round 6's stated design rule is that a create-capable window
must be impossible rather than detected; this one was created by an ACL the
installer never read.

The review doc also overstated the code: it claimed the bootstrap checks "every
consumed input **and its ancestor chain**". It checked the release root's
ancestors, not each input's.

Fixed with `Get-BootstrapInteriorDirectories`, which returns every directory
between the release root and a consumed input and **refuses** — rather than
returning nothing — for a path that is not under that root. Each interior
directory is proven with the same object gate before the input itself is walked.

## Finding 3 (medium, install-breaking) — the TLS catch-all path invoked a null command

`install-windows.ps1`, the `-ConfigureIIS` TLS block. Round 6 moved the elevated
native utilities off ambient PATH, but assigned the `netsh` path in two places
that were not in scope where it was used: once function-locally inside
`Ensure-SslCertBinding`, and once inside the `-SharePort443` branch. The
**catch-all** branch's stale-SNI cleanup then invoked an unassigned variable.

Reproduced exactly:

```
RuntimeException: The expression after '&' in a pipeline element produced an
object that was not valid. It must result in a command name, a script block, or
a CommandInfo object.
```

Under `$ErrorActionPreference = 'Stop'` that is terminating: the install dies
**after** the TLS certificate is bound and **before** the app pool is started,
leaving the host half-configured with the pool down.

Reachable on `-ConfigureIIS -HostName <name> -TlsCertThumbprint <t>` **without**
`-SharePort443` — a supported combination the code has a dedicated cleanup branch
for. The lab deployment always uses the SNI path, so no live re-proof of any round
could have found it. Fixed with one script-scope `$netshExe`, asserted to be
assigned before every use.

## Finding 4 (medium) — the audit coalescer's open-window index was unbounded

`audit_coalesce.py`. The 2026-08-15 rescan-2 fix made *durable* audit growth a
function of elapsed time. Nothing bounded the in-memory dictionary tracking which
windows are open: an entry was dropped only when that same key was recorded again
after its window lapsed, and no sweep ever ran.

For account-creation denials that is harmless — the key is
(event type × server-chosen reason), a small fixed set, and keying on the
attacker-chosen `kid` was deliberately avoided. The round-5 additions changed the
shape: `finalize-csr-mismatch` and `finalize-policy-denied` put `order_id` in the
key, so a client finalizing many orders badly mints a fresh, never-collected key
each time. The installer configures the app pool with `idleTimeout=00:00:00` and
`recycling.periodicRestart.time=00:00:00`, so the worker never recycles to reclaim
it either.

Fixed with `MAX_OPEN_WINDOWS` (1024), enforced only when a **new** window opens,
dropping expired entries before any live one. Below the cap the behaviour —
including the `previous_window` hand-off to a reopened key — is unchanged. Nothing
durable is touched: every window's tally is already committed to its row on each
increment, so eviction gives up only the ability to fold *future* repeats into an
existing row. This is deliberately not a pruner.

## Adjacent variants closed

- **The ACL read-back dump left ambient `%TEMP%`.** Round 6 moved the Python probe
  output and the `secedit` policy files into protected scratch and left this one,
  which is not scratch at all: it is the entire evidence for "is this pre-existing
  root ours?" and for every post-claim lockdown proof. `GetTempPath()` is
  `%windir%\Temp` — Users-writable — whenever the installer runs as SYSTEM under
  configuration management. The protected installer scratch directory is now
  created **before** the first root claim, and the library writes its dumps there.
  *(Corrected in round 2 — see R2-12: this first draft fell back to ambient TEMP
  whenever no scratch was configured, which is the one path that restores the
  behaviour being removed. On Windows it now throws.)*
- **A pre-scratch failure printed a spurious warning.** PowerShell registers a
  `trap` for the whole scope at parse time, but a function exists only once its
  definition has executed — so an early refusal (non-disjoint roots, say) entered
  the handler before `Remove-InstallerScratch` was defined and printed a
  `CommandNotFoundException` about an empty path immediately before the real
  error. Guarded.
- **README contradicted round-6 finding 3.** The prerequisite table still told
  operators that `-InstallPrereqs` installs Python "(uses `winget`)", fifty lines
  above the prose correctly saying it deliberately does not.
- **Round 6 never reached the CHANGELOG.** Every other round in this series has a
  section; the seven findings and the live-found finding 8 had none. Added.

## Not changed, and why

`-ConfigureIIS` re-runs `icacls /grant "<gMSA>:(OI)(CI)R" /L` against a
pre-existing site tree on every install, without `:r`. The concern is ACL
accretion across repeated installs, which is cosmetic. Converting it to `/grant:r`
would replace the `(OI)(CI)RX` grant a freshly created site tree receives with
`R`, dropping directory traverse for the pool identity — a functional change to
the IIS launch path that no unit test can settle and that belongs in front of a
live re-proof, not behind one. Left as-is and recorded here.

## Native proof required before pilot

On Windows PowerShell 5.1, on the deployed host shape, on the exact tip. Items
1–5 are new; item 6 was already owed from round 6.

1. An ACE granting a named user (and a custom group) **only** `WDAC`/`WO` on the
   release tree, on `scripts\lib\`, and on `src\` is refused by the bootstrap
   before the helper is dot-sourced. Control: the same tree without that ACE
   installs normally.
2. A write ACE on `scripts\` or `scripts\lib\` alone — the helper file itself
   untouched and administrator-owned — is refused.
3. `-ConfigureIIS -HostName <name> -TlsCertThumbprint <t>` **without**
   `-SharePort443` completes: the catch-all binding is created, any stale
   hostname binding is removed, and the app pool starts. This is the path that
   could not previously finish.
4. The `icacls /save` dumps are written under `%ProgramFiles%\.acme-adcs-ra-installer-*`
   and not under `%windir%\Temp` or the invoking user's TEMP, from the first
   provenance check onward; the directory is removed on both the success and the
   failure path.
5. Re-run the round-6 item 1 standard-user race loop unchanged: no create-capable
   handle, no post-lock plant, on any managed root.
6. **Still owed from round 6:** the MSI verification case (local and downloaded
   source paths replaced during verification; no replacement bytes reach
   `msiexec`). The lab host already has HttpPlatformHandler installed and the
   DLL-presence fallback short-circuits the path.
7. Repeat the complete clean install, reinstall, rollback, migration, and gMSA
   HttpPlatformHandler launch proof. Partial/delta proof is insufficient.

Until those pass, this is source-reviewed and test-clean, not pilot-ready.

## Test notes

Every new test is mutation-verified; the mutation each detects is named in its
docstring or comment. Eight PowerShell mutations and four Python mutations were
run and all were caught.

One test did **not** survive that check and was deleted rather than shipped. An
earlier draft guarded the eviction call with `if key not in self._windows` and
claimed a test proving it prevented bystander eviction. Removing the guard did
not fail the test — and could not have, because a key present at that point is
always one whose window has lapsed (a live key folds and returns earlier), so the
expiry pass frees its slot either way. The guard was unreachable-by-construction
dead weight and both it and the test are gone. The replacement test pins the
behaviour at the cap boundary and says plainly in its docstring that it is not a
mutation detector.

---

# Round 2 of the follow-up — three independent reviews of the fixes above

Scope: the four fixes above were themselves reviewed by three independent
reviewers, each pointed at a single named hazard rather than at the diff.
Twelve further defects, one high. **Two of them were in the fixes above**, which
is the same "the fix becomes the next finding" pattern this project keeps
hitting, and is the reason the round was run at all.

Gates after: **826 pytest + 1 skipped, 319 Pester + 3 skipped, ruff, mypy.**
Every fix mutation-verified — 10 PowerShell mutations and 12 Python — all
detected. Still **not a live Windows proof.**

## High

### R2-1 — `Get-SerialFromReqId` returned a transcript, so `-ReqID` could never revoke

`scripts/Revoke-Cert.ps1`. Two `Write-Output` diagnostics sat above the `return`,
and a PowerShell function returns everything written to the success stream — so
`$targetSerial` at the call site was a five-element array of banner lines with
the serial last, which the next statement pasted into
`-restrict SerialNumber=<banner lines…>`.

**This is the same defect the 2026-08-18 wave-3 round fixed in
`Test-SerialRevokedAtCa`, 130 lines above it, in the same file.** The sibling was
missed. It fails safe — nothing wrong is revoked — but it takes out the manual
containment path an operator reaches for during an incident, and no live re-proof
has ever exercised it because `Sync-Revocations.ps1` always passes `-Serial`.
Fixed to `[Console]::Error.WriteLine`, the idiom this file already documents.

## Medium

### R2-2 — the launch-configuration gate read one attribute of four

`Assert-WebConfigLaunchTrusted` extracted `httpPlatform/@processPath` and checked
only which tree it was in. Everything else that decides what the gMSA runs was
unread, and **`$ExpectedProcessPath` was a mandatory parameter that appeared only
inside error strings and was never compared to anything.** Driven against eight
crafted files, the gate accepted all of these:

| case | before |
|---|---|
| `arguments="-c ""import os;os.system(…)"""` | accepted |
| `PYTHONPATH` pointed at a world-writable directory | accepted |
| `ACME_RA_EAB_ALLOWLIST` / `ACME_RA_SAN_SCOPES` set in `<environmentVariables>` | accepted |
| `ACME_RA_DOTENV` redirected to a gMSA-writable path | accepted |
| a `<location>`-scoped `httpPlatform` override | accepted |

The env-var cases are the sharp ones, and I verified the mechanism rather than
assuming it: **pydantic-settings ranks an environment variable above the dotenv.**
Set both and the env var wins. So `web.config` — validated one attribute deep —
silently overrides `acme-ra.env`, the file the installer protects with a bespoke
read-only DACL, a strict owner check, a rollback re-protect path and a dedicated
`-ProtectedEntries` proof. Writing `web.config` needs admin-equivalent access to
the site tree, so this is a completeness gap in a stated control rather than a
direct non-admin escalation — but the stated control is "web.config IS launch
configuration… an unprovable launch configuration is refused, not adopted."

Fixed: every `//httpPlatform` node is checked (not one dotted lookup);
`processPath` must equal `$ExpectedProcessPath`; `arguments` must be exactly
`-m acme_adcs_ra`; the issuance-policy env names and `PYTHONPATH`/`PYTHONHOME`/`PYTHONSTARTUP` are refused; and
`ACME_RA_DOTENV`, if present, must be the protected file. A test asserts the
**shipped template still passes** — a gate that refuses the template breaks every
install.

**Operator-breaking.** A preserved `web.config` carrying any of the above now
fails the install rather than being adopted. That is the intended direction.

### R2-3 — an ACE-less DACL was judged administrator-only

`Test-ObjectDaclTrusted` and the installer's bootstrap both decided trust purely
from inside a `foreach` over `$acl.Access`, so an **empty** collection yielded
zero violations. A NULL DACL means *everyone has full control*, and .NET renders
it identically to a deny-everyone empty DACL. `Test-AclDumpLocked` already
treated exactly this condition as tampering and failed closed on it, so the file
disagreed with itself. For the interpreter chain this reopened round 5's finding.
Both gates now refuse it.

*Reported CONFIRMED for the decision logic (driven with a shadowed `Get-Acl`) and
SUSPECTED for the Windows half: that `Get-Acl` presents a NULL DACL as an empty
`.Access` is reasoned from documented `ObjectSecurity` semantics, not measured.*

### R2-4 — the nonce-cleanup and expired-order-sweep tasks could never have run

`Build-ActionScriptBlock` emitted six double quotes across eleven lines, and its
caller wraps the result in `-Command "…"`. `CommandLineToArgvW` re-splits on the
embedded quotes, so `@{ 'Authorization' = "Bearer $tok" }` reached PowerShell as
`… = Bearer $tok }` — "The term 'Bearer' is not recognized". Registration
reported success either way: `New-ScheduledTaskAction` only stores the string and
the post-register check reads `NextRunTime`, never `LastTaskResult`. Nonce GC and
the RFC 8555 §7.1.6 expired-order sweep would have failed silently on every run.

`Build-SyncActionCommand` had this invariant, a comment explaining it, and two
tests; this sibling had none. Now single-line, single-quoted, and both invariants
are tested. **Needs a Windows confirm:** run the nonce-cleanup task once and read
`LastTaskResult`.

### R2-5 — the coalescing key absorbed an attacker-chosen SAN

`IssuancePolicy.evaluate` returns `f"SAN out of scope for kid {kid}: {san}"`, and
`finalize` passed it straight into `details["reason"]` — which the coalescer keys
on. One order carrying forty out-of-scope identifiers, then one finalize per
identifier, produced **forty durable rows in one window**: exactly the
bound-defeat the module docstring says the key excludes attacker-chosen data to
prevent. **This is a defect in the area the first half of this round hardened.**

`PolicyDecision` gained a `reason_code` from a fixed vocabulary; the coalescer
keys on that and falls back to `reason` for call sites that send none. The prose,
including the offending SAN, is still written to the row in full.

### R2-6 — `Stop-AppPoolAndWait` read "appcmd failed" as "no such pool"

`& $AppcmdExe list apppool "$Pool" 2>$null` discarded stderr and ignored the exit
code, so a broken `applicationHost.config`, a stopped WAS, or an access denial
was indistinguishable from a first install. The installer then printed
`[ok] no such app pool yet` and went on to claim and rebuild trees a live gMSA
worker may hold write handles into — handles that survive the ACL reset. That is
rescan-2 F3, reached through the check that exists to prevent it. Now keyed on
stderr (not the exit code, whose not-found semantics cannot be established off
Windows), and tested with a stand-in appcmd.

### R2-7 — `_Window.distinct_kids` was unbounded within a window

`kid_samples` was capped and `distinct_kids` was not, so a client varying the kid
retained one digest each — ~5 MB per 50,000 kids — freed only when the window
rolls. `operations.md` recommends a *longer* window to reduce row growth, which
multiplies exactly this. Capped at `MAX_DISTINCT_KIDS`; past the cap the row
reports `distinct_kids_truncated: true` rather than a number that has quietly
stopped counting. `denial_count` stays exact.

## Low

- **R2-8 — `Reconcile-Revocation.ps1` ran bare-PATH `certutil` and `python`.**
  Same class as round-6 finding 3, in a script that runs with CA-officer context.
  Both now resolve to absolute/verified paths, and the CWD is removed from the
  child search path.
- **R2-9 — the interpreter was proven at one resolution and executed at another.**
  `Test-PathChainTrusted` ran against `$cmd.Source`; the probe was then handed the
  bare name and re-resolved it. Two lookups, one gap. Now one path.
- **R2-10 — `.Trim()` on a null probe line.** When no output line matched, the
  "output not recognised" branch was unreachable and the install aborted with a
  confusing error instead of skipping the candidate.
- **R2-11 — `Get-OfficerRights.ps1`**: `.Count` on an unwrapped single ACE (the
  normal provisioned state) renders blank on Windows PowerShell 5.1; and a
  descending range slice `$b[5..4]` is a *reversed* two-element read, not an
  empty one, which could satisfy the length guard and mis-parse `sidCount`.
- **R2-12 — the scratch fallback reopened the hole it closed.** My own fix fell
  back to ambient TEMP whenever no scratch was configured. On Windows it now
  throws; the TEMP path survives only off Windows, where the Pester suite runs.
- **R2-13 — eviction was invisible and mis-ordered.** An absent `previous_window`
  could not be told from an evicted predecessor, and eviction by `opened_at`
  destroyed the longest-folding window — the one whose survival saves the most
  rows, and a choice an attacker steers by minting fresh keys. Now
  least-recently-touched, with a `coalescer_evictions` marker on affected rows.

## Reported and deliberately NOT fixed

**`-SitePath` gets no ancestor-chain provenance.** The site root is proven
object-by-object, but `C:\inetpub` is not: delete-child on the parent replaces the
site root whatever its own DACL says — the same reasoning as this round's
interior-directory fix, applied to the tree holding the launch configuration. The
fix is a `Test-PathChainTrusted` call. It is not in this diff because its
baseline cannot be measured from here, and when round 5 added exactly that kind
of chain rule the live run found **two** calibration defects in it (the raw
generic-bit constants, and SID-vs-name comparison) plus a third around
`InheritOnly`. Shipping an uncalibrated refusal into the installer immediately
before a live re-proof is the specific pattern that has cost this project the
most. **Native item: survey the `C:\inetpub` chain on the lab host; if it passes
`Test-PathChainTrusted`, add the refusal.**

Also carried forward, unchanged: the duplicate site-tree ACE on re-runs
(cosmetic; converting to `/grant:r` would drop directory traverse), and the
coalescer's global lock being held across SQLite I/O (latency only — single lock,
no ordering inversion, no deadlock, and `emit_audit_hook` is correctly outside).

## Native cases owed, added to round 1's list

8. `Revoke-Cert.ps1 -ReqID <n>` resolves a serial and revokes it at the CA.
9. The nonce-cleanup task runs once and reports `LastTaskResult 0`.
10. A `web.config` carrying `arguments="-c …"`, a `PYTHONPATH`, an
    `ACME_RA_EAB_ALLOWLIST`, or a `<location>` override is refused; the deployed
    file is accepted unchanged.
11. `Reconcile-Revocation.ps1` still reconciles after the interpreter change.
12. **Under real Windows PowerShell 5.1** (`pester-windows-powershell`, and the
    Pester 5.1 install on the lab RA host): the whole suite, plus the
    `& certutil … 2>&1` behaviour in `Revoke-Cert.ps1` under `EAP=Stop`, which
    pwsh 7 cannot demonstrate either way — `SyncLib` documents that on 5.1 the
    first stderr line terminates, which would break the documented exit-code
    contract. **Reported SUSPECTED; unresolved.**

---

# Round 3 — three more independent reviews; sixteen findings, one high

Scope: the round-2 fixes, reviewed by three fresh hazard-scoped reviewers.
**Every finding but two was in a round-2 fix.** That is the third consecutive
round in which the remediation contained the next defect, and it is the single
most important fact about this codebase's installer.

Gates after: **827 pytest + 1 skipped, 337 Pester + 4 skipped, ruff, mypy.**

## High

### R3-1 — `Stop-AppPoolAndWait` would have aborted every first install

My round-2 fix threw on *any* stderr from the appcmd existence probe. But
`appcmd list apppool <absent>` writes
`ERROR ( message:Cannot find APPPOOL object with identifier … )` to stderr and
exits non-zero — and the installer does not create the pool until ~800 lines
later, so **on a first install the pool is absent by construction**. The guard
would have refused the install it was supposed to protect.

This is the netsh defect's exact shape: a guard only the untravelled path
reaches, invisible to a lab whose host already has the pool.

Rewritten so ambiguity is resolved by doing *more* work rather than less:
anything on stderr no longer decides, it falls through to stop-the-pool and
prove-the-worker-gone, and `Test-AppPoolWorkersGone` already fails closed on
output it cannot classify. Nothing now depends on appcmd's exit code or on the
wording of a localizable message.

**A second defect surfaced while mutation-testing that fix.** `$exists` was
built from every element of the `2>&1` capture — ErrorRecords included — so it
was never empty when stderr fired, which made the new `$probeErr` clause *dead
code that happened to produce the right answer*. A mutation deleting the clause
changed nothing, which is how it was found. `$exists` is now stdout only.

## Medium

- **R3-2 — the forbidden-env-name list was one delimiter deep.** `config.py`
  sets `env_nested_delimiter="__"`, so pydantic-settings reads
  `ACME_RA_SAN_SCOPES__<kid>__DNS_PATTERNS` as a path *into* `san_scopes`. My
  exact-string match walked straight past it. **Verified against the running
  config:** a nested variable replaced the protected dotenv's `dns_patterns` for
  an existing kid — that kid's issuance authorisation — while the installer
  printed `[ok] launch configuration verified`. The match now splits on the
  delimiter and compares the first segment.
- **R3-3 — `<handlers>` was never inspected**, and `install-windows.ps1` is
  itself what makes a site-level entry authoritative: it runs
  `appcmd unlock config -section:system.webServer/handlers`. A handler with a
  `scriptProcessor` executes an arbitrary binary as the gMSA — the same
  primitive pinning `processPath` removes. `<handlers>`, `<modules>` and
  `<isapiFilters>` are now all checked.
- **R3-4 — only `<environmentVariable>` children were read**, so the same
  setting smuggled in as `<add name="…">` was never examined.
- **R3-5 — settings with one production value were accepted at any value.**
  `ACME_RA_AUDIT_OFFBOX_REQUIRED=false` turns off the guarantee that audit
  events leave the box, on the host the threat model calls load-bearing;
  `ACME_RA_ALLOW_WEAK_CREDENTIALS=true` disables the credential floors and its
  own docstring says lab/CI only. Both refused now.
- **R3-6 — the anti-ambient-TEMP guard gated on `$env:OS`**, an inherited,
  caller-settable variable, in the one function whose thesis is not trusting the
  ambient environment. Anything starting the installer with `OS` unset silently
  got the fallback the guard exists to remove. Now read from the runtime. **Two
  further instances of the same gate were found and fixed** — including
  `Get-CanonicalPathString`, where an unset `$env:OS` skipped kernel final-path
  resolution entirely, so a junction or 8.3 alias would not be collapsed and two
  spellings of one tree could read as `disjoint`. That relation *is* the
  RX/Modify boundary between the code and state roots.
- **R3-7 — `PolicyDecision.reason_code` defaulted to `"allowed"`.** Any future
  denial branch omitting the keyword would emit `outcome="denied"` carrying
  `reason_code="allowed"`: two distinct denials folded into one row, the
  second's prose nowhere on disk, and a SIEM rule keying on the new field
  misreading it. A default is invisible to mypy. Now required.
- **R3-8 — the privileged siblings kept bare-PATH natives.** Round 2 hardened
  `Reconcile-Revocation.ps1` — the *read-only* script — and left `& certutil` in
  `Revoke-Cert.ps1` (which runs `-revoke` with CA-officer context),
  `Set-OfficerRights.ps1` (which writes CA officer rights) and
  `Get-OfficerRights.ps1`. The low-value script got hardened and the high-value
  ones did not. All now resolve absolutely.
- **R3-9 — and the python half of that fix closed nothing.** `Get-Command python`
  *is* the PATH lookup; a planted binary in a writable PATH directory is an
  `Application` with a rooted `Source` and satisfies every condition the fix
  added. It now goes through `Test-PathChainTrusted` — the same gate the
  installer uses — and refuses Store stubs.

## Low

- **R3-10 — the expiry sweep shed windows without counting them.** Only the LRU
  loop incremented `_evicted`, and the sweep is the branch an attacker drives
  (minting keys to reach the cap is what triggers it). A swept victim's
  successor row carried neither `previous_window` nor `coalescer_evictions` —
  byte-identical to a first-ever window, the exact ambiguity the marker exists
  to remove. Also documented: the counter is cumulative and never resets, so it
  answers "has the index been shedding" and not "is it shedding now".
- **R3-11 — the durable-growth claim needed a caveat.** Above
  `MAX_OPEN_WINDOWS` the bound degrades back toward one row per request, because
  round-robin across more keys than the index holds makes every lookup a miss.
  Out of reach at shipped defaults (>1024 live finalize keys in a 60s window
  against a 50-orders/hour/kid limit), but an operator setting
  `rate_limit_orders_per_window=0` — a documented mode — removes what keeps it
  out of reach, and a *longer* window makes it easier. Now stated in the module
  docstring rather than claimed unconditionally.
- **R3-12** false refusals that would have aborted a live upgrade: forward-slash
  paths (which IIS and Python both accept) refused with a message asserting the
  path was not absolute; a default `xmlns` on `<configuration>` making
  `SelectNodes('//httpPlatform')` return nothing and produce a "there is no
  httpPlatform" diagnostic about a file that plainly has one; and
  `arguments="-m  acme_adcs_ra"` refused over a double space.
- **R3-13** `ACME_RA_DOTENV` was validated only *if present*. Absent, the worker
  resolves `.env` against its own working directory, so the file the installer
  locks, owns, re-protects on rollback and proves is not the file the RA reads.
  Now required. **Operator-breaking.**
- **R3-14** the docs claimed `PYTHON*` was refused; the code matches exactly
  `PYTHONPATH`/`PYTHONHOME`/`PYTHONSTARTUP`. Docs corrected to the code.

## Test-quality findings — and the reason this section exists

A reviewer demonstrated that **six of round 2's new guards could be neutered
without a single test failing**, because their only coverage was a source-grep
that the mutation left intact. "Every new test was mutation-verified" was not
true of those. They now have behavioural tests that drive the real functions:
`Test-ObjectDaclTrusted`'s empty-DACL refusal (via a shadowed `Get-Acl`),
`Test-AclDumpLocked`'s in-loop SDDL-less branch (both earlier tests put that
entry last, exercising only the trailing commit), and both platform branches of
`Get-InstallVerifyScratchPath`.

Separately, `test_a_live_window_survives_below_the_cap` **did not detect the
mutation it named** — its clock never advanced, so nothing expired and the
unguarded sweep had nothing to destroy. Rewritten so the lapse it depends on
actually happens. That is the second test in this series to fail its own
mutation check; the first was deleted.

Three mutations run during this round initially survived
(`_evict_for_new_window`'s expiry counting, the appcmd stderr clause, the
under-cap guard) and each one exposed a real defect or a real test gap rather
than a false alarm.

## Still open, and still not fixed

- **`-SitePath` ancestor-chain provenance** — unchanged from round 2, same
  reasoning, still a native item.
- **`& certutil … 2>&1` under `EAP=Stop` on Windows PowerShell 5.1.** pwsh 7
  cannot demonstrate it either way; `SyncLib` documents that on 5.1 the first
  stderr line terminates, which would break the documented exit-code contract.
  Now known to affect `Reconcile-Revocation.ps1` as well as `Revoke-Cert.ps1`.
  **SUSPECTED, unresolved, needs the 5.1 engine.**
- **`appcmd list apppool <absent>` exit code and stderr**, on a real Windows
  host. The current design is deliberately independent of both, but the one
  command that settles it should be run:
  `appcmd list apppool "nope" 2>err.txt & echo %errorlevel% & type err.txt`.
- **Whether IIS honours a `<location>`-scoped `httpPlatform`**, and whether
  `IsapiModule`/`CgiModule` are registered by the installer's feature set. The
  gate refuses both regardless; these determine their severity, not the fix.

---

# Round 4 — review of the three rounds above; seven findings, one trust-verdict inversion

Scope: before lab-validating the rounds above, the uncommitted diff was itself
reviewed by three hazard-scoped reviewers (installer/lib PowerShell; the Python
coalescer/policy/finalize leg; the CA-officer operational scripts). Seven
findings, all fixed in source. One is the series' pattern at its purest: the
R2-11 `@()` wrapping **inverted the readback tool's trust verdict**.

Gates after: **830 pytest + 1 skipped, 345 Pester + 4 skipped, ruff, mypy.**
Nine mutations run against the new tests (4 Python, 5 PowerShell), all
detected. Still not a live Windows proof — that run follows this round.

## Medium

### R4-1 — `@()` around a `$null` parse made Get-OfficerRights report 1 ACE and exit 0

The R2-11 fix wrapped `Parse-OfficerRightsSD`'s return in `@()` to fix the
single-ACE unwrap. But the function `return $null`s for a truncated (<20 byte)
or DACL-less descriptor, and **`@($null)` is a one-element array** — Count 1 —
so the "present but contains no callback ACEs" guard was skipped, the operator
saw `Found 1 OfficerRights ACE(s)` over a blank table, and the script exited
0. The verify-by-readback tool affirming a restriction that is not in force is
the exact failure it exists to prevent. `OfficerRightsLib.ps1` documents this
whole class (`@(Get-ExistingAces ...)` plus never-`$null` returns); the copy in
Get-OfficerRights.ps1 violated it. Fixed: early exits return `@()`; a
behavioural test drives the lifted function for both degenerate inputs, and a
text assertion pins `return $null` out of the function.

### R4-2 — two more control-removing env names were still settable from web.config

`ACME_RA_ALLOW_FAKE_ADCS_BACKENDS` (lab/CI-only per its own docstring) was
missing from the forbidden list, and
`ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` from the pinned values. The
latter is pinned-when-present rather than forbidden: absent is the documented
optional mode (dotenv/default), the lab harness legitimately sets it to `true`
in web.config, and `false` is the only value that can silently override a
dotenv that turned the proof ON. Same class as R3-5.

### R4-3 — `finalize-csr-mismatch` still keyed its coalescing window on prose

The R2-5 fix gave `finalize-policy-denied` a `reason_code`; the sibling call
site 25 lines above got none. Its `reason` is a fixed string today, but
`out_of_order` — the attacker-chosen SAN list — sits in the same details dict
one refactor away from being interpolated into it. Pinned now, with an
end-to-end test that asserts both the stable code on the row and one row per
window under varied content.

### R4-4 — the 5.1 `2>&1`-under-`Stop` hazard was left standing in every CA-officer script

Round 3 hardened the *read-only* script's interpreter resolution and left the
exit-code contract exposed: `SyncLib` documents (from the 2026-08-13 live run)
that on Windows PowerShell 5.1 the first line a native command writes to a
merged stderr terminates the pipeline under `EAP=Stop` — before
`$LASTEXITCODE` is read. `Revoke-Cert.ps1`'s own header promises an
exit-N-relaying contract "reachable by wrapping automation" that this makes
unreachable, and `Set-OfficerRights.ps1`'s `net stop`/`net start` fallback runs
inside a catch block where a terminating error means the CA stays DOWN. The
EAP-lowering shield SyncLib already uses for its child hop is now applied to
every CA-officer native call: a central `Invoke-CertUtilCapture` in
Revoke-Cert.ps1 (used by `Invoke-CertUtil` and the three direct `-view` calls),
and shields in Reconcile-Revocation.ps1, Get/Set-OfficerRights.ps1. pwsh 7
behaviour is unchanged. The native item 12 confirmation is still owed, but the
code no longer depends on the answer.

## Low

- **R4-5 — the no-double-quote invariant was an assumption.**
  `ConvertTo-PsSingleQuotedLiteral` escaped single quotes (F4) and passed a
  double quote through verbatim; any input value carrying one re-tokenises the
  `-Command "..."` wrapper (R2-4 reachable again). A double quote is not
  representable in that position at all, so the builder now refuses it.
- **R4-6 — coalescer markers were forgeable from call sites, and the sample cap
  did not bind at window open.** `previous_window`/`coalescer_evictions` are
  stripped from caller-supplied details before being re-added from
  authoritative state; `kid_samples` honours `max_kid_samples` for the first
  kid of a window, not only the later ones.
- **R4-7 — two false-refusal/cosmetic edges.** A whitespace-padded
  `modules=" httpPlatformHandler "` (valid to IIS) was refused by exact
  compare; and the template-null-terminator strip in Get-OfficerRights.ps1 had
  its own descending-range edge (`0..-1` is `(0,-1)`, so a 2-byte all-zero
  blob kept its terminator).

## Test findings

- **`test_a_live_window_survives_below_the_cap` still did not detect its named
  mutation** — the third version in a row. The clock lapse added in round 3
  gave the sweep something to destroy, but `previous_window` is captured
  *before* eviction, so the hand-off assertion survives the mutation. What the
  unguarded sweep actually adds, below the cap, is a `coalescer_evictions`
  stamp on the reopened row — asserting its absence is the detection. The test
  now says so.

## Mutation verification (round 4)

Python: reason_code dropped from the mismatch call site; marker-stripping
removed; open-time sample cap reverted; under-cap early return deleted — all
detected. PowerShell: `return @()` reverted to `$null`; double-quote guard
disabled; ALLOW_FAKE name removed from the list; CRL pin removed; `modules`
`.Trim()` removed — all detected. One PowerShell mutation initially ran as a
parse error (it removed the last element of the forbidden array, leaving a
trailing comma) and was re-run surgically so the proof is behavioural, not
syntactic.

## Carried forward, unchanged

- `-SitePath` ancestor-chain provenance (native item: the `C:\inetpub` chain
  survey on the lab host).
- The `stop apppool`/`list wp` `2>$null` on the stop-and-prove path (bounded
  by `Test-AppPoolWorkersGone` failing closed on unclassifiable output; the
  probe redesign of R3-1 covers the decision point).
- The duplicate site-tree ACE on re-runs, and the coalescer's global lock
  across SQLite I/O (both documented in round 2's "not changed" section).

## Native cases owed, added to the running list

13. `Get-OfficerRights.ps1` against a truncated/no-DACL `OfficerRights` value
    (a lab-safe stand-in: point it at a CA config whose value is cleared)
    prints "no callback ACEs" and exits 1 — never "Found 1 ACE(s)".
14. The `net stop`/`net start` fallback path in `Set-OfficerRights.ps1` (stop
    certsvc by hand first, force the catch) completes on 5.1.
15. A failing `certutil -revoke` (unknown serial, say) under 5.1 relays the
    certutil exit code, confirming `Invoke-CertUtilCapture` holds — the
    documented item 12, now a confirmation rather than an open risk.

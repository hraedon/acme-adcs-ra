# Security review - Daybreak round 6 (2026-08-16)

Scope: independent validation and remediation of Daybreak's repository review
of `d1d7c17`. The report found seven issues: four high and three medium. All
seven are valid. The application issuance path remained strong; six findings
were one installer trust-boundary problem, and the seventh was a missing
durable account-cardinality invariant.

Source verification after the changes: 807 pytest passed, 1 skipped; 264 Pester
passed, 1 skipped; ruff and mypy clean. This is not a live Windows proof. The
installer changes are not pilot evidence until the exact tip completes the
native cases listed below.

## Design decision

The previous rounds repeatedly tried to prove a pathname safe after exposing or
reopening it. This round uses three construction rules instead:

1. A fresh directory is born with its final protected DACL. There is no
   create-then-lock interval and therefore no create-capable handle to revoke.
2. Privileged inputs move into a namespace with an explicit writer allowlist
   before they are built, verified, or executed. Familiar-principal denylists
   are gone from provenance decisions.
3. A durable resource limit is checked in the transaction that creates the
   resource. Route-level checks are not security controls.

## Finding 1 (high) - named writer ACEs bypassed provenance

Confirmed at `InstallVerifyLib.ps1`'s former `BroadTrusteeSids` gate. An allow
ACE granting FullControl to an arbitrary named user or custom group returned
safe before its rights were examined. Both the interpreter chain and preserved
site tree consumed that answer.

Fixed by resolving every write-capable ACE identity to a SID and accepting it
only when that SID is an authorized writer (Administrators, SYSTEM,
TrustedInstaller, and the invoking administrator where appropriate). An
unresolved dangerous identity fails closed. Tests include arbitrary named-user
and named-group FullControl/write cases.

## Finding 2 (high) - mutable repository source built elevated

Confirmed. The installer dot-sourced `InstallVerifyLib.ps1`, read dependency
locks and `web.config`, and invoked PEP 517 on `$repoRoot` without proving that
another principal could not modify the tree.

Fixed in two stages. A small inline bootstrap checks the owner, reparse status,
and write ACEs of every consumed input and its ancestor chain before any sibling
code is loaded. After the managed roots are established, those inputs are copied
to a fresh administrator-only snapshot under `%ProgramFiles%`; dependency locks,
the project build, and the IIS template are consumed only from that snapshot.
The script itself remains the operator-selected trust anchor, so the operator
contract now requires an administrator-only local release tree.

## Finding 3 (high) - `-InstallPrereqs` executed PATH programs

Confirmed for bare `py`, `python`, and `winget`. The later interpreter chain
gate did not protect the earlier prerequisite probes.

Fixed by removing Python package-manager execution from `-InstallPrereqs`.
Python 3.12+ must be installed separately. The ordinary discovery path accepts
only `Application` commands with an absolute source, checks the executable and
ancestor ACL/owner chain, and then invokes that exact path. Native installer
tools use absolute System32 paths.

## Finding 4 (high) - fresh-root handles survived lockdown

Confirmed. `New-Item` exposed the fresh root under inherited permissions;
`Set-ObjectProtectedDacl` then ran `/reset` before protection. A low-privilege
process could open a create-capable directory handle during either interval,
retain it after the DACL changed, wait until the emptiness check passed, and
plant `acme-ra.env` or `web.config` later.

Fixed with `CreateDirectoryW` and a self-relative `DirectorySecurity` descriptor
passed through `SECURITY_ATTRIBUTES` in the creation call. Runtime, state, site,
source-snapshot, and MSI-staging directories use this primitive. Existing-path
collisions are reported separately and re-verified/refused. Fresh paths never
run `/reset`; owner normalization occurs only after the protected DACL exists.

## Finding 5 (medium) - Win32 path aliases collapsed roots

Confirmed for non-existent components ending in a period or space. The lexical
tail survived canonicalization although ordinary Win32 consumers normalize the
name, allowing strings classified as disjoint to address one object.

Fixed by accepting ordinary absolute local DOS paths only. UNC, device and
extended namespaces, ADS syntax, dot segments, forward-slash spellings,
reserved device names, drive roots, and trailing-period/space components are
refused. Existing ancestors still use kernel final-path resolution, and the
runtime/state relation is recomputed after the runtime object exists and before
any state Modify grant can be applied.

## Finding 6 (medium) - MSI verification was not bound to execution

Confirmed. Hashing, Authenticode verification, and `msiexec` each reopened a
caller-controlled pathname.

Fixed by requiring an out-of-band SHA-256 for local and HTTPS sources, copying
or downloading into a fresh administrator-only staging directory, and checking
the staged file's digest, Authenticode status, and publisher. Only the staged
path reaches the absolute `%windir%\System32\msiexec.exe` path, and it is removed
after the child exits.

## Finding 7 (medium) - one EAB credential created unlimited accounts

Confirmed. Account idempotence was by JWK, so a valid kid could supply fresh
keys indefinitely and commit one account plus one audit row per request.

Fixed with `max_accounts_per_eab_kid` (default one). The store executes
`BEGIN IMMEDIATE`, counts every account row for the verified kid (including
deactivated rows), and either inserts the account and audit together or raises
`EabAccountLimitExceeded`. Concurrent distinct keys cannot exceed the limit;
deactivation cannot recycle durable capacity. Repeated quota denials use the
existing bounded account-denial coalescer.

## Adjacent variants closed

- Python probe output and `secedit` policy files no longer use caller-selected
  `%TEMP%`; they live in the protected installer scratch directory.
- Elevated native utilities used by the installer resolve to absolute System32
  paths rather than ambient PATH entries.
- A pre-existing site root is explicitly refused when the root itself is a
  reparse point; the child walk alone did not establish that.

## Native proof required before pilot

Run on Windows PowerShell 5.1 and the deployed host shape, on the exact commit:

1. A standard-user process loops opening create-child handles while each fresh
   root is created. It must never obtain one; no post-lock handle-relative plant
   may succeed.
2. Named user and custom group write ACEs on Python/source/site ancestors are
   refused, while the normal Program Files and gMSA RX paths pass.
3. Trailing-dot/space, dot-segment, ADS, device, 8.3, junction, UNC, equal, and
   nested root spellings are refused before the state grant.
4. PATH-first marker `py`, `python`, and `winget` programs are never executed.
5. A writable checkout is refused before the helper loads; a trusted checkout
    builds from the protected snapshot and survives mutation attempts against
    the original after snapshot creation.
6. Local and downloaded MSI source paths are replaced during verification; no
    replacement bytes reach `msiexec`.
7. Repeat the complete clean install, reinstall, rollback, migration, and gMSA
   HttpPlatformHandler launch proof. Partial/delta proof is insufficient.

Until those pass, the design is source-reviewed and test-clean, not pilot-ready.

## Native proof outcome (2026-08-16, tip `8964eba`)

Executed on the lab RA host under Windows PowerShell 5.1; see the validation
log entry in `pre-pilot-checklist.md` for the full tally. Items 1–5 and 7
passed (item 1 **after** the run found and fixed one more defect, below).
Item 6 is Pester-proven and source-ordered but was not live-executed: the
lab host already has HttpPlatformHandler installed and the DLL-presence
fallback short-circuits the MSI path; forcing the case would have required
hiding a production DLL. That single native case remains owed.

### Finding 8 (high, live-found) - the mid-install re-assert re-opened the root

The round-6 atomic creation covers a root's birth only. The post-build state
re-assert (and the claim's existing-tree branch, and the runtime re-assert)
then ran `icacls /reset` on the ROOT, which replaces the protected DACL with
the inherited one until `/inheritance:r` restores it a moment later.
`%ProgramData%` grants `Users (CI)(WD,AD,WEA,WA)`, so during that interval a
standard user can create content in the state root. A looping standard-user
process achieved exactly that (3 successes in 43,701 attempts; the post-claim
proof caught the plants and aborted the install, so nothing was adopted, but
the write itself is the thing the round-6 design says must be impossible). A
deterministic `/reset` probe confirmed the window: writable-by-standard-user
flips True between `/reset` and `/inheritance:r`.

Fixed on `8964eba`: roots are never `/reset` mid-install.
`Reset-TreeChildrenToInherited` resets descendant subtrees only;
`Set-ObjectProtectedDacl -SkipReset` re-asserts the exact protected shape
with no unprotected interval. The dotenv keeps its explicit-ACE-stripping
`/reset` (a preserved *file* may carry attacker ACEs; a root proven ours
cannot). Mutation-verified Pester coverage added; the live race re-run after
the fix measured 0 successes in 43,920 attempts with the install green.

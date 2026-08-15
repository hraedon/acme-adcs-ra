# Design: separating code from state in the Windows install

**Status:** current architecture, 2026-08-15. Supersedes the adoption model
that produced the findings in `security-review-2026-08-19.md`,
`security-review-2026-08-15-daybreak.md`, `-rescan.md` and `-rescan-2.md`.

This is not a response to a review finding. It is a response to the *shape* of
four consecutive rounds of them.

## The pattern that prompted it

Eight installer findings landed across four review rounds. Five of them were
defects in the previous round's fix:

| Mechanism | Introduced by | Findings it produced |
|---|---|---|
| `icacls /inheritance:r` claim | the 2026-08-19 F1 fix | Daybreak F1 — strips only *inherited* ACEs |
| `takeown /r` + `icacls /t` | the Daybreak F1 fix | rescan F2 (child junctions), rescan-2 F2 (`takeown` has no `/L`) |
| the read-back proof | the Daybreak F1 fix | rescan-2 F3 (root-only owner check) |
| `python.manifest.json` | the rescan F1 fix | rescan-2 F1 (a manifest in the namespace it describes authenticates itself) |
| HKLM manifest anchor | the rescan-2 F1 fix | — (deleted here before it could) |

Meanwhile the application side converged: new app-side findings ran 4 → 3 → 0 →
0 across the same rounds. The churn was entirely in ~900 lines of PowerShell
that CI never executes.

Every one of those mechanisms was an attempt to make it safe to **adopt** a
directory that a local user might have created first. Each layer was sound in
isolation and wrong as a strategy, because the premise underneath never changed.
The reviewer said so three times, in three separate reports — "quarantine it and
create a fresh secured root", "stage an immutable fresh runtime", "create a new
Administrator-only runtime directory … then atomically replace" — and each round
added a check instead.

## The two changes

### 1. Executable content leaves `%ProgramData%`

The default DACL on `%ProgramData%` grants `Users` *create folders / append
data*, with `CREATOR OWNER` inheritance supplying Full control over whatever
they create. That is the entire precondition for the planted-tree family of
findings: `C:\ProgramData\acme-adcs-ra` is predictable, and a non-administrator
can own it before the first install.

`%ProgramFiles%` grants `Users` read and execute. A non-administrator cannot
create `C:\Program Files\acme-adcs-ra` at all.

So the install is now two trees:

| | Code — `-RuntimeDir` | State — `-InstallDir` |
|---|---|---|
| Default | `%ProgramFiles%\acme-adcs-ra` | `C:\ProgramData\acme-adcs-ra` |
| Contents | interpreter, venv (under `current\`) | audit DB, logs, `acme-ra.env` |
| gMSA rights | read + **execute** | **modify** (dotenv: read) |
| Executed | yes | never |

The second half is as important as the first. The gMSA needs write access to
the database and the log; it used to get that over one tree that also held the
interpreter it runs as, so a compromised app pool could rewrite its own
interpreter (rescan-2 F3). Now the only thing it can write is data that is
never executed.

### 2. A root is proven ours, or refused

There is no force-claim path left. `Get-RootProvenance` answers `absent`,
`ours` or `foreign`, and `foreign` stops the install with
`Get-ForeignRootRefusal` — a message that names what disqualified the
directory, which files are worth rescuing, and the order to do it in.

"Ours" is defined by `Get-InstallTreeViolations`, which is the *same* function
that proves the lockdown at the end of an install. One definition, two callers
with opposite reactions to the same evidence: the post-claim proof throws on a
violation, the pre-flight reports one. They cannot drift, which matters because
drift between "what we leave behind" and "what we demand next time" would make
every reinstall a refusal.

This also closed a path no review had reported. The installer preserves
`acme-ra.env` no-clobber across reinstalls. A pre-created state directory with
a planted dotenv therefore got **preserved and ACL'd** rather than rejected —
and that file carries `ACME_RA_EAB_ALLOWLIST` and `ACME_RA_SAN_SCOPES`, which
decide who may enrol and for which names. Under the new rule the tree does not
qualify as ours, so the install refuses before reading it.

## What this deleted

- `python.manifest.json`, `Save-TreeManifest`, `Get-TreeFileHashes`,
  `Test-TreeManifestMatches`
- `Test-TreeManifestAuthentic`, `Get-TreeManifestAnchor`,
  `Set-TreeManifestAnchor`, `Get-ManifestAnchorValueName`, `Get-FileSha256`,
  and the `HKLM\SOFTWARE\acme-adcs-ra` key
- `Test-DestinationInterpreterTrusted`
- the destination-interpreter reuse branch, the shared-Python rebuild branch,
  and the delete-the-venv-first dance

All of it existed to answer one question — *may I reuse the bytes already
sitting there?* — which no longer arises, because the runtime is built from
scratch on every run in a location where nothing can pre-plant bytes.

## What this kept, and why

Honesty about the remaining surface matters more than a bigger deletion count.

- **Ownership normalisation** (`Reset-TreeToInherited`, now `icacls /setowner
  … /L`). Still needed: on Vista and later, a file created by an administrator
  is owned by that *account*, not the Administrators group, so a freshly-built
  tree fails its own owner check without it.
- **The reparse walk and the read-back proof.** Now applied only to directories
  this installer created moments earlier — so rescan F2's raced junction and
  rescan-2 F3's hostile descendants have no premise — but a proof of what we
  just built is still worth having, and it is exactly what the next run's
  pre-flight consumes.
- **The app-pool stop-and-prove-dead step**, unchanged. Handle-based access
  survives an ACL reset; killing the worker first is the only thing that
  addresses it.

## Rollback and the venv-relocation trap

The runtime is retired with an atomic directory rename, rebuilt at the *final*
path, and the retired copy is deleted only after the new tree passes its proof.
A failed build restores the retired runtime, so a failed upgrade leaves the host
serving what it served before.

It is built in place rather than staged elsewhere and renamed in, which is the
more obvious design, because **a venv is not relocatable**: `pyvenv.cfg` records
an absolute `home`, and every console-script `.exe` under `Scripts\` embeds the
absolute path of the interpreter that created it. A built-then-renamed venv is a
runtime whose `python.exe` cannot find its own stdlib. The window in which no
runtime exists is safe because the app pool is stopped and proven dead first.

## What is still unproven

Everything here is unexecuted PowerShell, on a project whose record says that is
where defects escape. Before any tag:

- a live install on a clean host, and a live *re*install over the result
- a refusal run: pre-create both roots as a non-administrator and confirm the
  installer refuses each with actionable output
- a rollback run: fail the build deliberately and confirm the previous runtime
  comes back
- the gMSA read+execute grant actually letting HttpPlatformHandler launch
  uvicorn — `RX` on the runtime tree is a narrower grant than the old `M`, and
  it is the single most likely thing to be subtly wrong
- the migration path in `operator-requirements.md` §4, walked end to end

`samples/lab-validation-runbook.md` and `samples/lab-harness/` are the starting
point; Pester 5.7.1 and Windows PowerShell 5.1 are on `mvmcitest01`.

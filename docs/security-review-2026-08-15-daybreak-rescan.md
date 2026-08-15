# Security review — Daybreak 2026-08-15 rescan (iteration 2)

Scope: Daybreak's re-review of `07bec69` — the first Daybreak-fix iteration.
Verdict: "Do not deploy or release this iteration yet." Three findings: one
high, one medium, one low (the standing WI-014). The account/keyChange audit
transactions and the switch-only registration were confirmed fixed.

**Both actionable findings are fixed.** WI-014 remains deferred (third
consecutive review to carry it; still the same operator-owned retention-policy
question — see the first Daybreak review for the reasoning). Suite:
**773 pytest + 1 skipped** (unchanged — both findings are installer-side),
Pester 170 → **184**, ruff and mypy clean.

## Finding 1 (high) — the ACL lockdown protected future writes; it did not authenticate the bytes already there

Two instances, one root cause: "we secured the namespace, therefore its
contents are ours" — which is false twice over. First, a tree that
**pre-existed** the install could contain anything; the lockdown re-ACL'd
those bytes but preserved, preferred, and then **executed** them. Second, even
a genuinely-ours tree is writable by the **gMSA** (the app pool needs Modify
to run), so a compromised app pool can rewrite the interpreter between runs
and the next elevated install will "trust" it.

- `install-windows.ps1:339` — a destination-local `python\python.exe` was the
  FIRST launcher candidate whenever `Test-DestinationInterpreterTrusted`
  passed (root secured, not a reparse point) — i.e. exactly the planted-bytes
  case the finding describes.
- The venv: `python -m venv` over an existing directory **without `--clear`**
  refreshes its own files and leaves everything else — so a planted
  `.pth`/`sitecustomize.py` survived every "rebuild" and executed on each
  elevated `pip` invocation. (The reviewer's "existing venv startup code is
  similarly retained.")

**Fixed** by making executed bytes authenticate, per source:

- **Shared interpreter — manifest or nothing.** The whole `python\` tree is
  SHA-256-manifested (`python.manifest.json`, a sibling) at build time, and
  the manifest is DACL-protected to Administrators/SYSTEM **only** — the gMSA
  can rewrite the interpreter but not the document that vouches for it.
  `Test-TreeManifestMatches` is strict set-equality: a tampered file, a
  planted file, a deleted file, or a missing/corrupt manifest all fail. A
  destination-local interpreter enters the launcher list **only** after
  passing; anything else is deleted on the spot and (if needed) rebuilt from
  the authenticated `py install --target`/system-interpreter path, then
  freshly manifested. Pre-fix trees carry no manifest and therefore fail
  closed. The second ACL pass re-protects the manifest, because the tree-wide
  `/reset` strips its protected DACL back to inheritance.
- **Venv — deleted and rebuilt every run.** `Remove-Item -Recurse` (after a
  reparse walk) before `python -m venv`; no planted startup file can survive
  a run. Cost is nil — the pinned closure was already reinstalled every run.

Manifest machinery lives in `InstallVerifyLib.ps1` (`Get-TreeFileHashes`,
`Save-TreeManifest`, `Test-TreeManifestMatches`) and is round-trip tested on
Linux (Get-FileHash is cross-platform) against exactly the attacker shapes:
tampered `python.exe`, planted `sitecustomize.py`, deleted manifested file,
corrupt and missing manifests.

## Finding 2 (medium) — child reparse points escaped the ACL boundary

Only the **root** was checked for reparse status; the recursive primitives
behind the lockdown — `takeown /r` and `icacls … /t` — **traverse** child
junctions/symlinks (icacls needs `/L` to operate on the link itself; takeown
has no `/L`). So a junction planted in a pre-created tree redirected the
elevated ownership/ACL rewrite **outside the install directory**. Notably this
is a hazard the *first* fix introduced: the old one-line claim never recursed.

**Fixed** with a refuse-don't-traverse policy plus link-safe flags:

- `Find-ReparsePoints` — a manual, level-by-level .NET walk that **never
  descends into a reparse point** (`Get-ChildItem -Recurse` cannot be used:
  it follows junctions on Windows PowerShell 5.1, which is the exact behavior
  this exists to avoid). A subdirectory that cannot be enumerated (deny ACE)
  is itself a refusal — an uninspectable tree is not a tree to operate on.
- `Assert-NoReparsePoints` runs before **every** recursive privileged
  operation (both ACL passes' `takeown`/`icacls /reset`, the venv delete, the
  unverified-python delete), and `Assert-InstallTreeLocked` re-walks as a
  post-condition.
- `icacls` now carries `/L` on both `/reset /t` and `/save /t`, so the tool
  with the flag available never follows a link for either the writes or the
  read-back proof.

**Residual, documented:** `takeown` has no `/L`, so a junction planted into
the millisecond window between the pre-walk and `takeown` could in principle
be traversed before the post-walk aborts the install. The static case is
impossible (pre-walk refuses), the escape is detected (post-walk), and the
install never proceeds past a detected link — but the traversal itself, if
raced, is not prevented. Closing that fully means dropping `takeown` for
per-object ownership via .NET with manually enabled privileges; recorded as
acceptable-for-now rather than silently assumed fixed.

## Finding 3 (low) — WI-014, unchanged

Unauthenticated `newAccount` denials still grow the audit store/JSONL without
bound (`routes/accounts.py:142`). Deliberately deferred again: the fix is a
retention policy on a security log, not a code patch. The SIEM leg is already
bounded (v1.9's capped HEC queue); the local-store growth remains the open
part, tracked as WI-014.

## Observability

- CI previously triggered only on `main`, so this branch's commits built
  nothing (the reviewer noted the missing check run). `push` now also matches
  `security-review-*`: review-cited hashes get built from the moment they are
  pushed.
- **The live install proof is still owed.** Linux CI executes neither
  `takeown` nor the read-back proof nor the manifest dance against a real
  Windows filesystem, and the 2026-08-14 round already proved that gap lets
  broken installers sit green on `main`. The next re-proof must include a
  fresh install into a **pre-planted** tree (planted `python\python.exe`,
  planted venv `.pth`, child junction) and show refusal/rebuild/abort
  behavior. Recorded in AGENTS.md and on the next re-proof's list.

## Verification

- 773 passed, 1 skipped (pytest — the two account-atomicity suites are
  unchanged and still mutation-verified); 184 passed (Pester, incl. the new
  manifest round-trip and installer-authentication suites); ruff and mypy
  clean.
- Manifest functions round-trip verified live on the dev box (clean tree
  verifies; tampered/planted/missing-manifest all fail with the expected
  reasons).
- Installer and lib parse clean on both `pwsh` 7 and (syntactically) Windows
  PowerShell 5.1 targets; behavioral proof on 5.1 remains part of the owed
  live run.

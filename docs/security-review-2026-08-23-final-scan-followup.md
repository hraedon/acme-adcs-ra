# Security review follow-up - final whole-repository scan (2026-08-23)

## Scope

A whole-repository static review of local `main` at `0b0f5a0` reported six
findings: five medium and one low. The review was offline and partial, so every
finding was traced through the deployed call path before remediation. All six
were confirmed and fixed in `2d02a70`.

This document contains placeholders only. Lab-specific hosts, CA identifiers,
credentials, certificate serials, and transcripts remain in the gitignored
`samples/` companion and the session scratch directory.

## Remediations

### 1. Finalize authorization is revalidated at the CA boundary

Finalize now carries the RFC 7638 thumbprint of the exact account key that
verified the request. Immediately before ADCS submission it re-reads and
requires all of the following:

- the account still exists and is valid;
- the current key still has the authenticated thumbprint;
- the account's EAB kid is still allowlisted; and
- the worker still holds the order's processing-generation lease.

Account deactivation and `keyChange` share an account-scoped process lock with
the final check and ADCS call. This gives the supported single-process server a
linear order without holding a SQLite write transaction over network I/O: a
mutation that commits first blocks submission, while a submission that takes
the lock first finishes before the mutation commits. A blocked submission
returns the order to `ready` under its lease and audits the abandoned attempt.

### 2. Certsrv work has a bounded, isolated lifetime

The certsrv leg now applies one monotonic deadline across the complete
`certfnsh.asp`, leaf-certificate, CA-renewal, and PKCS#7-chain sequence. Each
HTTP timeout is clamped to the remaining budget. A watchdog aborts a live body
read at expiry, including the Winsock close required to wake a Windows reader,
and every response is closed on all exits. Failures after CA issuance retain
the ReqID, leaf, and chain already obtained so finalize can quarantine rather
than orphaning the certificate.

Enrollment no longer consumes Starlette's shared worker pool. A dedicated
executor bounds both running and admitted work, sheds excess admission, and
does not cancel an admitted operation during request cancellation or shutdown.
That last property is required because abandoning a worker after CA issuance
would skip the RA's durable completion or quarantine step.

New settings:

- `ACME_RA_ADCS_ENROLLMENT_TIMEOUT_SECONDS`
- `ACME_RA_ADCS_ENROLLMENT_TOTAL_TIMEOUT_SECONDS`
- `ACME_RA_ADCS_ENROLLMENT_MAX_WORKERS`
- `ACME_RA_ADCS_ENROLLMENT_MAX_PENDING`

Configuration refuses a total deadline below the socket timeout and an
admission ceiling below the worker count.

### 3. CSR application purposes fail before issuance

If a CSR contains standard Extended Key Usage, its set must be exactly
`serverAuth`. `clientAuth`, anyExtendedKeyUsage, PKINIT, and mixed sets are
rejected before the enrollment leg is called. A CSR with no EKU remains
accepted because the restricted ADCS template supplies the extension.

Microsoft Application Policies (`1.3.6.1.4.1.311.21.10`) is an alternate ADCS
application-purpose request. `cryptography` exposes it as an unrecognized
extension, so the RA rejects its presence instead of pretending to have parsed
the embedded policy set. Post-issuance EKU verification remains in place as a
second boundary.

### 4. The installer proves the Python runtime closure

The elevated installer previously proved `python.exe` and its ancestor chain,
but Python loads sibling DLLs, the standard library, `.pth` files, and site
initialization before producing the first version-probe output. It now proves
the complete interpreter tree before the first execution:

- every runtime object has an authorized owner and no unauthorized writer;
- the tree and its ancestor chain are trusted;
- reparse points are refused before any recursive walk;
- a venv extends the proof through `pyvenv.cfg` to its base runtime; and
- unreadable or incomplete `pyvenv.cfg` metadata fails closed.

The `py` launcher is no longer a candidate because probing it executes the
selected interpreter before that interpreter can be identified and proven.
Direct `python.exe` and `python3.exe` candidates are resolved once to exact
Application paths and the proven path is retained for later execution.

### 5. Inbox PowerShell commands have pinned provenance

The installer no longer treats successful `Get-Command` resolution as proof
that an expected cmdlet exists. It imports the expected inbox module by absolute
path from a Windows directory derived from machine/OS state, not the inherited
process environment. Before import it proves the module tree and ancestor chain
and refuses reparse points.

Commands must be Cmdlet or Function exports from the expected module under the
trusted module root. Resolution uses the imported module's own export table,
not global command lookup order. PATH Applications, scripts, aliases,
same-named foreign modules, and prefix-matching paths are rejected. The checks
cover the IIS, ServerManager, and ActiveDirectory commands used by the
installer; existing skip/warning behavior remains when a trusted module is not
available.

### 6. Manual revocation sync no longer accepts bearer values on argv

`Sync-Revocations.ps1` changed `-AdminToken` and `-ConfirmToken` from string
parameters to switches. Token values are read only from `ACME_ADMIN_TOKEN` and
`ACME_CONFIRM_TOKEN`; a selected but absent variable fails before network I/O.
Examples now set the environment first and pass only a bare switch. The
registered-task path remains compatible because it already loads the protected
dotenv into the environment at run time.

This intentionally removes the old direct `-AdminToken <secret>` and
`-ConfirmToken <secret>` interfaces. They exposed credentials in process
listings and shell history and had no safe compatibility reason to remain.

## Review and local verification

The fixes received independent adversarial application, PowerShell, and final
integration reviews. Follow-up changes closed a `py` launcher pre-probe gap,
made admitted enrollment drain safely at shutdown, prevented an unexpected
socket-wrapper exception from skipping the Windows close, made
`pyvenv.cfg` failures refuse a partial proof, and bound command selection to
the imported module's export table. No high or blocking source finding remained.

Local gates on `2d02a70`:

- Python: 925 passed, 1 skipped;
- Pester: 424 passed, 4 platform skips;
- Ruff: clean;
- mypy: clean across 34 source files; and
- `git diff --check`: clean.

The security tests were mutation-checked across the account predicates,
deadline clock, executor admission/cancellation, CSR EKUs, interpreter closure,
module provenance, command selection, and token parameter shape.

## Live Windows, IIS, and ADCS proof

Executed 2026-08-23 against the exact code commit `2d02a70` on the lab RA and
issuing CA.

The Windows PowerShell 5.1 installer exited 0 while exercising the new
interpreter-tree and trusted inbox-module gates against the host's real
user-scoped Python, IIS/WebAdministration, ServerManager, and ActiveDirectory
installation. It rebuilt the protected runtime, installed the hash-pinned
dependency closure, preserved the state tree, verified `web.config`, restarted
the gMSA app pool, and returned `/directory` 200.

Application results:

- issuance, EKU, SAN, chain, CA denial, and revocation-reason controls: 14/14;
- ACME front controls: 13/13;
- key-rollover ceiling/state/audit: 12/12;
- both post-issuance transport-orphan branches: 6/6 each;
- task-driven CA revocation and queue drain: 5/5 plus 3/3 verification;
- least privilege: gMSA token succeeded, CRL publication was denied, an
  out-of-template revocation was denied with restricted-officer, and reason 8
  was refused before CA action;
- authority split: admin-only revoked but could not confirm, while confirm-only
  recovered the already-revoked row and drained it; and
- CRL evidence first failed closed while the serial was absent, then succeeded
  after publication with audit verification `crl-verified`.

The shipped default CRL freshness ceiling still does not cover the lab CA's
7-day-plus-overlap publication window. That expected calibration failure is the
existing WI-052, not a regression in this change.

The first CRL-evidence retry used a stale gitignored wrapper that still named
the retired ProgramData script tree and a placeholder token. It failed before
the RA and was not accepted as evidence. The registered task, which loads the
credential from the protected dotenv and runs the deployed script tree, produced
the fail-closed and successful `crl-verified` results above. A second CA
publication was required because the first generated CRL did not yet contain
the just-revoked serial.

Teardown was verified:

- all seven certificates caused by the run, including the ReqID-only orphan,
  were selected at CA disposition 21;
- the CRL was republished;
- CA security returned to 224 bytes and four ACEs with `OfficerRights` absent;
- IIS request-filter deny sequences were empty;
- the RA database restored with `integrity=ok` and every table count identical
  to the pre-run fingerprint;
- throwaway credentials were absent; and
- the app pool returned to `Started` with `/directory` 200.

## Residual proof limits

The full native run proves the changed installer and the ordinary issuance and
revocation paths. The deliberately timed account-mutation race and a synthetic
TLS trickle were not injected into the live CA path; their ordering and deadline
properties are covered by deterministic, mutation-sensitive tests. A
same-named foreign inbox module preloaded under Windows PowerShell 5.1 also
remains a live availability calibration case; provenance fails closed if the
trusted export cannot be selected.

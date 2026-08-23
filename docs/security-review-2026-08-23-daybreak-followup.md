# Security review follow-up — Daybreak (2026-08-23)

Scope: independent verification and remediation of the three findings reported
against `5654360` on `security-review-2026-08-15-daybreak`.

## Branch reconciliation

The named August 18 and August 19 review branches are already ancestors of the
Daybreak branch. A wholesale merge from either would add nothing; comparing the
tips in the opposite direction misleadingly looks like a large deletion because
the current branch has substantial later hardening. The intended merge is the
Daybreak branch, with these fixes, into `main` after validation.

## Finding 1 — concurrent key-change overwrite — fixed

The report was correct. Route validation compared `oldKey` with an account
snapshot, while the transactional update was guarded only by account ID.

The authenticated old-key thumbprint now reaches
`Store.update_account_key_with_audit`. One `BEGIN IMMEDIATE` transaction:

1. re-reads the account and requires the same thumbprint and `valid` status;
2. evaluates the per-EAB rollover ceiling;
3. updates with ID, expected thumbprint and status in the SQL predicate;
4. requires exactly one changed row; and
5. writes the success audit before commit.

A stale request returns ACME `unauthorized` and writes no success event. A
new-key uniqueness race returns `badPublicKey`, not an internal error.

Proof includes two coordinated SQLite writers authorized by one old key,
concurrent deactivation, a real unique-index conflict, route error mapping and
the existing success/rate-limit/atomic-audit tests. Removing the compare-and-swap
made both race tests fail.

## Finding 2 — CRL DNS pin was not the connection target — fixed

The report was correct. The old code compared separate resolver results and
then passed the hostname to `requests`, which resolved again.

CRL retrieval now resolves once, fails closed on an empty result, and connects
the urllib3 pool to a selected numeric address for the initial request and every
redirect. The URL hostname remains:

- the HTTP `Host` header;
- TLS SNI; and
- the TLS certificate hostname-verification target.

Redirect authority rules remain same-host/same-port with the documented
HTTP-to-HTTPS default-port upgrade. Private/internal destinations remain valid:
internal CDPs are the expected deployment shape, so destination ranges belong
to operator network policy rather than a blanket application denylist.

The pin requires direct transport. Environment HTTP proxies are not used because
the proxy would perform its own DNS lookup and connection, recreating the defect.
`requests>=2.32` is explicit because the adapter overrides that release line's
TLS-aware connection-selection API.

Proof uses real sockets for initial and redirected HTTP requests and a generated
local CA for an HTTPS handshake. It verifies one hostname lookup, numeric-address
connection, preserved Host and SNI, acceptance of the configured hostname, and
rejection of a different hostname. Mutating the transport back to the hostname,
or binding TLS verification to the numeric address, makes the tests fail.

## Finding 3 — configured retention never ran — closed by refusal

The report was correct that `run_sweep` had no production caller. Its proposed
warning not to wire the current function unchanged is also correct:

- a generic SIEM health probe is not proof that every candidate row was
  delivered, especially with bounded asynchronous queues;
- deletion and `audit-retention-swept` currently commit separately; and
- the sweep event is not exported off-host.

`audit_prune_enabled=true` is therefore rejected during configuration validation,
with a second composition-root check for validation bypass. This deliberately
does not claim that cumulative local audit growth is now bounded. It removes the
false promise and prevents unsafe evidence deletion. Operators must keep the flag
false and continue capacity monitoring/archival; retention-floor checks,
footprint warnings, denial coalescing and JSONL rotation remain available.

Future pruning requires acknowledged per-row archive delivery, atomic
delete-plus-self-audit, and off-host export of the sweep event before any
production caller is added.

## Verification

Local gates on the code commit `0b89af1`:

- Python: 896 passed, 1 skipped.
- Ruff and mypy: green.
- Cross-platform Pester: 368 passed, 4 platform skips.
- Mutation checks: key CAS, numeric socket target, TLS hostname binding, and
  pruning refusal each failed when its control was removed.
- Two independent post-fix adversarial reviews found no exploitable defect in
  the CAS or transport. Their valid test-gap finding produced the real TLS
  handshake test; their adapter-version finding produced the `requests>=2.32`
  floor.

### Live Windows/IIS/ADCS proof

Executed 2026-08-23 on the lab RA and issuing CA against the exact committed
artifact `0b89af1`. The brokered directory credential completed a StartTLS LDAP
preflight and found the enrollment gMSA; no credential value reached argv,
stdout or the transcript. The installer deployed version 1.9.1 and exited 0.

Results:

- issuance/EKU/SAN/chain/CA denial/revocation-reason controls: 14/14;
- ACME front controls: 13/13;
- real CRL retrieval through the new pinned transport plus POST-as-GET-only
  resources: 9 passed, with only the standing CRL-cadence calibration check
  failing as designed (649200-second validity window versus the 604800-second
  default replay-age ceiling, WI-052);
- key-rollover ceiling/state/audit: 12/12;
- both post-issuance transport-orphan branches: 6/6 each;
- task-driven CA revocation and queue drain: 3/3 after issuance/revocation;
- least privilege: gMSA token succeeded, CRL publication denied with access
  denied, out-of-template revocation denied with restricted-officer, reason 8
  refused before CA action;
- authority split: admin-only revoked but could not confirm (exit 2),
  confirm-only recovered the already-revoked row and drained it (exit 0);
- `audit_prune_enabled=true`: refused by the deployed config loader;
- CRL evidence: confirmation first failed closed with
  `crl-evidence-required-but-absent`; after publication the same registered task
  exited 0, drained the queue, and audited `verification: crl-verified`.

The first CRL-evidence attempt reported task exit 1 before reaching the RA. This
was a stale lab wrapper, not product behavior: `sync-crl.ps1` still named the
retired ProgramData scripts path and contained literal token placeholders. The
current registered task loads the confirm credential from the ACL-protected
dotenv and produced the expected fail-closed/publish/retry sequence above. The
wrapper was not used as evidence.

Teardown was verified rather than assumed. All seven certificates caused by the
run, including the ReqID-only orphan, were revoked and selected under CA
disposition 21; the CRL was republished; CA security returned to 224 bytes/four
ACEs with `OfficerRights` absent; IIS `denyUrlSequences` was empty; the RA store
returned to its backup fingerprint (`integrity=ok`, every table count equal);
the throwaway EAB material was absent; and the app pool returned to `Started`.
The three maintenance tasks existed before the run and were left `Ready`,
re-registered against the current protected dotenv-loading implementation.

Not exercised in this pass: the optional stale-enrollment `Lqueue`/`Ldrain`
stress phases and MSI-source replacement. They are separate accumulated live
proof debt, not paths changed by these three findings.

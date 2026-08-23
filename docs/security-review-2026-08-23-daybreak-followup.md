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

- Focused Python security tests: green.
- Mutation checks: key CAS, numeric socket target, TLS hostname binding, and
  pruning refusal each failed when its control was removed.
- Ruff and mypy: green.
- Cross-platform Pester: green (368 passed, 4 skipped).
- Full Python suite and live Windows/IIS/ADCS proof: recorded after the final
  committed artifact is deployed.

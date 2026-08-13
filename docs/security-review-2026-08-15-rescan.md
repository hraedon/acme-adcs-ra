# Security review — 2026-08-15 hardening branch, rescan

Scope: an external scan (Codex, in collaboration with Daybreak Blue) of the two
hardening commits that answered the [2026-08-15 review](security-review-2026-08-15.md)
— `5468e0f..f1fd80a`, a diff-scoped review of the changed security behaviour and
the order, store, authentication, enrollment, deployment, test and policy code
supporting it. **One reportable finding: medium, high confidence.** Four other
reviewed surfaces came back clean (JWK/RSA bounds, resource retrieval,
revocation-task credential separation, and the removed legacy GET config).

This scan is the first of the series to arrive with a **working reproduction**
rather than a source-only hypothesis: a focused pytest against the exact reviewed
source that drove a reclaim to 200 and then reached the enrollment interface
twice for one order. It was re-run here before anything changed, and it holds.

Baseline at review time: 599 Python tests + 1 skipped, 22 TaskAction Pester
tests, `ruff` and `mypy --strict` clean. After the fix: **612 Python tests + 1
skipped**, 22 Pester, `ruff` and `mypy --strict` clean.

## The finding

### Queued enrollment remains reclaimable before the active marker is set

Confirmed, and the scan's root-cause analysis is exactly right. The
`ActiveEnrollments` registry introduced by the previous review was placed
**inside the worker**, in `_finalize_submit_enrollment`. That put its lifetime
strictly *inside* the interval it was supposed to protect:

```
finalize route            ready→processing CAS ─┐
                                                │  ← unmarked: task queued
worker (threadpool)                             ├─ [ enrolling(order_id) ]
                                                │  ← unmarked: worker returned
finalize route            _finalize_complete ───┘     but no cert row yet
```

Two gaps follow, and in both of them the reclaim endpoint's checks are all
*truthfully* satisfied — there is no live worker in the registry, there is no
certificate row, and the operator's CA check genuinely finds no issuance:

1. **The queue gap (the one the PoC drives).** `run_in_threadpool` admits a task
   to a bounded threadpool. Under load the task can sit queued well past
   `reclaim_minimum_processing_age_seconds`. The order is already committed to
   `processing`, but nothing anywhere records that a submission is pending. A
   reclaim reopens it to `ready`, the client re-finalizes, and then the original
   queued task runs — it holds the CSR, the account, and the policy decision it
   was created with, and it re-checked nothing. Two submissions, one order.
2. **The completion gap.** The mark was released when the worker returned, but
   `_finalize_complete` — which writes the certificate row — runs after that. A
   reclaim landing there sees no certificate for an order the CA has already
   satisfied.

**Root cause, in the scan's words and ours:** a security invariant that needs one
durable owner for the whole `ready → processing → terminal` interval was
implemented as a *process-local observation* of a *narrower* interval. Absence
from the registry was treated as proof that no task could still submit, and it
never was.

The severity assessment is fair. Reaching this needs a prolonged worker delay
*and* an admin-authorized, CA-checked recovery action, so it is not
client-reachable on its own — but the outcome is two domain-trusted certificates
for one order, one of which the RA cannot name and therefore cannot revoke.
That is the invariant this project exists to hold.

## The fix

The remediation the scan asked for, in both halves it asked for.

### 1. The mark covers the whole in-flight interval

It moves out of the worker and into the finalize route
(`routes/orders.py`), wrapping the CAS, the threadpool hand-off, *and*
`_finalize_complete`. There is now no point between "this order is `processing`"
and "its terminal state is durable" at which the registry says nothing is
happening. Losing the CAS simply releases the mark on the way out.

`ActiveEnrollments` is also now reference-counted rather than a set, so if two
holders for one order ever overlap, the first to exit cannot clear liveness for
the second. That should not arise — the CAS admits one finalize at a time — but
"should not arise" is the wrong strength for the thing standing between a reclaim
and a double issuance.

### 2. A durable lease, re-checked immediately before the CA is touched

The registry is process-local memory. The scan is right that memory is the wrong
place for this guarantee to *rest*, so the durable half is a new
`processing_generation` column on `orders`:

- `Store.acquire_processing_lease` replaces `transition_order_to_processing`. It
  is the only way into `processing`, and every entry increments the generation
  and returns it. The generation **never decreases** — a reclaim clears
  `processing_started_at` but deliberately leaves the counter alone, so a later
  finalize can never re-mint a generation some queued task is still holding.
- `Store.holds_processing_lease(order_id, generation)` is the revalidation: still
  `processing`, *and* still this generation.
- The finalize route carries the generation into the worker, and the worker calls
  `holds_processing_lease` **immediately before `submit_csr`**. A task that was
  queued across a reclaim finds its lease lapsed, audits
  `finalize-enrollment-abandoned` (`reason=processing-lease-lapsed`, both
  generations, and the stage), logs at WARNING, and returns the order's current
  state to its client **without calling the CA and without writing to the order**
  — it does not own it any more.
- **Every transition out of `processing` is now lease-scoped.** The worker's
  `EnrollmentDenied` revert, the transport-orphan `→ invalid`, the
  `record_issuance` success flip, the finalize self-heal, and both branches of
  the admin reclaim all pass the generation they hold or observed. That answers
  the scan's structural complaint directly: reclaim no longer reads the registry
  and mutates the store in two unrelated critical sections — its write is scoped
  to the lease its read decided against, so a lease that changed in between loses
  the CAS instead of overwriting a stale judgement.

One deliberate asymmetry: `record_issuance` still writes the **certificate row**
unconditionally and only the order flip is lease-scoped. An issued certificate is
never left untracked — that is the orphan class the 2026-08-13 and 2026-08-14
reviews closed, and a lease check must not reintroduce it. Losing on generation
audits `finalize-enrollment-race`, exactly as losing on status already did.

## Tests

`tests/test_enrollment_lease.py`, 13 tests, structured around the scan's own
test list:

| Scan's requested test | Test here |
| --- | --- |
| Queue a finalize past the reclaim floor; assert the stale worker never calls `submit_csr` | `test_reclaim_is_refused_while_the_enrollment_is_still_queued` (route level, real request in flight) + `test_a_task_queued_across_a_reclaim_never_reaches_the_ca` (durable lease, registry deliberately absent) |
| Pause after the worker returns but before `_finalize_complete`; assert reclaim cannot reopen | `test_reclaim_is_refused_after_the_ca_issued_but_before_the_cert_is_recorded` |
| Two holders for one order; one completing must not clear the other's liveness | `TestTheMarkIsReferenceCounted` |
| Mutation-test by moving lease acquisition back inside the worker | Done — see below |

The two route-level tests drive a **real** finalize request on a background
thread and pause it inside the app at the exact window, then issue the reclaim as
a real admin request from the main thread. The enrollment leg counts CA calls, so
the assertion is "the CA was never asked twice", not "the second issuance was
tidied up afterwards".

**Every test was mutation-checked.** Five mutations, each reverting one half of
the fix, all detected:

| Mutation | Tests that failed |
| --- | --- |
| Mark taken inside the worker again (the original shape) | both route-level tests (and the log line `finalize CAS lost race … cert recorded but order was moved` — the finding's own outcome) |
| No lease re-check before `submit_csr` | both stale-task tests |
| Generation predicate dropped from every `processing` CAS | reclaim-CAS scoping, lapsed-lease issuance |
| `acquire_processing_lease` does not increment | 5 tests across both classes |
| `ActiveEnrollments` back to a plain set | the reference-count test |

Three tests are deliberate positive controls rather than mutation targets
(`test_the_holder_of_the_current_lease_is_not_blocked`,
`test_a_lost_cas_mints_nothing`, `test_orders_do_not_interfere`): a guard that
refuses everything would satisfy every negative assertion above, and these are
what stop that passing.

## Upgrade impact

`processing_generation` is added by the existing orders-table migration
(`ALTER TABLE … ADD COLUMN … NOT NULL DEFAULT 0`), so an in-place upgrade needs no
operator action. Existing rows start at generation 0; the first entry into
`processing` after the upgrade mints 1. An order that is *already wedged in
`processing`* across the upgrade carries generation 0 and no lease holder, which
is the correct reading — there is no live worker after a restart, and reclaiming
it still requires the operator's `?ca_verified_no_issuance=true` assertion.
`test_an_existing_database_gains_the_column_and_starts_at_zero` pins this.

The renamed store method (`transition_order_to_processing` →
`acquire_processing_lease`) is internal; there is no API or config change, and no
new configuration.

## What remains unproven

- **Live re-proof.** No live ADCS/IIS/AD/PowerShell 5.1 execution was performed
  for this fix; it is static-plus-unit only, like the review it follows. The
  pending re-proof should exercise a reclaim against a genuinely slow enrollment
  on the real estate. Note the scan's own limitation still applies in the other
  direction: its PoC proved two calls to the enrollment interface, not two
  certificates at a real CA.
- **Multi-process deployment.** The supported deployment remains one uvicorn
  process, and the registry is per-process. The durable lease now covers the
  cross-process case for the *decisive* check (a worker in process B cannot
  submit once process A's reclaim has moved the order), but the reclaim endpoint
  would no longer see process B's in-flight mark, so it would fall back to the
  age floor plus the operator's CA assertion. Making the mark itself durable is
  the work that a multi-process deployment would require, and it is not done
  here.
- **Cross-process CA-side reconciliation** (machine-verifiable ReqID lookup)
  remains future work, as recorded in the previous review.

## Agreement with the scan

No corrections. The finding, its root cause, its severity, and its remediation
were all accurate, and the reproduction was decisive — this is the first scan in
the series where nothing had to be reclassified. The one thing worth adding is
that the *completion* gap the scan flagged as "a narrower second gap" is fixed by
the same move rather than separately: putting the mark in the route rather than
the worker closes both by construction, which is why the fix is a relocation and
not two patches.

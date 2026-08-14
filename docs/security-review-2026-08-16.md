# Security review — 2026-08-16

Scope: a full-repository external scan (Codex, in collaboration with Daybreak
Blue) of `c6b800f` — the first **repository-mode** scan since the enrollment-lease
work; the two before it were diff-scoped and could only speak to what had just
changed. Four findings: three medium, one low, none high or critical.

Baseline at review time: 612 Python tests + 1 skipped, 93 Pester, `ruff`, `mypy
--strict`, lock validation and `pip-audit` all clean. After the fixes: **620
Python tests + 1 skipped**, 93 Pester, all gates clean.

**All four are real and all four are fixed.** Nothing was reclassified,
downgraded, or argued with. Two of them are the same defect this project had
already fixed *somewhere else* and missed here, which is the most useful thing
the scan surfaced.

## Finding 1 (medium) — synchronous CRL retrieval on the event loop

`confirm_ca_revocation` is `async def`, so FastAPI runs it **on** the event loop,
and it called `_crl_evidence_for` inline — a synchronous `requests.get` of an
operator-configured URL, streamed, then signature-verified and parsed. A slow or
trickling CRL endpoint stalled every other request in the process for the whole
timeout. The supported deployment is a single process, so there is nothing else
to absorb it.

This is the **same defect, and the same fix, as the enrollment leg** — which was
moved off the loop in the 2026-08-15 review for exactly this reason. That change
did not sweep the other blocking external call in the codebase.

**Fixed** by handing the evidence check to `run_in_threadpool`, and by
short-circuiting idempotent confirmations **before** any network work: a repeat
confirmation for a serial already marked `ca_crl_updated` has nothing to learn
from the CRL, and fetching anyway turned a retry loop on the revocation host into
repeated outbound requests on the issuance path.

## Finding 2 (medium) — TCP syslog backpressure reached the request path

`_to_syslog` called `Logger.info` inline. For a TCP sink that is a blocking
`sendall`, on the calling thread, and the calling thread is the event loop
because `_audit` runs on the issuance path. There was no socket deadline and no
bound. **TCP syslog is the shipped production setting** in
`deploy/iis/web.config`, so this was the default posture, not an exotic one.

The sharp part: the **HEC sink already had exactly this treatment**, added after
measured evidence (5000 events against a dead endpoint left 4987 queued —
recorded in that code's own comment). Syslog simply never got it. One sink was
hardened and its sibling was left as it was.

**Fixed** by giving both sinks one shared bounded queue (`_submit_bounded`), so
the HEC path is no longer a special case, plus a socket timeout on the TCP
handler. On overflow the event is dropped *from the off-box sink only* — the
audit table row is already durable before this runs — and counted, so loss is
visible rather than silent.

## Finding 3 (medium) — the installer resolved build tooling live, as Administrator

`install-windows.ps1` hash-verified the entire runtime closure with
`--require-hashes`, and then did two things that were not covered by it:

- `pip install --upgrade pip` — an unpinned, unhashed fetch from a live index; and
- `pip install <repoRoot>` — which builds through pip's default PEP 517
  isolation, resolving `[build-system] requires = ["hatchling"]` from the index
  at install time, unversioned and unhashed.

Both run elevated on an issuance-path host. The runtime pinning is what made this
easy to miss: every package visible in the install log *was* hash-verified, and
the build closure never appeared in the log at all.

**Fixed** three ways:

- the live pip upgrade is **gone**, replaced by a version floor check that fails
  with an actionable message rather than reaching for the network;
- a new hash-pinned `deploy/build-requirements.lock.txt` carries the PEP 517
  build closure (hatchling and its dependencies); and
- the project install now uses `--no-build-isolation` after preinstalling that
  closure with `--require-hashes`, so nothing is resolved from the index at build
  time.

Verified by construction, not just by reading: the build closure installs under
`--require-hashes`, and the project then builds and installs with
`--no-build-isolation --no-index` — i.e. with no index access available at all.

## Finding 4 (low) — `removeFromCRL` accepted as proof of revocation

CRL evidence decided `revoked = entry is not None`. It never read `CRLReason`,
and never checked whether the document was a delta CRL.

`removeFromCRL` (reason 8) is the one CRL entry that asserts a certificate is
**not** revoked: it means a certificate came off *hold* and relying parties
should stop treating it as revoked. So a fresh, validly signed CRL could satisfy
`require_crl_evidence`, drain a live certificate off the pending-revocation
queue, and record `verification: crl-verified` — while the entry it relied on
meant the opposite.

This project **already refuses reason 8 on the ACME revoke route** (2026-08-14
F3, where it would have reached `certutil -revoke <serial> 8` at the CA).
Accepting it as *evidence* is the same hazard facing the other way. And it is
reachable in practice rather than in theory: `certutil -revoke <serial> 8` after
a hold is the documented un-hold, and it is how this project's own lab has
released test certificates.

**Fixed**: an entry whose reason is `removeFromCRL` returns `revoked=False` with
an explanatory detail (`checked=True` — the CRL was readable; this is an answer,
not a failure). A CRL carrying `DeltaCRLIndicator` returns `checked=False`
entirely: a delta lists only changes since a base CRL, the RA holds no base to
apply it to, and it is precisely the document where reason 8 legitimately
appears. An entry with **no** reason still counts as revoked — an absent
`CRLReason` means `unspecified`, and reading that as "not revoked" would be the
opposite failure.

## Tests

`tests/test_security_review_2026_08_16.py`, 8 tests. Finding 3 is PowerShell plus
a lockfile and has nothing for pytest to assert; it is covered by the Pester
suite and by the offline-build verification above.

**All mutation-checked** — each fix reverted in turn, each detected:

| Mutation | Detected by |
| --- | --- |
| `removeFromCRL` counts as revoked again | the reason test |
| delta CRL accepted as standalone evidence | all four CRL tests |
| syslog emits inline again | both backpressure tests |
| CRL fetch back on the event loop | the off-loop test |
| no idempotent short-circuit before the fetch | the no-refetch test |

Three tests are deliberate positive controls (ordinary revocation still counts,
an absent reason still counts, the current lease holder is not blocked), because
a guard that refused everything would satisfy every negative assertion.

**One of these tests was vacuous on its first attempt and mutation-checking is
what caught it.** The off-the-event-loop test originally asserted the helper ran
somewhere other than `threading.main_thread()` — but `TestClient` drives the app
from a portal thread, so that held with the fix reverted. It now asserts that
`asyncio.get_running_loop()` *raises* in the helper, which is true exactly when
the work is off the loop and false when it is inline.

## What remains unproven

- **No live re-proof of these four.** Static-plus-unit only. The CRL evidence
  paths in particular deserve exercising against the real CA's published CRL,
  including a genuine `certutil -revoke <serial> 8` un-hold, which the lab can
  produce.
- **Windows TCP syslog backpressure was not reproduced on Windows.** The bound
  and the non-blocking behaviour are proven by unit test; the exact blocking
  characteristics of a stalled Windows TCP syslog socket were not measured, and
  the scan said the same.
- **The installer changes have not been run on the real RA host.** The offline
  build was verified on Linux. The next live re-proof should install from a
  network-restricted position to confirm no index access is needed.

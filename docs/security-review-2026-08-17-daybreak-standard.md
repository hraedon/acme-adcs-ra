# Security review — Daybreak standard pass (2026-08-17)

Scope: independent triage of Daybreak's repository-wide static review of
`7325cdb` (branch `security-review-2026-08-15-daybreak`). The report contained
**four medium findings, no high or critical**. Coverage was partial by the
reviewer's own account: 37 of 167 tracked files fully reviewed, and no live
Windows, IIS, gMSA, syslog or ADCS environment was available to it.

Triage verdict: **one genuinely new defect, one duplicate-by-vector of an open
work item, one re-report of a consciously accepted posture, and one real gap
that reinforces two open work items.**

Source verification after the change: **840 pytest passed, 1 skipped** (832
before; the 8 new tests are the F4 suite), ruff clean, mypy clean on 33 source
files. `ruff format` is not a CI gate and was not run repo-wide.
**This is not a live Windows proof.**

## Finding 4 (reported medium) — syslog failures counted as delivered — FIXED

**Rated high here, not medium.** Confirmed by execution rather than by reading.

`_setup_syslog` built a stock `logging.handlers.SysLogHandler`. That handler
funnels every `emit()` exception into `logging.Handler.handleError`, which
reports to stderr and **returns**. `Logger.info()` therefore returns normally
after a send that never left the host, and both delivery-health paths inferred
success from that return:

- `_syslog_send` — `try/except/else`, so the `else` branch incremented
  `_offbox_delivered` on every send.
- `probe_offbox_delivery` — the `audit_offbox_required` startup gate, same
  non-raising path.

Measured against the pre-fix code with a TCP collector killed by RST:

| | pre-fix | post-fix |
|---|---|---|
| `probe_offbox_delivery()` with collector dead | `True` — "syslog accepted the probe over TCP" | `False` — "syslog refused the startup probe: …" |
| 5 sends to a dead collector | `delivered 0→5`, `failures 0→0` | `delivered 0→0`, `failures 0→5` |

Instrumenting `handleError` showed the transport was raising the whole time —
one `ConnectionResetError` then four `BrokenPipeError`s — and every one was
swallowed.

**Why high.** This is the same defect class as wave-3 F2, which was fixed for
the HEC sink only. The `SiemEmitter` docstring states the intent outright:
`audit_offbox_required` exists so that a revoked token or dead endpoint cannot
leave the RA "issuing certificates while believing an off-box audit trail was in
force", and calls that trail "precisely the control meant to survive a
compromise of this host". The shipped `web.config` selects TCP syslog, so this
is the default production audit path. No attacker is required — a collector
outage is sufficient, and it fails silently in the safe-looking direction.

**Fix**: `_RaisingSysLogHandler`, a `SysLogHandler` subclass that

1. re-raises from `handleError`, so a failed send reaches the caller's
   `try/except` and the counters record reality;
2. drops the dead stream socket on failure, so the next event reconnects via
   `createSocket()` instead of wedging the sink until the process restarts —
   without this the fix would convert a silent permanent failure into a loud
   permanent one;
3. re-applies the send timeout in `createSocket()`. The stock implementation
   does not carry it across a reconnect, and never applied it at all when the
   *initial* connect failed and the socket was created lazily on first emit —
   so this also closes a latent hole in the existing indefinite-block guard.

The TCP probe message no longer says "accepted", which overclaimed: a completed
`sendall` proves a live transport, not receipt. Syslog has no acknowledgment;
HEC is the sink that can prove delivery.

**Tests** (8, in `TestSyslogDeliveryIntegrity`): three controls — live collector
delivers, probe wording, absent collector disables the sink at construction —
plus dead-transport probe failure, failure accounting, socket-drop-and-
reconnect, timeout preserved across reconnect, and one bounded real-socket
end-to-end case.

Two notes on how these tests were built, because both were nearly mistakes:

- **The first version was flaky at ~1 run in 3.** Killing a real collector is
  racy: after an RST the first `sendall` is often absorbed by the local send
  buffer and the error surfaces on the next write. The defect under test is
  "does a raise get counted as a delivery", not "how fast does TCP notice", so
  the deterministic tests inject the transport failure and the single real
  socket test asserts detection *within a bounded number of sends*.
- **Every test was mutation-checked.** Reverting to the stock handler fails 5;
  removing the socket reset fails 2; removing the `createSocket` override fails
  exactly 1; making `handleError` return instead of raise fails 5. The three
  controls stay green under all four mutations, as controls should. The
  timeout test was *vacuous* in the flaky first version and only earned its
  place after the rewrite — which is precisely why the mutation pass is run.

## Finding 1 (medium) — unlimited keyChange rotations — VALID, folds into WI-014

Confirmed: `routes/key_change.py` has no rate, quota or cardinality check of any
kind, and each successful rotation inserts a non-coalesced `audit_log` row.

This is a **second vector on the same root cause as open WI-014** (unbounded
audit growth from unauthenticated `newAccount` denials), differing only in that
this one is authenticated. One retention-plus-quota design closes both, so it is
tracked there rather than as a separate item. Not fixed in this pass — WI-014
was consciously deferred and this does not change its priority enough to
pre-empt the live validation debt.

## Finding 2 (medium) — IIS allowlist not enforced — ALREADY ADJUDICATED

Accurate as an observation: `deploy/iis/web.config` ships `<ipSecurity>` inside
an XML comment and the installer does not require allowed addresses.

But this exact observation was raised in the **2026-08-11 review** and
dispositioned then: an in-process token bucket was added before the
unauthenticated nonce write (20/s, burst 100) as the compensating control, and
the allowlist was documented as *required rather than recommended*.
`docs/operator-requirements.md:87` states it plainly — "Not enforced by the
installer — **your responsibility**, and it is a stated pilot condition in the
threat model". The reviewer did not have that history.

Their remediation — have the installer refuse without an allowlist — is a
coherent proposal but a **change of posture, not a defect fix**, and it has real
costs: the RA cannot know the operator's client addresses, `<ipSecurity>`
requires the IP and Domain Restrictions role feature, and a hard refusal breaks
first-install and lab flows. **Left as-is.** Recommend recording the decision
explicitly in `SECURITY.md` so the next reviewer stops re-finding it; this is
the second time.

## Finding 3 (medium) — privileged script tree not authenticated — VALID

Better founded than the report knows. The scripts tree is **not installed by the
installer at all**: `docs/operations.md:857` tells operators to hand-copy the
entire `scripts/` directory to an unspecified location, and neither
`Register-MaintenanceTasks.ps1` nor `Sync-Revocations.ps1` checks anything
beyond `Test-Path` before persisting or executing a path as the gMSA or a CA
officer.

Two pieces of local evidence sharpen it:

- the round-7 ACL survey measured `BUILTIN\Users:(Write)` on `C:\ProgramData`,
  which is exactly why the *code* root lives under `%ProgramFiles%` — but the
  scripts tree has no such requirement;
- the lab itself stages CA-officer scripts in `C:\Temp\ra-scripts`.

So the failure mode is the natural consequence of following the documentation.
This converges with open **WI-015** (add the `-SitePath` ancestor-chain refusal;
the `C:\inetpub` baseline came back clean in round 7) and **WI-053**. The
primitive already exists — `Test-ObjectDaclTrusted` — it simply is not applied
to the privileged script path. Not fixed here: it is Windows-side work that
wants the same live session as the outstanding revocation proof.

## What this round did not change

Findings 1, 2 and 3 are unfixed by design, for the reasons above. The larger
outstanding debt is unchanged and is **not** a review problem:

- **Rverify, the sync/queue drain and the officer-script class D1–D7 have never
  been executed** at this tip. Round 7 was blocked from proving them by what was
  diagnosed as a CA DCOM fault; that diagnosis was **retracted on 2026-08-17**
  (it was the SSH logon session holding no Kerberos TGT — see the runbook §1
  callout), so the work is unblocked and needs a lab session, not a fix.
- **`01417b5`** — a 98-line Windows PowerShell 5.1 fix to `InstallVerifyLib.ps1`
  — landed after the round-7 live proof and has never been through a live
  install. CI's 5.1 Pester job is green on it, but the round-6 and round-7 live
  runs each found installer defects that green Pester missed.

The reviewer's own two follow-ups are *live-windows-validation* and
*remaining-file-review*, which points the same way: the next spend should be the
lab, not another static pass.

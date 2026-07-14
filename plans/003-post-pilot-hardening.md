# Plan 003 — Post-pilot hardening: issuance-path defense-in-depth & operational visibility

**Status:** COMPLETE — WI-016..020 implemented (commit `7d5c5b9`). Originally
proposed 2026-07-07.
**Author:** Claude (Fable 5), from the 2026-07-07 review

> **Closure (2026-07-13):** all five work items shipped, reviewed by the kimi
> adversarial reviewer (cross-lineage pass, all 5 → done), and WI-015 live
> re-proof PASSED against the deployed commit. Test count is now 433 pass / 1
> skip (up from the 376 cited in the ground-truth snapshot below). The
> ground-truth bullets are preserved as the point-in-time "before" state; read
> them as history, not as current gaps.
>
> Subsequent hardening (post-003): MED-1 added post-issuance SAN verification
> (the issued cert's SANs are checked against the order, not just the CSR), and
> the M-3 cert-revocation CAS now returns a deterministic `won_cas` signal so
> the route no longer infers a lost CAS from timestamp inequality.

**Strategic role:** 1.0 shipped a correct, well-documented RA and Plan 002
carried it through the pilot gate (WI-015 PASSED). This plan is what separates "works" from
"responsible to run unattended" — the two operational-hardening items that a
compromise or a silent drift would exploit, plus three smaller robustness/UX
gaps. Nothing here adds a signing key, widens the gMSA's rights, or changes the
trust model (EAB + network allowlist + deterministic SAN scope remains the whole
authorization story). Every item is either defense-in-depth *inside* that model
or visibility *into* the one honest limitation (CA-side revocation). These are
post-1.0 / post-pilot: WI-015 (the live re-proof) is not gated on them, but a
production pilot that runs for weeks unattended wants WI-016 and WI-017 done.

## Ground truth at time of writing

- 1.0 is shipped: full ACME subset (directory, EAB-gated accounts, orders,
  challenge, finalize, cert retrieval, revokeCert), deterministic SAN-scope
  policy, channel-bound gMSA enrollment, SIEM audit, out-of-band revocation.
  376 tests pass, `mypy --strict`, CI green on 3.12/3.13, MIT/public.
- **The SAN-scope policy is fail-closed** (verified): an account (`kid`) with no
  `san_scopes` entry has an empty allow-list and every SAN is denied;
  subject-only issuance is rejected. Good — this plan does not touch that; it
  hardens the paths *around* it.
- **No in-app rate limiting exists.** `operations.md` delegates all throttling to
  a reverse proxy (a copy-paste snippet). There is no per-account order cap in
  the RA itself. A leaked EAB credential with network reach can mint unlimited
  in-scope certs until the proxy config (which the operator must get right)
  catches it — and if the deployment fronts the RA directly, nothing does.
- **Revocation is out-of-band and the two states can silently diverge.**
  `revokeCert` flips only the RA store; the CA is revoked separately via
  `scripts/Revoke-Cert.ps1`. There is no check that the RA's revocation view
  matches the CA database. A cert revoked at the CA that the RA still reports
  valid (or the reverse) is invisible today.
- **The challenge is intentionally a no-op** — it transitions to `valid` without
  a domain-control proof, because the enterprise trust gate is EAB + network +
  SAN scope. That is a sound, documented design. Its consequence is that the
  `kid`→scope mapping *is* the entire authorization surface, so its tightness
  wants a first-class audit path (there is a mint/rotate helper, `scripts/eab.py`,
  but no "show me every kid and its scope" view).
- **`keyChange` (RFC 8555 §7.3.5) is not implemented.** Account-key rollover has
  no endpoint. Certify the Web likely never exercises it, but it is a spec gap.
- **`certfnsh.asp` disposition parsing is English-string-based.** WI-007 hardened
  it against real captured bodies and fixed a pending→denied misclassification,
  but a non-English ADCS locale remains a latent misread.

## Principles this plan must hold

- **No signing key, ever. No new gMSA privilege.** Nothing here moves the RA
  toward CA rights. The revocation-reconciliation item is **read-only** against
  the CA database (`certutil -view`) — it observes drift, it does not act on it.
- **Issuance path = security-critical.** WI-016 changes the order-accept path and
  earns an adversarial review + a live re-proof folded into the next WI-015 cycle.
- **Fail-closed, fail-visible.** A rate-limit breach denies (does not queue); a
  reconciliation mismatch is surfaced loudly (does not get silently repaired).
- **Deterministic, no LLM in the issuance path** — unchanged.

---

## Phase 1 — Defense-in-depth inside the trust model

### WI-016 — In-app per-account order rate limiting
- Add a deterministic, store-backed rate limit on order creation, keyed by
  account (`kid`): a configurable ceiling of new orders per rolling window
  (default e.g. 50/hour, tunable per deployment; a global ceiling as a second
  backstop). On breach, return RFC 8555 `urn:ietf:params:acme:error:rateLimited`
  with a `Retry-After` header — the spec-correct signal a conformant client (and
  Certify the Web) already understands. This is defense-in-depth that does **not**
  depend on the operator's reverse-proxy config being present or correct: even a
  directly-fronted RA, or one whose proxy rule was fat-fingered, is protected, so
  a leaked EAB credential cannot mint an unbounded cert flood before the network
  layer notices.
- Emit a SIEM audit event on every rate-limit denial (account, window, count) so
  a credential-abuse spike is observable, not just blocked.
- **AC:** limits are config-driven (per-account default + optional per-`kid`
  override + global backstop); the window is computed deterministically from the
  order-creation timestamps already in the store (no wall-clock nondeterminism in
  the tested path — inject the clock as the finalize/order code already does);
  a fixture that creates N+1 orders in-window gets `rateLimited` + `Retry-After`
  on the last; the denial is SIEM-audited; the limit is documented in
  `operations.md` as *in addition to*, not instead of, the reverse-proxy guidance.

## Phase 2 — Visibility into the honest limitation

### WI-017 — RA-vs-CA revocation reconciliation (read-only)
- Ship a read-only reconciliation check that compares the RA store's revocation
  view against the CA database (`certutil -view` filtered to the RA's issuance
  template / requester identity, or an equivalent CA-DB read) and reports drift
  in three buckets: **revoked-at-CA-but-valid-in-RA**, **revoked-in-RA-but-active-
  at-CA** (the dangerous one — the operator ran `revokeCert` but the out-of-band
  CA step was never done), and **in-sync**. This does not *close* the revocation
  gap (that needs a CA revocation endpoint the RA deliberately does not have) —
  it makes the gap **observable** so an operator can catch a missed out-of-band
  revocation instead of discovering it in an incident. Read-only: it never
  revokes or reactivates anything; it flags.
- Package it as an operator-run script (`scripts/Reconcile-Revocation.ps1` on the
  CA side, or a `certutil`-output ingest the RA can parse) plus a documented
  cadence, matching the WI-013 maintenance-task pattern. The output is a
  drift report the operator acts on out-of-band. A future enhancement (noted, not
  built) is emitting the drift buckets to SIEM so a "revoked-in-RA-but-active-at-
  CA" row alarms.
- **AC:** a synthetic CA-DB export + RA store with one entry in each bucket
  classifies all three correctly; the tool reads only (no `certutil -revoke`
  reachable from it); the `Reason 7`/unused constraint already enforced elsewhere
  is respected; `operations.md` ## Revocation runbook gains a "reconcile" section
  with cadence; the tool is safe to run repeatedly.

### WI-018 — EAB scope audit view
- Add a read-only "show me every account and its authorization" command to
  `scripts/eab.py` (`eab.py audit` / `list`): for each configured `kid`, print
  the SAN scope patterns and whether the account has ever been used, so the
  operator can periodically confirm no scope has quietly widened (e.g. to
  `*.corp.local`) — the whole authorization surface in one glance, since the
  challenge is a no-op and scope *is* the trust decision. Secrets (MAC keys) are
  never printed; this shows kid → scope → last-seen only.
- **AC:** `eab.py audit` lists every `kid` with its scope patterns and last-used
  timestamp (from the store), no MAC key material in the output; a wildcard scope
  is visually flagged (it is the widest blast radius); documented in
  `operations.md` ## EAB lifecycle alongside mint/rotate.

## Phase 3 — Spec & robustness gaps (lower priority)

### WI-019 — ACME `keyChange` (account-key rollover, RFC 8555 §7.3.5)
- Implement the `keyChange` endpoint: the outer JWS signed by the old account
  key wrapping an inner JWS signed by the new key over the rollover payload, with
  the RFC-mandated checks (inner `url` == outer `url`, inner `account` ==
  requester, new key not already in use). Advertise it in the directory. Low
  urgency (Certify the Web is unlikely to drive it) but it closes an RFC 8555
  conformance hole and a real operational capability (rotate a compromised
  account key without re-enrolling).
- **AC:** the full inner/outer JWS validation is tested against the hand-rolled
  ACME client fixtures (`tests/hand_rolled_acme_client.py`), including the reject
  paths (mismatched url, wrong account, key already in use, inner key == old
  key); the directory lists `keyChange`; a successful rollover re-keys the
  account and old-key JWS is thereafter rejected.

### WI-020 — Locale-robust `certfnsh.asp` disposition parsing
- Reduce dependence on English `certfnsh.asp` strings for the
  pending/issued/denied disposition. Prefer a locale-independent signal where ADCS
  exposes one (the `certnew.cer?ReqID=&Disposition=` / request-id extraction and
  the HTTP-level cues), and where a string match is unavoidable, document the
  assumed CA UI language as an explicit, single-point configuration rather than a
  hardcoded constant scattered across the parser — so a non-English CA is a
  one-line config change, not a silent misclassification.
- **AC:** the disposition classifier's language assumption is a single named
  constant/config surface, documented; the existing real-captured `certfnsh.asp`
  fixtures still pass; a non-English fixture (synthetic is fine) is either
  correctly classified via the locale-independent path or fails **loudly** with a
  "disposition unrecognized — check CA locale" error rather than a wrong verdict.

## Sequencing

WI-016 and WI-017 are the two that matter for an unattended pilot and are
independent — do them in either order; each is self-contained. WI-016 touches the
issuance path, so it folds into the next WI-015 live-re-proof cycle (add a
rate-limit-breach case to the round-trip). WI-018 is a small, high-leverage
visibility win with no issuance-path risk — cheap to land alongside either. WI-019
and WI-020 are genuine but lower-urgency robustness/conformance items; schedule
them after the pilot is running. None of these gate WI-015.

## Explicitly out of scope

- **A CA revocation endpoint / any gMSA privilege escalation.** WI-017 observes
  drift; it never gains the rights to fix it in-band. Closing the revocation gap
  by giving the RA CA-revoke rights is a separate, recorded security decision
  (threat-model §E), not this plan's to make.
- **Real ACME domain-control challenges (DNS-01/HTTP-01).** The enterprise trust
  model (EAB + network + scope) is deliberate; WI-018 hardens *auditing* of that
  model, it does not replace it.

# Pre-pilot checklist

`acme-adcs-ra` is **issuance-path infrastructure** — its worst case is
mis-issuance or leak of a standing ADCS enrollment identity. The read-only
family's "worst case it's wrong" margin does not apply. This checklist gates a
deployment from "the code works" to "responsible to run." Nothing here is
optional for a pilot; items are owned by the operator unless marked otherwise.

Derived from `docs/threat-model.md` (the §-references point back to it). Keep it
honest: check a box only when the thing is actually true, not when it's planned.

## A. Code / artifact integrity (engineering)

- [ ] **Working tree committed.** Never deploy issuance infra from an uncommitted
      tree — it breaks the provenance story the tool exists to provide.
- [ ] **CI green on the deployed commit.** Linux gates (ruff, mypy --strict,
      pytest, pip-audit) pass on the exact commit being deployed, on a remote
      runner — not just locally. See `.github/workflows/ci.yml`.
- [ ] **Live re-issue against current `main`.** The post-WI-001..005 finalize
      decomposition and CAS-guarded transitions landed *after* the 2026-06-20
      live proof and are validated by unit tests only. Re-run a real end-to-end
      issue on the lab against the current commit before pilot. **The proven
      artifact and the shipped artifact must be the same commit.**
- [ ] **Live-only checks accumulated by the scan series.** Each of these is
      unit-tested as far as it can be on a Linux dev host and genuinely unproven
      against a real CA/host. They are cheap to fold into the next live
      re-proof, and two of them decide whether a *revocation* proceeds:
  - [ ] **`Test-SerialRevokedAtCa` (2026-08-17 F4).** `certutil -view -restrict
        "SerialNumber=<s>,Disposition=21"` is assumed to select only revoked
        rows. Confirm against the lab CA that a revoked serial matches and an
        issued one does not — and that the self-check (serial appearing under
        both 20 and 21) does not fire. Fails safe either way, so a mismatch
        means "no worse than before", not "broken".
  - [ ] **End-to-end confirmation retry (2026-08-17 F4).** Revoke at the CA,
        make the RA callback fail (block it / stop the pool), then re-run
        `Sync-Revocations.ps1 -Execute` and confirm it reports
        `already-revoked-at-CA`, reaches the confirm POST, and drains the
        pending set. This is the whole point of exit 6, and only a live run
        exercises the wiring.
  - [ ] **Installer MSI verification (2026-08-17 F1).** With a real
        HttpPlatformHandler MSI: correct `-HttpPlatformHandlerSha256` installs;
        a wrong digest aborts before `msiexec`; an `http://` URL is refused.
        The decision functions are unit-tested, the `Get-FileHash` /
        `Get-AuthenticodeSignature` calls around them are not.
  - [ ] **POST-as-GET-only RA (2026-08-15 F4).** Plain `GET /acme/cert/{id}`
        and `/acme/authz/{id}` now return 405. Prove Certify the Web renews
        against it; any breakage is a CtW bug to file, not a reason to restore
        the forms.

## B. ADCS enrollment leg (the gMSA chokepoint — §4.A)

- [ ] **gMSA installed on the host**: `Test-ADServiceAccount` returns `True`.
      (AES Kerberos-etype + group-membership gotchas are on record if it fails.)
- [ ] **Template is server-authentication-only** (no client-auth/PKINIT EKU) and
      its ACL grants **Enroll to the gMSA only** — verified with
      `scripts/Verify-TemplateEnrollment.ps1` (confirms a normal user cannot
      request it). This EKU scope is what bounds a compromise to TLS-service
      spoofing.
- [ ] **`/certsrv/` reachable** in the chosen transport mode (A or C per
      `docs/certsrv-setup.md`); EPA posture matches the channel-binding client.

## C. ACME front gating (§4.B, §5)

- [ ] **EAB enabled and pinned** to the authorized Certify-the-Web client(s).
      Kids are high-entropy (UUID / ≥128-bit), **not** hostnames/customer names.
- [ ] **EAB MAC keys placed in `acme-ra.env` by hand** (never committed, never on
      a command line); file readable only by the gMSA + Administrators. Use
      `scripts/eab.py` to mint a high-entropy kid + MAC key (stdout-only; see
      `docs/operations.md` ## EAB lifecycle).
- [ ] **Documented EAB rotation procedure exists** (kid + MAC key + SAN scope)
      *before* pilot — threat-model §B calls this a precondition. Runbook:
      `docs/operations.md` ## EAB lifecycle (mint + rotate via
      `scripts/eab.py`).
- [ ] **Network allowlist in place.** The installer deliberately does **not**
      restrict the endpoint. Add `<ipSecurity>` (IP and Domain Restrictions role
      service) or a scoped firewall rule to the Certify-the-Web host. Do **not**
      blanket-firewall 443 if it is SNI-shared with cert-watch/gpo-lens. Snippet
      + caveats: `docs/operations.md` ## Network allowlist and reverse-proxy
      rate limiting.
- [ ] **`base_url` is the exact public origin (scheme + host + any port).** It is
      the **authority** for the JWS and EAB URL bindings as of 2026-08-11, not a
      display value: a JWS or EAB signed against any other URL is refused, and a
      mismatch fail-closes every legitimate request on day 1 (§4.D).
- [ ] **EAB credentials are per-deployment.** Because the EAB binding now pins to
      this RA's `newAccount` URL, a kid+MAC pair shared with a test/staging RA no
      longer verifies here — but sharing one is still a credential-hygiene
      failure. Mint separate kids per environment.
- [ ] **Account eviction path understood.** Removing a kid from `eab_allowlist`
      now evicts every account created under it *completely* (orders, key
      rollover, and revocation), not just issuance. Clients can also self-disable
      via RFC 8555 §7.3.6 deactivation. Both are audited.

## D. Admin surface (§4.A, §4.D)

- [ ] **`admin_token` set, high-entropy, ACL'd, and rotatable** — treat it like an
      EAB MAC key. A holder can reconcile a stuck order to `ready`, the one
      action that can enable a re-enroll. Runbook: `docs/operations.md` ##
      Admin token and reclaim runbook.
- [ ] **Reclaim runbook understood:** before using the reclaim→`ready` branch the
      operator MUST confirm at the ADCS CA database that no cert was issued for
      the order's ReqID. The server cannot make that double-issuance call itself.
      Runbook: `docs/operations.md` ## Admin token and reclaim runbook.

## E. Operations / DoS / observability (§4.G, §6)

- [ ] **Reverse-proxy rate limiting** per-account / per-IP (complements the
      in-app per-account order limit from WI-016, which bounds order creation
      but not raw request rate; a proxy flood still reaches the CA). Snippets +
      tuning guidance: `docs/operations.md` ## Network allowlist and in-app
      rate limiting.
- [ ] **Crons wired:** `DELETE /acme/admin/nonces` (nonce GC) and
      `DELETE /acme/admin/expired-orders` (order sweep, RFC 8555 §7.1.6).
      Install via `scripts/Register-MaintenanceTasks.ps1` (WI-013); see
      `docs/operations.md` ## Scheduled maintenance tasks.
- [ ] **Monitoring alerts on time-in-`processing` p99** (pilot condition);
      `GET /acme/admin/orders?status=processing` surfaces stuck orders. SLOs +
      alerting guidance: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **SIEM alerts on `finalize-enrollment-abandoned`.** A stale enrollment
      abandoned before the CA call because its order was reclaimed while it was
      still queued. Nothing was issued — but it means ordinary queueing is
      crossing the reclaim age floor, which is the schedule the double-issuance
      finding needed. Investigate enrollment latency, not the reclaim.
      Background: `docs/security-review-2026-08-15-rescan.md`.
- [ ] **Audit leaves the box — REQUIRED, not "consider" (§4.D.1).** The default
      `jsonl` sink writes next to the database, so a compromise of the RA host —
      the adversary §4.A calls load-bearing — destroys the audit table *and* its
      only mirror. Set `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with the syslog or
      HEC sink; the RA then refuses to start in the same-host-only posture. A
      write-once/append-only destination on the SIEM side remains desirable.
      SIEM delivery monitoring: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **Nonce ceiling reviewed.** `/acme/new-nonce` is unauthenticated and each
      call is a SQLite write; the in-app token bucket
      (`nonce_rate_limit_per_second`, default 20/s burst 100) bounds it before
      the write. Confirm the default is comfortably above real client volume and
      that the network allowlist above is actually in place — the bucket is
      defence in depth, not a substitute for it.
- [ ] **Retention/archival** for `audit_log` and the cert table decided. Guidance:
      `docs/operations.md` ## Retention and archival.

## F. Known limitation to accept with eyes open

- [ ] **CA-side revocation is out-of-band, operator-run (WI-010, §4.E).**
      `revokeCert` records the revocation in the RA store only (cert → revoked,
      order → revoked, GET cert → 410 Gone) — it does **not** write the CA CRL.
      The audit event honestly records `revocation_scope=ra-store-only`,
      `ca_crl_updated=false`; the ACME response surfaces an
      `out_of_band_revocation` hint. The operator closes the loop by running
      `scripts/Revoke-Cert.ps1` (a CA officer, **not** the gMSA) which runs
      `certutil -revoke` and republishes the CRL. The enrollment gMSA gains no
      CA-officer rights (the project's tightest security tenet). Confirm the
      on-call runbook references `Revoke-Cert.ps1` and that the operator
      verifies the CRL republished after each revocation before pilot. Runbook:
      `docs/operations.md` ## Revocation runbook. **Reason 7 is rejected** by
      both the RA and `Revoke-Cert.ps1` (RFC 5280 "unused"; `certutil` rejects
      it) so an accepted reason can never silently break the out-of-band loop.

---

When every box above is checked, the deployment has cleared the bar this tool is
engineered to. Until then it has not — regardless of a green local test run.

---

## Validation log

- **Daybreak round-4 findings validated and fixed (2026-08-15) on `102a1f4`,
  live-proven on the lab RA host.** Four findings on the installer rework
  (2 medium, 2 low), all closed on the same branch with 14 new Pester cases
  (235 total, plus 795 pytest / ruff / mypy green):

  - **M1 TOCTOU on first-install state-root creation** — between the
    provenance check and `New-Item -Force`, a local attacker could pre-create
    the predictable ProgramData path; the claim then worked *for* them
    (`setowner /t` normalised their files' owners, the proof passed, the
    re-protect protected their planted dotenv, and no-clobber preserved it —
    the adoption finding reopened by race). Fix: creation without `-Force`
    (throws on an existing path) plus a provenance re-verdict on collision; a
    non-admin cannot manufacture an "ours"-shaped tree (owner Administrators
    is unreachable for them), so the retry can only land in the foreign
    refusal. **Not live-proven** — the branch is reachable only by a genuinely
    won race; it is source-asserted and reviewed instead.
  - **M2 legacy single-tree layout passing the generic provenance check** —
    a clean pre-split tree has the same trustee/owner/DACL shape as ours, so
    it verified as "ours" while the preserved web.config kept launching the
    old gMSA-writable ProgramData venv. Fix, both halves **live-proven**:
    the state tree now refuses `venv`/`python`/`scripts` at its root
    (decided before the icacls walk) — proven against the **real preserved
    `.preSplit` tree**: refusal names the venv as executable content, tree
    untouched; and a post-install check warns loudly when the site's
    web.config `processPath` points inside the state tree — proven with a
    simulated half-done migration (warning printed, then a clean install over
    the healthy tree still exits 0 and `/directory` answers 200, so the new
    rule does not trip on our own layout).
  - **L1 CWD executable hijack on bare `py`/`python` probes through
    `cmd /c`** — an elevated shell in a user-writable directory would execute
    a planted interpreter during the probe. Fix:
    `NoDefaultCurrentDirectoryInExePath` process-wide (set before any
    `cmd /c`) plus absolute-path resolution in `Invoke-PyProbe`. Source-
    asserted; deliberately not "proven" live by executing planted bytes as
    admin.
  - **L2 overlapping `-RuntimeDir`/`-InstallDir` silently collapsing the
    RX/Modify boundary** — both grant sets have the same proof shape, so
    nested or equal roots stayed green while the gMSA gained Modify over
    executable content. Fix: `Get-PathRelation` refusal before any host
    mutation. **Live-proven**: equal roots and nested roots both refused
    (relation named), app pool never touched (still Started), nothing
    created.

- **Installer rework validation — the two-tree layout EXECUTED for the first
  time (2026-08-15) on `54b90db`, the tip after two live-found defects were
  fixed and re-proven on the host.** Everything the code/state split's "what is
  still unproven" list demanded, on the exact commit, from CI-green preflight
  through teardown. See `samples/lab-run-2026-08-15-installer-validation.md`
  (gitignored) for the full transcript map.

  **Proven live, all on `54b90db`'s own bytes:** clean install from absent
  roots (exit 0, both trees claimed, built, and read-back-proven); reinstall
  over the result (both roots recognised as ours, runtime retired → rebuilt →
  retired copy deleted, dotenv preserved no-clobber); **refusal of the real
  old-layout tree** (the §4 BREAKING behaviour, actionable message naming the
  violations and the rescue list); **refusal of a genuine non-admin pre-plant**
  (a throwaway local user pre-created a ProgramData state root with a hostile
  `acme-ra.env` — refused, tree untouched, refusal precedes any dotenv read;
  and its attempt to pre-create under `%ProgramFiles%` is access-denied, so
  the code root cannot be pre-planted at all); **rollback** (deliberately
  corrupted pinned hash → build fails after retirement → previous runtime
  restored byte-identically, zero `.retired-*` leftovers, and after the
  by-hand pool restart the old runtime still serves `/directory` 200);
  **the gMSA `RX` grant launches uvicorn** — HttpPlatformHandler starts the
  ProgramFiles venv as the domain gMSA and `/directory` answers 200 with the
  app running as the gMSA identity; **the §4 migration walked end to end**
  (backup → rescue → read-the-dotenv → rename → fresh install → restore db/env
  byte-identical → re-run installer → web.config processPath → verify: §5
  shape, owners Administrators, spnego imports, db integrity + counts
  unchanged).

  **Two escaped defects found and fixed on the branch (both the WI-050
  class — PowerShell semantics invisible to Linux CI):**
  1. `icacls /save` writes UTF-16LE **without BOM**; `Get-Content -Raw`
     decoded it as ANSI on Windows PowerShell 5.1 (this pwsh *sniffs* BOM-less
     UTF-16, which is why local Pester was green) — the ACL proof failed
     closed on a healthy tree and blocked every install. Fixed in `b816352`
     (`Get-IcaclsDumpText`, byte-sniffed decode, ordinal `StartsWith`).
  2. The state-root claim's `icacls /reset /t` strips the dotenv's protected
     DACL, and it was only re-applied ~150 lines later — a build failure in
     between (the rollback path) left `acme-ra.env` inheriting gMSA **Modify**
     (EAB allowlist + SAN scopes worker-writable), and the *next* pre-flight
     then correctly refused the tree, bricking the install. Fixed in
     `54b90db` (re-protect immediately after the claim; the rollback catch now
     re-protects and re-proves the state tree too). Both fixes re-proven live
     on the host: the failed-build rerun prints "state tree re-protected and
     re-proven" and the dotenv survives the failure protected.

  **Also closed:** the `*S-1-5-32-544` star form **works** for
  `icacls /setowner` on this host (previously "unverified for that verb").

  **Not proven:** the no-rollback proof-failure path (a runtime that builds
     but fails its proof — the honest "app pool left stopped deliberately"
     message); a `-ConfigureIIS` first install from bare IIS (the lab host
     already had the site); the user-scoped-Python copy path was exercised,
     the machine-wide reference path was not (the host's 3.13 lost the
     launcher preference to the profile 3.14).

  **Host end-state (deliberate, not restored):** the lab RA now runs the
  two-tree layout on `54b90db`'s runtime with the same store (counts
  22/5/21/87, unchanged), same dotenv, same siem trail; the old tree is
  preserved at `C:\ProgramData\acme-adcs-ra.preSplit` as the migration
  rollback artifact; `web.config` processPath points at the ProgramFiles
  venv. The CA host was never touched (no issuance, no revocation, no
  ca-provision this run). Refusal runs leave the app pool stopped
  (fail-closed; restart by hand) — observed behaviour worth knowing
  operationally, not a defect.

- **Full E2E lab validation — PASSED (2026-08-15) on `2d6ac20`, the tip after the
  two fixes the `b028b96` pass produced plus the three CI/test/PowerShell commits
  behind them.** Preflight green on the exact commit (CI, ruff, mypy, pytest
  768/1, Pester 148). Deployed by the ordinary installer (exit 0) and asserted on
  the *installed* package; the hash-pinned closure installed clean into a
  throwaway venv on Windows/3.14. **No new product defect found.** The
  sync-path PowerShell fix (`2d6ac20`) is exercised live: the agent ran to
  completion six times on this deployment.

  **What passed.** §A 14/14, §A1 front controls 13/13, §G 5/5 (removed GET
  routes answer 405), both transport-orphan branches 6/6, the revocation round
  trip three times (R 5/5 + Rverify 3/3 each: through the registered task as the
  gMSA, then the agent-authority pair, then under CRL evidence). Agent authority:
  admin-token-only exits 2 with the confirm 401'd; confirm-token-only completes
  with no admin token present at all. CRL evidence fails closed
  (`crl-evidence-required-but-absent`) until an administrator republishes, then
  records `crl-verified`. Least privilege live: the gMSA is denied CRL
  publication (`0x80070005`), denied an out-of-template revocation
  (`CERTSRV_E_RESTRICTEDOFFICER`), and its token carries no domain groups (E-1).
  Reason 8 refused inside the gMSA context by `Revoke-Cert.ps1` (exit 3, exact
  error text). The lease: §L 9/9 (migration on the real store, pre-existing
  orders still generation 0, in-flight reclaims refused by the registry) and
  §Lqueue 8/8 (saturation 40 sockets, target provably queued — committed to
  `processing` with **no** enrollment audit row — reclaim denied
  `enrollment-in-flight`, nothing reopened, re-finalize takes a fresh lease).

  **The WI-053 deployment shape, proven live for the first time.** The sync task
  registered with `-RevocationSyncOnly -ConfirmToken` only: the task action
  loads **only** `ACME_RA_REVOCATION_CONFIRM_TOKEN` from the ACL'd dotenv at run
  time (F2), contains no admin-key load and no literal token, runs as the gMSA
  with LogonType Password — and that task drained every revocation this run
  queued. The revocation host needs no admin authority, in the deployed
  artifact, not just in the script.

  **STILL NOT established: the durable lease stopping a stale worker.** Third
  run, same verdict — raced, neither confirmed nor refuted. The contested
  order's two `finalize-enrollment-transport-failed` rows are sequential: the
  gen-1 worker ran and returned (transport failure) before the SQL-reclaim +
  re-finalize could invalidate it, so no worker ever survived a generation bump
  and no `finalize-enrollment-abandoned` row exists anywhere. `total_abandoned=0`
  with Ld4/Ld5 holding (no order anywhere has two certificates; the contested
  order has none — the CA never issued for it). Ld1 remains the documented
  non-defect: 86 orders wedge in `processing` for operator reconciliation.

  **The CRL cadence finding stands unchanged** (CRL3 FAIL by design of the
  check): 7d 12h20m window vs the 604800s default ceiling — the WI-052 operator
  item, configuration not code.

  **Two harness defects found (not product).** (1) Lqueue's saturation counter
  reads `ca-ip.txt`, which held the *real* CA address, but the §9-approved
  blackhole is **config-mode** (`ACME_RA_ADCS_HOST=192.0.2.1`), so it counted
  the wrong destination and failed at `ca_sockets=2` while the substantive
  checks passed — the counter must be pointed at the blackhole address in that
  mode (re-run then measured 40/40 clean). (2) `bh-off.ps1` only clears the
  *firewall* blackhole; the config blackhole needs the explicit
  `setenv ACME_RA_ADCS_HOST` restore, which teardown.ps1 does. Also: the lab's
  key-auth SSH admin logon **cannot DCOM to the CA** (it carries no network
  credential —
  `RPC_S_SERVER_UNAVAILABLE` on `-ping` while the same call succeeds on the CA
  console and as the gMSA task), so teardown revocations must run through the
  gMSA runner. The §2 ssh-quoting trap claimed three more victims this run
  (icacls `$:`, a method call, a pipe under cmd.exe).

  **Teardown verified, not assumed.** All five certificates this run caused the
  CA to issue revoked — including the untracked ReqID-only orphan (ReqID 201,
  serial `6c…c9`) — and the CRL republished; CA back to 224 bytes / 4 ACEs /
  `OfficerRights: ABSENT`; `denyUrlSequences` empty; RA store restored from the
  pre-run backup and **fingerprint-identical** (integrity `ok`, every row count
  equal); tasks unregistered; dotenv verified free of throwaway credentials;
  web.config back to its pristine 10-variable set; harness temp removed on both
  hosts. Artifacts table in `samples/lab-run-2026-08-15-notes.md`.

- **Full E2E lab validation — PASSED (2026-08-14) on `b028b96` + two fixes it
  produced, with one claim still NOT established.** The first full pass over the
  whole 2026-08-15 → 2026-08-18-wave-3 security series; every one of those
  rounds had landed on `main` without a live run. Deployed by the ordinary
  installer and asserted on the *installed* package. **Two defects found, both
  invisible to CI, both in PowerShell that CI never executes.**

  **Defect 1 — the pinned installer could not install at all.** `install-windows.ps1`
  aborted with "Bundled pip is too old for --require-hashes" against pip 26.2.1.
  `(& $venvPy -m pip --version) 2>&1` returns a two-element `Object[]` (the
  banner plus pip's trailing empty line), and `-match` against an ARRAY filters
  the collection instead of capturing, so `$Matches` was never set, `$Matches[1]`
  read as `$null`, `[int]$null` was 0, and `0 -lt 23` threw. Live from `fb3a14e`
  (2026-08-16), which introduced the floor check — **every fresh install on
  Windows, the RA's only production platform, was broken for the whole series.**
  Fixed by `Get-PipMajorVersion` in `lib/InstallVerifyLib.ps1`, covered by tests
  fed the real two-element array captured on the host.

  **Defect 2 — the wave-3 F1 fix was inert in exactly the case it existed for.**
  `Test-SerialRevokedAtCa` correctly detected a disposition-21/reason-8 row, then
  defeated itself: its three `Write-Output` diagnostics joined the return value,
  because a PowerShell function returns its whole success stream. The call site
  is `if (Test-SerialRevokedAtCa ...)`, `@(three strings, $false)` is a non-empty
  array, and a non-empty array is truthy. Proven end to end against the real CA:
  a certificate placed off the CRL and **still valid** was reported "ALREADY
  revoked", exiting 6 — which drains the serial off the RA's pending feed and
  records `revocation-ca-confirmed`, booking a containment failure as a success.
  Diagnostics moved to `[Console]::Error.WriteLine` (the file's own idiom for
  exactly this reason); re-run live afterwards, exit 0 and a real re-revocation.
  Both branches of the function had the defect. Nothing covered this function —
  it lives in `Revoke-Cert.ps1`, not `lib/`, so the Pester suite never saw it;
  it is now covered by AST-extracting the shipped text.

  **What passed.** §A issuance 14/14 (EKU exactly `serverAuth`, SAN from CSR,
  chain to root, CA policy denial mapped, reasons 7/8 refused). §A1 front
  controls 13/13 (JWS/EAB URL pinning, kid locality, deactivation, cross-account
  401, nonce ceiling). §G 5/5 — the removed GET routes answer **405, not 401**.
  Both transport-orphan branches 6/6 each: leaf-in-hand quarantined with serial
  and ReqID and queued; ReqID-only leaves no row, only the audit record. The
  revocation round trip drained three times through the registered task running
  as the gMSA. Least privilege, live: the gMSA is **denied** CRL publication
  (`0x80070005`) and **denied** an out-of-template revocation
  (`CERTSRV_E_RESTRICTEDOFFICER`), and its token carries **no domain groups at
  all** (E-1 hardening). Agent authority: admin-token-only exits 2 with the
  confirm 401'd, confirm-token-only completes with no admin token present. CRL
  evidence fails closed (`crl-evidence-required-but-absent`) until an
  administrator republishes, then records `crl-verified` with CRL number 87.
  The account-JWK twin migration applied to the real 21-account store: every row
  canonical, zero duplicate thumbprints, the UNIQUE index present, integrity
  `ok`. The lease: 9/9 and 8/8, the queue gap reproduced and refused
  `enrollment-in-flight` with the age floor at 0 so it cannot have answered.
  The hash-pinned closure installs clean into a throwaway venv on Windows/3.14.

  **The Windows CRL watchdog, proven where it was previously absent.** A hostile
  server that sends headers and goes silent is cut at **3.01 s** against a 30 s
  per-read timeout, on `win32`, reporting the deadline rather than a bare read
  timeout, and fails closed (`checked=False`). This is the control that existed
  on Linux and was missing on Windows for the whole of the 08-17 round.

  **STILL NOT established: the durable lease stopping a stale worker.** Same
  outcome and same evidence as the 2026-08-14 run, reached independently: the
  contested order's two `finalize-enrollment-transport-failed` rows are
  **sequential** (21:23:18 then 21:23:19), so the gen-1 worker returned before
  the gen-2 re-finalize began and no stale worker ever survived a generation
  bump. Neither confirmed nor refuted; still unit-tested and mutation-proven
  only. It needs a CA stand-in that accepts the connection and stalls.

  **Observation 1 of the previous run is confirmed, and is by design.** Orders
  wedge in `processing` after a connect-level transport failure (43/43 here) and
  nothing ever retires them: `Store.sweep_expired_orders` sweeps only
  `pending`/`ready` and documents `processing` as "operator-reconcilable". A
  client retry does take a fresh lease, so orders are not bricked — but a CA
  outage still turns every in-flight order into operator work.

  **The CRL cadence finding stands unchanged.** This CA's 7d 12h 20m validity
  window still exceeds the 7-day default ceiling. The override is plumbed and
  works (`ACME_RA_REVOCATION_CONFIRM_CRL_MAX_AGE_SECONDS=691200` reads back as
  691200 against a 604800 default), so this is configuration, not a code gap.

  **Teardown verified, not assumed.** CA back to 224 bytes / 4 ACEs /
  `OfficerRights: ABSENT`, `denyUrlSequences` empty (checked via the full
  `appcmd` path after a PATH miss made a first check meaningless), all five
  certificates this run caused the CA to issue revoked — including the
  ReqID-only orphan that nothing tracks — and the CRL republished. The RA store
  restored and **verified against the pre-run fingerprint**: integrity `ok` and
  every row count identical. Tasks unregistered, dotenv restored, web.config
  back to its exact pristine 10-variable set. Ten ACME-template certificates
  from *earlier* sessions remain issued at the CA — pre-existing, not this run.

- **Enrollment-lease live re-proof — PASSED (2026-08-14) on `1832163`, with one
  claim explicitly NOT established and three observations opened.** Targeted at
  the 2026-08-15 rescan fix rather than a full pass: §A issuance regression, the
  removed GET routes, and a new lease phase. Deployed by the ordinary installer
  and confirmed on the *installed* package, not the source tree — the version
  string is `1.9.1` both before and after this change, so it proves nothing on
  its own.

  **§A issuance regression + removed GET routes, 19/19.** A real certificate
  issued with EKU exactly `serverAuth`, SAN from the CSR, chain to the existing
  root. `GET /acme/cert/{id}` and `GET /acme/authz/{id}` return **405, not 401**
  — the routes are unregistered, not merely refusing, which is the stronger
  evidence and the one the previous harness could not have distinguished.

  **The lease, 9/9 + 8/8.** The migration applied to the real production-shaped
  store (integrity `ok`, all 22 pre-existing orders still at generation 0, row
  counts unchanged). A normal issuance mints generation 1 and completes. Against
  a genuinely running enrollment, repeated reclaim attempts were refused
  `enrollment-in-flight` and **none ever reopened the order**.

  **The queue gap — the finding's own schedule — reproduced and refused.** With
  the threadpool saturated (40 concurrent hung enrollments, confirmed by socket
  count against the CA address) one further finalize was submitted. Its order
  committed to `processing` while the audit log showed **no enrollment event for
  it at all**, proving its task had never run. Reclaiming that order was refused
  `enrollment-in-flight`, with `reclaim_minimum_processing_age_seconds=0` so the
  age floor could not have been what answered. Before the fix this returns 200
  and reopens the order.

  **NOT established: the durable lease stopping a stale worker.** The attempt
  bypassed the in-memory mark by reclaiming in SQL, but the audit trail shows
  two `finalize-enrollment-transport-failed` rows for the contested order —
  both tasks ran, so the stale-worker condition was never created. The lease
  check remains unit-tested and mutation-proven only. Reproducing it live needs
  a CA stand-in that accepts the connection and stalls, so enrollments expire on
  a read timeout at staggered times instead of all at once.

  **Three observations, none security-blocking:**
  1. **A connect-level transport failure leaves the order wedged in
     `processing` permanently** (no revert on `ca_issued=False`) and returns
     503. This run produced 285 such failures and therefore 285 wedged orders.
     Recovery is an admin reclaim that asks the operator to confirm at the CA
     database that nothing was issued — when the RA already knows the CA was
     never reached. A CA outage turns every in-flight order into an admin
     ticket.
  2. **Under ~42 concurrent hung enrollments the RA takes ~21 s to admit a new
     request**, and admin reclaims serialise (the handler does its SQLite work
     on the event loop).
  3. **Measured end-to-end finalize against the real CA is ~0.4–0.5 s.** The
     `reclaim_minimum_processing_age_seconds` default of 60 s is ~120× that.
     The figure it was reasoned from (4 × 30 s per-call timeouts) is a
     worst-case bound, not the operating point; the floor should be set from
     measurement.

  Lab left pristine: all 8 certificates this run caused revoked at the CA
  (`21 -- Revoked`) and the CRL republished; store, dotenv and `web.config`
  restored and **verified against a fingerprint taken at backup time** (integrity
  `ok`, every table count identical); app pool back to `Started`.

- **v1.9.1 live re-proof — PASSED (2026-08-14), one blocking defect found and
  fixed, three residuals opened.** Run against commit `bef2022`, which is
  `v1.9.0-rc2` plus the two fixes this run produced — and the reason the shipped
  version is **1.9.1**: 1.9.0 never released, because this run is what found the
  two things wrong with rc2. This is the full
  pass the rc1 row below demanded: **§A, §A.1, §B/§C, §D, §E from a clean
  start**, plus every case the 2026-08-14 review added. The whole sequence is
  automated end to end, so it is repeatable rather than a one-off; the
  methodology, the access paths and the tricks for provoking each path live in
  a gitignored runbook (`samples/lab-validation-runbook.md`) because they name
  the real hosts.

  **Before anything was measured: the tip was CI-red.** `v1.9.0-rc2`
  (`cb1285c`) failed `ruff` on three `RUF059` findings in the new review tests
  — the lint job, on all three Python versions. Fixed in `a3e68d8`. Proving a
  commit that cannot ship is wasted lab time, so this is now the first
  preflight step.

  **§A — issuance (real CA), 14/14.** Full round-trip issued a real
  certificate: EKU exactly `serverAuth`, SAN from the CSR, chain leaf → issuing
  CA → existing root, and the CA database recording the requester as the
  enrollment gMSA under `ACME-ServerAuth`. An out-of-scope SAN is refused at
  finalize; an EC P-256 key draws a genuine `Denied by Policy Module` from the
  CA, mapped to `400 rejectedIdentifier`.

  **Reason 8 is refused, and no path emits it** (the 2026-08-14 blocker).
  `revokeCert` with reason 8 → `400 badRevocationReason`; the certificate stays
  valid, is still served, and **is not queued** for CA-side revocation.
  `Revoke-Cert.ps1 -Reason 8` exits **3** before it touches `certutil`. Reason 7
  likewise refused.

  **§A.1 — front controls, 13/13.** URL binding pinned to `base_url` (JWS `url`
  + `Host:` naming another deployment → rejected; EAB naming another deployment
  → `badExternalAccountBinding`; foreign `kid` → rejected), deactivation then
  401, POST-as-GET resolves order/account/orders, another account's certificate
  → 401, `/docs` `/redoc` `/openapi.json` → 404, and the nonce ceiling returning
  a 204/429 mix with `Retry-After`.

  **The transport-orphan quarantine, against the real CA — both branches.**
  Provoked by making the CA refuse exactly one Web Enrollment URL (IIS request
  filtering scoped to `/CertSrv`), so the CA genuinely issues and the RA fails
  after it:
  - `certnew.p7b` refused (leaf in hand) → **500**, order terminal-`invalid`, a
    `quarantined` row carrying serial and ReqID, queued for CA-side revocation,
    never served on a retried finalize. The CA confirms the certificate as
    `Issued` — and the ordinary pull agent later revoked it, which is the whole
    design closing.
  - `certnew.cer` refused (ReqID only) → **500**, order terminal-`invalid`, **no
    row** (the RA never received the bytes), and the ReqID made loud in the
    audit. Both orphans were revoked by hand at teardown, which is exactly the
    operator action this branch documents.

  **§C — revocation round trip, as the gMSA, through the shipped registration
  path.** `Register-MaintenanceTasks.ps1` registered the sync task
  (`LogonType=Password`), the task ran as `gMSA-acme-ra$`, revoked at the CA and
  confirmed back: CA disposition `Revoked` with the requested reason, RA pending
  set drained to empty, exit 0.

  **Authority separation, end to end.** The admin token is **refused** on the
  confirm endpoint (401) — both directly and through the agent: an agent given
  only the admin token revokes at the CA, fails every confirm, leaves the serial
  pending and **exits 2**. The same agent given only `-ConfirmToken` — no admin
  token anywhere — reads the pending list, confirms, drains the queue and exits
  0.

  **CRL evidence, against the real ADCS CRL.** With
  `revocation_confirm_require_crl_evidence=true`: the confirm is **refused**
  (`400`, audit `reason: crl-evidence-required-but-absent`) while the serial is
  not yet on a published CRL — the scoped officer cannot publish one
  (`certutil -CRL` → `0x80070005`). After an administrator republished, the same
  confirm succeeded with audit `verification: "crl-verified"`, carrying the CRL
  number and `thisUpdate`. Fail-closed control and positive both observed.

  **§C least privilege / §D enrollment bound.** As the gMSA: CRL publication
  denied `0x80070005` (no Manage-CA); revoking a certificate on another template
  denied `0x80094009 CERTSRV_E_RESTRICTEDOFFICER` (template scoping enforced);
  and the live token shows **no `Domain Computers`** — the E-1 hardening still
  holds.

  **The pinned installer runs on Windows.** `install-windows.ps1` installed from
  `deploy/requirements.lock.txt` with `--require-hashes --only-binary :all:`,
  exit 0. Stronger form also checked: the full 29-package closure — exported on
  Linux for 3.13 — installs clean into a **throwaway venv** on Windows /
  Python 3.14, so every wheel was actually fetched and hash-verified rather than
  reported "already satisfied". No platform wheel gap.

  ### The defect this run found

  **`Set-OfficerRights.ps1` could not provision a CA that had no `OfficerRights`
  value — the default, and therefore the first-provisioning path.** It aborted
  with `Buffer cannot be null` and wrote nothing, *after* the CA-side
  Certificate Manager grant had already been made, leaving the CA
  half-configured. Cause: the 2026-08-13 fix for the single-element unwrap
  wrapped every return in `,$result`, and `,@()` reaches the call site as a
  one-element array holding an empty array — so `@(Get-ExistingAces $b).Count`
  was 1 with no ACEs and the phantom entry went into the ACE builder with a null
  `RawAce`. Fixed in `bef2022`; provisioning then succeeded on the pristine lab
  CA and the template scoping enforced correctly.

  It **reproduces under pwsh 7 on Linux** — unlike the previous round's two
  defects, CI could have caught this one. It did not, because the two Pester
  tests covering the empty case asserted `$result = Get-ExistingAces $null`,
  and assignment collapses a single-item pipeline back to the item, while the
  shipped code says `@(Get-ExistingAces …)`. **The tests asserted a shape the
  shipped code never uses.** They now assert the call-site expression, and
  reverting the library fix fails them.

  ### Residuals this run opened

  - [ ] **A quarantined transport orphan can never satisfy
        `revocation_confirm_require_crl_evidence=true`.** The chain-fetch
        failure *is* the orphan case, so the quarantined row has **no stored
        chain** — and CRL evidence pins the issuer by selecting, from the
        certificate's own stored chain, the key that signed it (the F12 fix).
        Observed live: `could not locate the issuing CA certificate in the
        stored chain, so the CRL signature cannot be verified`. The serial is
        revoked at the CA on every run and confirmed on none, so the queue never
        drains and the agent exits 2 forever. Fail-closed, so not an exposure,
        but a guaranteed stuck queue. **Default configuration is unaffected** —
        verified: with the default (`false`) the same serial confirmed as
        `agent-asserted` and drained. Needs a decision on which trust source may
        verify a CRL for a chain-less row.
  - [ ] **The default CRL freshness ceiling is narrower than this CA's
        cadence.** `CRLPeriod = 1 Week`, and the published CRL's validity window
        is **7d 12h 20m** against a default `revocation_confirm_crl_max_age_seconds`
        of 7 days. In steady state the age of the current CRL reaches the
        ceiling exactly as the next one is published — zero margin — so any
        delayed publication starts failing evidence checks. The ceiling should
        be set from the CA's real cadence (≥ `CRLPeriod` + overlap), not left at
        the default; the freshness gate itself was confirmed live (a 1-second
        ceiling refuses the real CRL).
  - [x] **`Register-MaintenanceTasks.ps1` re-introduces the admin token on the
        revocation host.** `-AdminToken` was mandatory and always written into
        the revocation-sync task action as `$env:ACME_ADMIN_TOKEN`, even when a
        confirm token was supplied — which undoes, at deployment time, the
        authority split the confirm token exists to create. **Resolved in the
        2026-08-15 review (finding 3):** `-AdminToken` is now optional, and
        `-RevocationSyncOnly -ConfirmToken …` registers only the sync task with
        zero admin-token bytes in its action. See docs/operations.md.
  - [x] **The plain GET forms are removed (finding 4, 2026-08-15).**
        `allow_unauthenticated_resource_get` was exercised both ways: with it
        **off**, a complete order still issues through POST-as-GET only. On that
        basis (and RFC 8555 conformance) the owner + Sol closed the loop
        entirely — both plain GET routes and the config flag are removed; a plain
        GET now returns 405. The re-proof runs against the POST-as-GET-only RA;
        if Certify the Web regresses, file a CtW bug (it uses Certes, which does
        POST-as-GET).

  **Lab returned to its pre-run state** (verified, not assumed): CA security
  descriptor byte-identical at 224 bytes with its four original ACEs,
  `OfficerRights` absent, `denyUrlSequences` empty, `certsvc` running; every
  certificate this run caused the CA to issue revoked and the CRL republished;
  scheduled tasks unregistered; RA store and dotenv restored from the pre-run
  backup (`integrity_check` ok, matching row counts); app pool left `Started` as
  found; temp directories cleared on both hosts. Ten unrevoked ACME test
  certificates from *earlier* sessions remain and were deliberately not touched.
  The E-1 hardening was left in place, as the runbook requires.

  **Teardown hazard worth recording:** restoring the SQLite store by copying the
  backup `.db` over a newer database corrupted it (`database disk image is
  malformed`) — the write landed while the worker still held the file. Stop the
  pool, confirm it is actually `Stopped`, remove `acme_ra.db` **and its `-wal`
  / `-shm` sidecars**, then copy. Re-done that way, `integrity_check` returned
  `ok` and the row counts matched the backup exactly.

- **v1.9.0 live re-proof — PASSED (2026-08-13), with two defects found and
  fixed.** Run against commit `26eae31` (the 2026-08-13 security review),
  deployed as a wheel into the gMSA app-pool venv on the lab RA host with
  `scripts/` and `scripts/lib/` shipped alongside. This closes proof gaps 1–3
  of `docs/security-review-2026-08-13.md`, which had shipped ten security fixes
  validated **only against fakes on Linux**.

  **§A — issuance + EKU (real CA).** Full ACME round-trip (new-account EAB →
  order → challenge → finalize → cert) issued a real certificate: EKU exactly
  `serverAuth`, `clientAuth` absent, SAN taken from the CSR, chain leaf →
  issuing CA → existing root (no new intermediate), requester recorded in the CA
  database as the enrollment gMSA. Out-of-scope SAN rejected at finalize; a CSR
  whose SANs did not match the order rejected before the CA saw it; reason 7
  rejected with `badRevocationReason`; revoked certificate → `410 Gone`. The
  strict chain validator did **not** false-reject — a successful issuance is the
  only proof of that, and no unit test can give it.

  **§A.1 — ACME front controls.** All passed: JWS `url` naming another host
  rejected against `base_url` (not the request Host); an EAB or `kid` naming
  another deployment rejected; account eviction on kid rename — **with the
  control first** (a new account under the renamed kid must succeed) — old
  account `newOrder` and `revokeCert` both 401; deactivation then 401;
  POST-as-GET of order/account/orders resolving while another account's
  certificate is refused; `/docs`, `/redoc`, `/openapi.json` all 404; the nonce
  ceiling returning a 204/429 mix with `Retry-After`.

  **§C — automated revocation, single-identity.** The enrollment gMSA was
  granted Certificate Manager (`0x2`, **not** Manage-CA) plus template-scoped
  `OfficerRights`, and the registered scheduled task ran as the gMSA: serials
  revoked at the CA and confirmed back to the RA, pending set draining. The
  least-privilege bound held live and visibly — `certutil -revoke` **succeeded**
  while the `-PublishCrl` republish was **denied** `0x80070005` (needs
  Manage-CA), and a certificate issued from a *different* template was refused
  `0x80094009 CERTSRV_E_RESTRICTEDOFFICER`.

  **§D — enrollment-side bound.** The gMSA's **live token** carries no Domain
  Computers membership (the WI-035 / Finding E-1 hardening persists), and
  issuance continued to work throughout.

  **2026-08-13 review findings, exercised against the deployment:** separated
  confirm authority — the admin token is refused on the confirm endpoint, the
  confirm token is accepted, and an unset confirm token disables the endpoint
  (finding 1); the sync agent refusing a non-https / credential-bearing / path-
  bearing RA URL **with a listener proving no request carrying the Bearer token
  left the host**, plus a control showing the listener would have caught one
  (finding 4); startup refusing an `audit_offbox_required` deployment whose sink
  cannot emit (finding 5); a certificate the CA issued outside policy
  **quarantined** — recorded with its serial and ReqID, order terminal-invalid,
  queued for CA-side revocation, and never served on a retried finalize
  (finding 6); an unknown nonce answered `400 badNonce` in ~44 ms rather than
  blocking on the writer lock (finding 7); credential floors refusing startup on
  short tokens and on an EAB `mac_key` decoding to zero bytes, while accepting
  every credential `scripts/eab.py` generates (finding 9); malformed JWS field
  types answered 4xx, not 500 (finding 10).

  **CRL evidence against a real ADCS CRL (closes proof gap 2).** With
  `revocation_confirm_require_crl_evidence` set, a serial the CA had really
  revoked confirmed as `verification: "crl-verified"`; the **negative control**
  — a serial absent from the CRL — was refused, fail-closed; with evidence made
  optional the same serial confirmed as `agent-asserted`. Note the operational
  coupling observed live: the serial only reached the CRL after an
  administrator republished it, because the scoped officer cannot.

  **Two defects found, fixed, and re-verified live** (see the CHANGELOG
  `[Unreleased]` entry): `Set-OfficerRights.ps1` aborting on a *successful*
  single-officer provisioning (a Windows PowerShell 5.1 `.Count` semantic the
  Linux Pester suite structurally cannot see), and `Sync-Revocations.ps1`
  aborting the whole batch on the first failed revoke instead of logging and
  continuing. Both were re-run against the CA after fixing: provisioning exits 0
  and reports the ACE correctly; the batch now continues past a failure and
  exits 2 (partial), as documented.

  - [x] §A re-cleared on the deployed commit (live issue + denial + revocation).
  - [x] §F revocation runbook re-exercised (`Sync-Revocations.ps1` +
        `Revoke-Cert.ps1` requester check, live at the CA).
  - [x] **The proven artifact is NOT the shipped artifact — a fresh full pass is
        required before the v1.9.0 tag.** Everything above ran against
        `26eae31`. The two fixes landed after it, as did the release-preparation
        changes (docs, an IPv6-loopback fix in `Assert-SafeRaUrl`, and
        `__version__`). The issuance leg is untouched by all of them and both
        defects were re-run live after fixing, but `Set-OfficerRights.ps1` and
        `Sync-Revocations.ps1` are not the bytes that were proved end-to-end
        from a clean start.

        This is not a formality. The runbook's cadence rule — *a full live
        re-proof at every release, on the exact commit being shipped* — is
        precisely what caught these two defects, and both were invisible to a
        green Linux CI run. Waiving it for the commit that fixes them would draw
        the wrong lesson. **Re-run the full runbook — §A, §A.1, §B or §C, §D,
        §E — against `v1.9.0-rc2`, from a clean start, and add a second
        validation-log entry before the v1.9.0 tag.** Full scope rather than
        the PowerShell delta: the lesson of this round is exactly that a subset
        does not transfer.

        **The target is now `v1.9.0-rc2`, not rc1.** A second external scan
        (2026-08-14, `docs/security-review-2026-08-14.md`) found seventeen more
        findings against rc1, two of them blocking, and all seventeen are fixed
        in rc2. The re-proof was correctly *not* run against rc1.

- **Additional cases the 2026-08-14 review adds to the re-proof.** These are
  the fixes whose correctness genuinely cannot be established off a real CA:

  - [x] **Reason 8 is refused, and never reaches `certutil`.** Submit a
        `revokeCert` with `reason: 8` → **400 badRevocationReason**, and the
        certificate must remain valid and absent from the pending list. Then run
        `Revoke-Cert.ps1 -Reason 8` directly → **exit 3**. Plan 004 recorded
        that reason 8 leaves a held certificate "off the CRL and valid", so the
        point is that no path can now emit it.
  - [x] **The transport-orphan quarantine, against a real CA.** The fix most in
        need of live proof, because provoking it means interrupting the RA
        between the CA's "issued" response and the chain fetch — and the whole
        question is what the CA is left holding. Confirm the certificate is
        recorded `quarantined` with its serial and ReqID, is queued for CA-side
        revocation, is never served, and that the order is terminal. Confirm the
        ReqID-only branch too (block `certnew.cer`): no row, but a loud audit
        row carrying the ReqID.
  - [x] **The pinned installer runs on Windows.** `--require-hashes` with
        `--only-binary :all:` is stricter than what the host did before, and the
        lock file was exported on Linux for Python 3.13 — a platform-specific
        wheel gap surfaces only here.
  - [x] **CRL freshness against the real publication cadence — measured
        2026-08-14, and the default does not fit.** The lab CA publishes weekly
        (`CRLPeriod = 1 Week`) and its CRL declares a **7d 12h 20m** validity
        window against a 7-day default ceiling, so the current CRL's age reaches
        the ceiling exactly as the next one is published: zero margin, and any
        delayed publication fails evidence checks. Set
        `revocation_confirm_crl_max_age_seconds` from the CA's real cadence
        (≥ `CRLPeriod` + overlap). The gate itself is live — a 1-second ceiling
        refuses the real CRL, and the default accepts it.
  - [x] **The unauthenticated GET forms are removed (finding 4, 2026-08-15).**
        Closed entirely on RFC 8555 conformance grounds: `GET /acme/cert/{id}`
        and `GET /acme/authz/{id}` and the `allow_unauthenticated_resource_get`
        flag are gone; only account-scoped POST-as-GET remains, and a plain GET
        returns 405. The re-proof should confirm Certify the Web completes a full
        round-trip against the POST-as-GET-only RA; if it does not, that is a CtW
        bug to file. (The test harness already drives a complete order to
        issuance via POST-as-GET only.)
  - [x] **The revocation agent runs with only `-ConfirmToken`.** No admin token
        on the revocation host: confirm the pending-list read still works and
        the whole loop completes.
  - [x] **A failed confirm exits 2.** Point the agent at an RA that will refuse
        the confirm; the CA-side revocation should succeed, the serial stay
        pending, and the script exit 2 rather than 0.
  - **Still open before pilot:** the operator-owned items in §B–§E, unchanged.
  - **Lab returned to its pre-run state:** CA `OfficerRights` removed and the CA
    security descriptor restored byte-for-byte, the temporary group membership
    removed, the throwaway template deleted and unpublished, every test
    certificate revoked and the CRL republished, scheduled tasks unregistered,
    RA database and dotenv restored from a pre-run backup, app pool left running
    as found. The RA venv now holds the **v1.9.0** package (it held v1.7.0 before
    the run).

- **2026-06-24 — §A cleared.** Working tree committed; CI green on the deployed
  commit (`lint-typecheck-test` 3.12/3.13 + `pip-audit`); **live re-issue against
  the deployed commit performed on the lab.** A full ACME round-trip
  (new-account → new-order → challenge → finalize) driven through the deployed RA
  (IIS app pool as the gMSA) issued a real **serverAuth-only** cert with the
  **SAN from the CSR**, off the existing CA, chaining leaf → issuing CA → existing
  root (no new intermediate); the CA database recorded the requester as the gMSA.
  A first attempt was correctly **denied by the CA policy module**
  (`CERTSRV_E_KEY_LENGTH`, an EC test key below the template's minimum) and the RA
  mapped it to `400 rejectedIdentifier` — incidentally exercising the new
  enrollment-error wiring against a genuine CA denial. The throwaway test cert was
  revoked CA-side and the temporary EAB credential removed.
  - **Still open before pilot:** all operator-owned items in §C.4 (network
    allowlist), §C (EAB rotation procedure), §D (admin token), §E (rate
    limiting, crons, monitoring), and the §F revocation-runbook acknowledgement.

- **WI-015 — PASSED (2026-07-13):**
  Live re-proof against commit `7d5c5b9` on the lab RA host. Full ACME
  round-trip (new-account → new-order → challenge → finalize) through the
  deployed RA (IIS app pool as the gMSA, port 9443) issued
  a real **serverAuth-only** cert with the **SAN from the CSR**
  (`reproof.WORK-DOMAIN.local` placeholder — real lab hostname recorded in
  gitignored local notes, not committed per the AGENTS.md identifier rule),
  off the existing CA (`CN=CA01` → existing root, no new intermediate). Serial
  redacted (real lab serial kept in gitignored local notes). A policy-denial
  (out-of-scope SAN `evil-example-com.test`) was rejected at finalize
  with `400`. Revocation with reason=1 succeeded (cert → revoked, GET →
  410). Reason 7 was rejected with `badRevocationReason`. The re-proof
  also found and fixed a Windows-specific SQLite bug (`DELETE ... LIMIT`
  in the probabilistic nonce GC; replaced with a portable subquery).
  - [x] §A re-cleared on the new commit (CI green on the deployed SHA; live
        re-issue + denial + revocation performed).
  - [x] §F revocation runbook acknowledged (`docs/operations.md` ##
        Revocation runbook; `scripts/Revoke-Cert.ps1` lab-validated revoking a
        throwaway cert; reason 7 rejection confirmed at the RA surface).
  - [x] The proven artifact == the shipped artifact (same SHA `7d5c5b9`).

- **MED-1/MED-2 re-proof — PASSED (2026-07-14):**
  Live re-proof against commit `c283d81` on the lab RA host (IIS app pool
  as the gMSA, ADCS CA in Mode A). All 15 test cases passed:

  1.  Account creation (EAB) — PASS
  2.  Order creation (in-scope SAN) — PASS
  3.  Challenge completion — PASS
  4.  Finalize (CSR → real cert from ADCS) — PASS
  5.  Certificate download — PASS
  6.  SAN in cert matches request — PASS
  7.  serverAuth EKU only (no clientAuth) — PASS
  8.  Chain off existing CA (leaf → issuing CA → root, no new intermediate) — PASS
  9.  Policy denial (out-of-scope SAN rejected at finalize) — PASS
  10. Revocation (reason=1, RA store) — PASS
  11. Revoked cert → 410 Gone — PASS
  12. Reason 7 rejected — PASS
  13. **MED-1 positive**: multi-SAN issue (two in-scope SANs), all issued
      cert SANs verified within order scope, no non-DNS SANs — PASS
  14. **MED-1 audit**: zero `finalize-issued-cert-san-mismatch` events in
      the audit log — PASS
  15. **MED-2**: revocation CAS completed deterministically, audit records
      `revocation_scope=ra-store-only`, `ca_crl_updated=false` — PASS

  CA-side verification (via domain admin on the CA host): CA database
  confirms Requester = `WORK-DOMAIN\gMSA-acme-ra$` for both test certs,
  Template = `ACME-ServerAuth`, Disposition = Issued. Both test certs
  revoked CA-side (reason=1) and CRL republished. Lab database restored
  to pre-test state; temporary scripts removed.
  - [x] §A re-cleared on commit `c283d81` (live re-issue + denial +
        revocation + MED-1/MED-2 performed).
  - [x] The live proof ran against source commit `c283d81`; the RC prep
        commit (`4942178` and subsequent fixes) adds only non-issuance
        artifacts (CHANGELOG, SECURITY, CI, checklist). The issuance-path
        source is unchanged between the proof and the RC tag.

- **2026-07-15 — parked at v1.0.0; lab deployment stopped.** The project is
  parked (feature-complete, no active development; see `AGENTS.md` ## Status).
  The lab RA's IIS app pool was **stopped** (verified: pool state `Stopped`,
  ACME directory endpoint unreachable) so no standing enrollment-capable
  identity runs unattended while parked. The deployment remains installed and
  configured — re-enabling for a pilot is `Start-WebAppPool` plus a fresh run
  through this checklist (§A first: re-proof on the deployed commit).

- **WI-028 — v1.5 automated-revocation re-proof — PASSED (2026-07-23):**
  Live E2E re-proof of the v1.5 build (automated revocation + WI-026 EKU
  self-enforcement) on the lab RA host, plus the **single-identity** deployment
  option (Plan 006). Base issuance re-proof went 12/12 (issuance, serverAuth-only
  EKU verified live, chain off the existing CA, out-of-scope SAN denied, revoke →
  410, reason-7 rejected). For revocation, the enrollment gMSA was provisioned as
  a **template-scoped officer** (Certificate-Manager only — no Manage-CA) and the
  `Sync-Revocations.ps1 -LocalMode` agent, scheduled as that gMSA, **revoked
  `ACME-ServerAuth` certs at the CA and confirmed them back to the RA**
  (`ca_crl_updated=true`; pending set drained to empty; CA DB Disposition =
  Revoked). The least-privilege bound held live: `certutil -CRL republish` was
  **denied** for the officer identity (needs Manage-CA), so the default loop skips
  it and relies on scheduled CRL publication (`-PublishCrl` is the opt-in for
  immediate freshness, gated on granting Manage-CA — see threat-model §E). The
  pass found and fixed six PowerShell defects (see `CHANGELOG.md` [Unreleased]
  Fixed); all fixes were re-validated live. CA returned to a pristine baseline
  (no OfficerRights, CA-Security restored) and the RA re-parked (tasks removed,
  app pool stopped) afterward.
  - [x] §A issuance-leg re-proof on the v1.5 build (issuance + WI-026 EKU).
  - [x] Automated revocation round-trip proven (RA `revokeCert` → agent →
        CA revoke → RA confirm) with WI-022 requester check + WI-025 officer
        restriction both active.
  - [ ] **Still open before pilot:** the operator-owned §B–E items, the
        Finding E-1 remediation (enrollment gMSA's Domain Computers membership
        confers `Machine`-template enroll; see `docs/revocation-scope-validation.md`),
        and cutting the v1.5.0 release (WI-029).

- **Plan 007 v1.6 hardening sweep (2026-07-23/24):**
  - **WI-035 (Finding E-1) — REMEDIATED + VERIFIED.** Enrollment gMSA moved off
    the Domain Computers enroll path (`primaryGroupID` change); verified by
    template ACLs, the gMSA's live token (no Domain Computers), and an issuance
    regression pass. It can now enroll only `ACME-ServerAuth`. See
    `docs/revocation-scope-validation.md` Finding E-1.
  - **WI-036 (two-identity topology) — PROVEN LIVE (2026-07-24).** A dedicated
    revoker gMSA (`gMSA-acme-rev`, separate identity) held template-scoped officer
    rights while the enrollment gMSA held **none**, and ran the full round-trip: RA
    `revokeCert` → pull agent as the revoker → `certutil -revoke` at the CA → RA
    confirm. Verified: WI-022 requester check passed, CA-DB disposition =
    **Revoked**, RA pending drained to empty, compromise independence held,
    least-privilege CRL skip applied. **The earlier block was an unrelated homelab
    AD defect, NOT clock skew (that was ruled out):** a gMSA created without an
    explicit `msDS-SupportedEncryptionTypes` gets RC4 added, which the DCs block,
    so its Kerberos fails and its managed password is unusable — create revoker
    gMSAs with **AES128,AES256** (see `docs/live-reproof-runbook.md`).
  - **WI-037/038/039 — DONE.** Pester pure-logic suite (CI); the live re-proof
    runbook (`docs/live-reproof-runbook.md`) + cadence; deterministic CI
    (`uv sync --locked`, pinned linters/Pester).

- **2026-08-07 security-hardening re-proof — PASSED (2026-08-08):**
  Live re-proof of commit `5d30937` (the 2026-08-07 security review: CA-capable
  CSR/cert rejection, CN→SAN binding, certsrv key binding, rate-limit TOCTOU
  fix, JWS streaming cap, algorithm exactness, EAB URL binding, HEC HTTPS
  enforcement, cryptography ≥50.0.0) on the lab RA host (the lab Windows
  host, IIS app pool as the gMSA, ADCS CA `CA01` in Mode A). Deployed the
  1.6.0 wheel + cryptography 50.0.0 into the app-pool venv; app pool started;
  `/directory` → 200.

  **Core 12 cases (all PASS):** account creation (EAB) → order (in-scope SAN)
  → challenge → finalize (CSR→real cert) → download → SAN matches CSR →
  serverAuth EKU only (no clientAuth) → chain off existing CA (leaf → issuing
  CA → existing root, no new intermediate) → out-of-scope SAN denied at
  finalize → revoke (reason=1, RA store) → revoked cert 410 Gone → reason 7
  rejected (`badRevocationReason`). Serial `6C00…006C`, RequestID 108.

  **New security-hardening checks (3/3 PASS):** CSR with
  `BasicConstraints CA=true` → rejected at finalize; CSR with `keyCertSign`
  KeyUsage → rejected; CSR with out-of-scope CN (not in SAN set) → rejected.
  All three exercise the new `csr_validation` rejection paths before the CSR
  reaches ADCS.

  **CA-side verification (via domain admin on the CA host):** CA DB RequestID
  108 confirms **Requester = `WORK-DOMAIN\gMSA-acme-ra$`** (the enrollment
  gMSA), **Template = `ACME-ServerAuth`**, **Disposition = Issued**. The
  w3wp.exe + python.exe process owners are both the gMSA (confirmed via
  `Win32_Process`). The RA audit-log `requester` field shows the RA host's
  machine account — this is a known artifact of the `_requester()` best-effort
  env-var capture (`USERNAME` resolves to the machine account for gMSAs, not
  the gMSA name); the authoritative CA DB shows the gMSA.

  **Teardown:** app pool stopped (re-parked); DB restored from backup; test
  scripts removed. The test cert (serial `6C00…006C`, RequestID 108) is
  serverAuth-only, for a test hostname, and expires in 90 days; CA-side
  revocation via `certutil -revoke` / `ICertAdmin::RevokeCertificate` returns
  `ERROR_INVALID_PARAMETER` on this lab CA (a CA-level quirk, not code-related)
  — left as a harmless test artifact.

  - [x] §A issuance-leg re-proof on the security-hardening commit (core 12 +
        3 new CSR-rejection checks).
  - [x] cryptography 50.0.0 verified on Windows Server 2025 / Python 3.14.
  - [ ] **Still open before pilot:** the operator-owned §B–E items (unchanged).

- **2026-08-13 — security review closed in code, LIVE RE-PROOF OUTSTANDING.**
  Ten findings from an external static scan of v1.8.0, all independently
  reproduced first and all remediated (`docs/security-review-2026-08-13.md`).
  566 tests + 81 Pester tests green; `ruff` and `mypy --strict` clean; every new
  test mutation-checked.

  **This entry is deliberately not marked PASSED.** Unlike the 2026-08-07 and
  2026-08-11 rows above, no live lab re-proof has been run against this code.
  The issuance leg changed (`Store.record_issuance`, certificate quarantine, the
  `_certificate_response` valid-only gate), so §A must be re-run per
  `docs/live-reproof-runbook.md` before pilot.

  - [ ] **§A issuance-leg re-proof on the 2026-08-13 commit — NOT RUN.**
  - [ ] **CRL-evidence path never exercised against a real ADCS CRL.** Only
        enable `ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE` after proving
        it against the lab CA's published CRL.
  - [ ] **`Set-OfficerRights.ps1` restart assertions not run on a CA.** The new
        `Get-Service` / `Get-Process certsrv` checks are Windows-only and were
        parse-checked on Linux `pwsh` only.
  - [ ] **New required config before the revocation loop works:**
        `ACME_RA_REVOCATION_CONFIRM_TOKEN` on the RA and `-ConfirmToken` on the
        sync agent. Without it every confirm returns 401.
  - [ ] **Existing deployments: re-check credential strength.** EAB MAC keys
        < 32 bytes or admin tokens < 32 chars now refuse startup.
  - [ ] Still open before pilot: the operator-owned §B–E items (unchanged).

- **2026-08-11 — security review + live re-proof, PASSED.** Twelve findings from
  a pre-production-deployment review closed (`docs/security-review-2026-08-11.md`),
  plus a thirteenth found while reading real `certutil` output. Re-proved live
  against commit `db06c6f` on the lab RA (IIS app pool as the enrollment gMSA,
  ADCS CA, Mode A): **26 checks, 26 passed.** Section A unchanged (serverAuth-only
  EKU, SAN from the CSR, issuer `CONTOSO-CA01-CA`, out-of-scope SAN denied, reason-7
  rejected), and the new chain-binding verifier accepted the real CA's
  `certnew.p7b`. New controls proven live: EAB minted for another deployment
  rejected; `Host:`-header spoof rejected against a **catch-all `*:9443:`
  binding** (so the request genuinely reached the app); `kid` from another
  deployment rejected; order/account/orders POST-as-GET resolve; cert POST-as-GET
  is account-scoped; `/docs` `/redoc` `/openapi.json` all 404; a 220-request nonce
  flood capped (162×204, 58×429); account deactivation refuses the next request.
  **Account eviction proven with a control** (a new account under the renamed kid
  must still succeed, ruling out a false pass from a dotenv that failed to load):
  after the kid was pulled, both `newOrder` and — the case the pre-fix code
  allowed — `revokeCert` returned 401. Revocation round-trip completed through
  the real `Revoke-Cert.ps1` (`Confirm-SerialAtCa` found the row, WI-022 requester
  check confirmed the gMSA, `certutil -revoke` succeeded) and the confirm callback
  accepted the lowercase `certutil` serial form, draining the pending set.
  Also verified: `certutil` does **not** echo the `-restrict` clause, so
  `Confirm-SerialAtCa`'s existence test is sound (a flagged concern, cleared).
  Lab left as found — RA parked (pool stopped, endpoint unreachable, dotenv/DB/
  web.config restored), CA pristine (no `OfficerRights` ever written), all
  session certificates revoked at the CA, temp cleared on both hosts.
  - **Still open before pilot:** the operator-owned items in §B–§E, unchanged —
    plus the two new required items (off-box audit sink, network allowlist).

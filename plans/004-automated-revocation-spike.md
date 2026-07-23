# Plan 004 — Automated revocation without gMSA privilege growth (officer-restriction spike)

**Status:** DONE — WI-021 spike PASSED (template-scoped officer restriction proven
live); the mechanism ships as part of v1.5 (see [Plan 005](005-v1.5-feature-complete.md)),
and the automated loop was live-reproven end-to-end on 2026-07-23. Authored
2026-07-22 by Claude (Opus 4.8) after a live mechanism investigation on the lab
CA (`WORK-DOMAIN-CA`). **WI-021 PASSED 2026-07-22/23** — template-scoped revocation
proven live end-to-end: a cleanly-provisioned restricted officer revokes its
**allowed** template (success) and is denied the **disallowed** template
(`CERTSRV_E_RESTRICTEDOFFICER`). The GUI `OfficerRights` format is fully decoded and
a CA-accepted headless builder is validated. Deployment constraints: the revoker
must not belong to any broader cert-manager group (union semantics) and needs
`Certificate Service DCOM Access`. See the "Live proof" subsections under WI-021.
**Author:** Claude (Opus 4.8)

> **One-line thesis:** revocation *can* be automated without giving the
> enrollment gMSA any CA-officer rights — by moving the privilege onto a
> **separate CA-side identity whose officer power is scoped, by the CA itself,
> to the one template the RA issues** (`ACME-ServerAuth`). Microsoft's
> "Restrict Certificate Managers" feature makes this a CA-enforced boundary, not
> an agent-logic convention. The feature exists and covers revocation (Microsoft
> docs); the CA enforces `OfficerRights` on presence (proven live). The one
> unconfirmed link is an *observed* template-scoped denial on this CA — blocked
> because a CA-valid `OfficerRights` descriptor could not be built headlessly
> (the config is a GUI/reference-validated-builder job, confirmed empirically).

## Why this plan exists

Today (WI-010, decided 2026-06-30) revocation is deliberately out-of-band: the
RA's `revokeCert` marks its own store (`revocation_scope=ra-store-only`,
`ca_crl_updated=false`) and a **human CA officer** runs `scripts/Revoke-Cert.ps1`
to write the CA CRL. The tightest security tenet is that the **enrollment gMSA
(`gMSA-acme-ra$`) must never gain CA-officer ("Manage CA") rights** — a
compromised RA host would otherwise be able to revoke *any* certificate on the
CA (`docs/threat-model.md` §E).

The question this plan answers: **can we automate the out-of-band step without
weakening that tenet?** The answer is yes, and it rests on a reframe — the tenet
constrains *the RA-host identity*, not *automation of revocation*. Authority can
live on the CA side under a different, tightly-scoped principal that the RA host
never possesses.

## Findings from the live mechanism investigation (2026-07-22)

All confirmed against the lab CA `WORK-DOMAIN-CA` (config `CA01\WORK-DOMAIN-CA`),
via `ca-localadmin` SSH (local reads) and the scheduled-task-as-`ca-admin` dodge
(domain-authenticated ops). No CA state was changed — every step was read-only
or fully torn down.

1. **Template-scoped revocation is a real, documented ADCS control.** Microsoft's
   *Restrict Certificate Managers* feature refines a certificate manager's
   ability to **approve requests _and revoke_ certificates** "based on a subset
   of the certificate templates" (and by subject group). The premise "we can't
   scope revocation to the template" is **refuted by Microsoft's own docs**.
   Source: learn.microsoft.com "Restrict Certificate Managers"
   (`cc753372(v=ws.10)`).
2. **Storage:** the restriction lives in the CA's local registry value
   `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\WORK-DOMAIN-CA\OfficerRights`
   (REG_BINARY). On this CA it is **currently absent** → certificate managers
   are presently **unrestricted** (default). Confirmed live.
3. **Binary format:** `OfficerRights` is a `SECURITY_DESCRIPTOR` whose DACL uses
   **callback ACEs** (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE` / `..._DENIED_...`).
   After the ACE header + AccessMask + trustee SID, the opaque callback data is:
   `SID-count (DWORD LE)` → `SID array` (subject/group restrictions; each SID
   `8 + 4*SubAuthorityCount` bytes) → `certificate template` (Unicode string:
   v1 template CN, or v2+ template OID). One ACE per (officer, template).
   Source: sysadmins.lv "How to read ADCS Enrollment Agent/Certificate Manager
   rights in PowerShell" (Vadims Podans, PSPKI author).
4. **There is NO clean headless configuration path.** `certutil` has no officer
   command; **PSPKI 4.4.1** (the usual tool) exposes only CA *Security* cmdlets
   (`Get/Set-CASecurityDescriptor`, `Add/Remove-CAAccessControlEntry` — the
   coarse `ManageCertificates` role, no template dimension) and **no**
   officer-rights API; the CA object has no `GetOfficerRights` method. The PSPKI
   author states plainly: *"there is no built-in way"* to modify these
   structures — configuration is the **certsrv.msc GUI** (Certificate Managers
   tab) or **custom callback-ACE construction** written via
   `ICertAdminD2::SetOfficerRights` / the registry. **Decision-relevant for an
   IaC posture:** the one-time restriction setup is GUI-or-custom-code, not
   `terraform`/PSPKI. (Acceptable — it is a *one-time* control, unlike the
   revoke loop which must be automated.)
5. **Test targets exist and confirm requester-scoping.** The CA holds 13 issued
   `ACME-ServerAuth` certs (template OID
   `<ACME-ServerAuth-template-OID>`),
   **all** with `Request.RequesterName = WORK-DOMAIN\gMSA-acme-ra$`, alongside
   `Machine` (×4) and `DomainController` (×3) certs from other requesters — a
   clean allowed/disallowed target split for the enforcement proof.

## The design (once WI-021 passes)

Two CA-enforced boundaries, plus a defense-in-depth check, none touching the
enrollment gMSA:

- **Primary control — CA-enforced template restriction.** A *dedicated* officer
  gMSA (`gMSA-acme-revoker$`), granted "Issue and Manage Certificates," then
  restricted via `OfficerRights` to **only** `ACME-ServerAuth`. Even a fully
  compromised revoker — or a compromised RA feeding it serials — cannot revoke a
  DC/Machine cert, because the CA refuses officer operations outside the allowed
  template. This is the boundary that makes automation safe.
- **Defense-in-depth — requester check in the agent.** Before each revoke, the
  agent confirms `Request.RequesterName == WORK-DOMAIN\gMSA-acme-ra$` from the
  authoritative CA DB (harden `Confirm-SerialAtCa` in `scripts/Revoke-Cert.ps1`,
  which today confirms existence but not requester). Cheap; catches the case
  where the ACME template is ever shared with another enroller.
- **CA-side pull agent.** Runs **on the CA** (local `certutil -revoke`, no
  Kerberos double-hop) as `gMSA-acme-revoker$`. Pulls the RA's drift set — the
  `revoked_in_ra_active_at_ca` bucket that `scripts/reconcile_revocation.py`
  already computes — and closes the loop. Source of "what to revoke" = the RA;
  authority to revoke = CA-side, template-bounded. The RA host never holds it.
  Transport: a read-only, Kerberos-auth'd `GET /admin/revocations/pending` on
  `routes/admin.py` (cleaner than sharing the SQLite file cross-host), restricted
  to the revoker principal.
- **Fail-visible, one-directional.** Dry-run default; every auto-revoke lands in
  the CA DB (under the revoker identity) and flips the RA audit's
  `ca_crl_updated` → true. Keep it RA→CA only; the reverse bucket
  (`revoked_at_ca_valid_in_ra`) stays a human review item.

**Complementary lever (separate, not in this plan):** short-lived certs +
auto-renew shrink the incident window so the agent is a backstop, not a hot path.

## Honest costs

- **A new high-value credential.** `gMSA-acme-revoker$` is a CA officer. We
  relocate the privilege off the RA host and CA-bound it to one template; we do
  not eliminate it. It must be a gMSA (passwordless), constrained to log on only
  to the CA, and fully audited.
- **One-time config is GUI/custom-code.** See Finding 4. If a custom callback-ACE
  builder is written, it is security-descriptor-on-a-live-CA code and earns its
  own review; the GUI path avoids that at the cost of a manual step.

---

## WI-021 — Live enforcement proof (the gate)

**Claim to falsify:** *an officer restricted to `ACME-ServerAuth` is denied
`certutil -revoke` on a non-ACME cert, and permitted it on an ACME cert.*

The design question is settled by Microsoft's docs (Finding 1); WI-021 confirms
**this CA enforces as documented** and shakes out CA-specific gotchas — the
"lab catches integration bugs" tenet. It is the single gate: no revoker gMSA, no
pull agent, and no `Revoke-Cert.ps1` requester hardening ship until it passes.

**Prereqs / seams already verified:** storage location, current unrestricted
state, `ca-admin` scheduled-task automation, and the ACME-vs-Machine target split
are all confirmed (Findings 2/4/5).

**Procedure (all reversible; run on `WORK-DOMAIN-CA`):**
1. Create throwaway manager principal `revoker-test` (via `ca-admin`), known password.
2. Grant it "Issue and Manage Certificates" on the CA
   (`Add-CAAccessControlEntry -AccessType Allow -AccessMask ManageCertificates`).
   **Not** CA Administrator, **not** a Domain Admin (admins may bypass officer
   restrictions — the test principal must be a plain manager).
3. Configure `OfficerRights`: one `ACCESS_ALLOWED_CALLBACK_ACE` for `revoker-test`'s
   SID, template = the `ACME-ServerAuth` OID, subject-SID-count = 0 (all
   subjects). Preferred path = **certsrv.msc GUI** (correct by construction);
   alternative = a reviewed custom callback-ACE builder (Finding 3). Restart
   `certsvc`. **Verify well-formed by reading it back** with a `Get-OfficerRights`
   parser before trusting any result.
4. As `revoker-test` (scheduled task `/RU revoker-test /RP …`):
   - `certutil -revoke <ACME serial> 6` (CertificateHold — reversible) → **expect
     success**.
   - `certutil -revoke <Machine serial> 6` → **expect Access Denied**.
5. **Interpretation:** a clean *allow-on-ACME + deny-on-Machine* is trustworthy
   even under residual format uncertainty — only correct template-scoped
   enforcement produces exactly that split. A deny on *both* means the blob is
   wrong (redo via GUI), not that the feature fails.
6. **Teardown:** lift the held ACME cert (`certutil -revoke <serial> 8`
   removeFromCRL), delete the `OfficerRights` value, restart `certsvc`, remove the
   CA ACE, delete `revoker-test`. Confirm `OfficerRights` absent + managers
   unrestricted (back to the state this investigation left the CA in).

**Note on lab hygiene:** the `ca-admin` password reaches the CA only as a scp'd
file consumed by the scheduled-task runner, shredded locally and deleted from the
box immediately. Never place it on a command line.

### Live spike results — 2026-07-22 (partial: enforcement split NOT reproduced headlessly)

Ran the full procedure on `WORK-DOMAIN-CA`. Outcome, stated plainly:

**Proven live:**
- **Enable semantics = presence.** The CA consults `OfficerRights` per-operation
  and activates enforcement on the mere presence of the value (no separate enable
  flag). Demonstrated by behavior change: with the value present the CA changed
  how it processed officer operations; deleting it restored the prior behavior.
- **The whole test harness works.** Throwaway domain officer (`revoker-test`,
  created via ADSI — the AD PS module isn't on the CA), CA-Security grant of
  `ManageCertificates`, the "Log on as a batch job" grant required for a fresh
  principal to run under the scheduled-task-as-user dodge, and revoke-as-
  restricted-officer all function. Once a **CA-accepted** `OfficerRights` blob
  exists, the allow/deny test runs immediately.
- **The `OfficerRights` binary format is stricter than the .NET SD reader.** A
  blob built with `System.Security.AccessControl` that round-trips *correctly*
  through the authoritative `Get-OfficerRights` **reader** (AceType 9, SidCount,
  template OID all parse back) is **rejected by the CA**: every officer operation
  (revoke, even as unrestricted `ca-admin`/local admin) then fails
  `0x80070057 ERROR_INVALID_PARAMETER`, and removing the value instantly restores
  healthy revocation. Two constructions were tried — a 4-ACE blob (admins = all
  templates, `revoker-test` = ACME, all-bits mask) and a minimal 1-ACE blob
  (`revoker-test` = ACME, mask = `ManageCertificates`/2) — **both rejected**. This is
  the empirical confirmation of the PSPKI author's warning: hand-building a
  CA-valid officer-rights descriptor is not reliably achievable without a
  GUI-produced reference sample.

**NOT proven live:** the clean *allow-ACME / deny-Machine* enforcement split.
It was blocked upstream — I could not headlessly produce an `OfficerRights` blob
the CA accepts, so the officer restriction never actually took effect. The
template-scoping of revocation therefore still rests on **Microsoft's
documentation + the certsrv.msc GUI**, not on an observed denial on this CA.

**What this changes:** it *reinforces* the "configure once via the GUI"
recommendation — the GUI produces a correct blob by construction, whereas a
custom builder needs a captured GUI sample to reverse-engineer the exact
byte-level requirements (candidate unknowns: the precise AccessMask, whether
"all templates" is expressible as a no-template ACE, ACL revision, ACE ordering).

**Revised WI-021 gate:** apply the restriction via **certsrv.msc** (an operator
GUI action — the one-time step the owner has already accepted), then run the
(working) `revtest` harness as `revoker-test`: revoke an ACME cert (expect success)
vs a Machine cert (expect Access Denied). If a fully headless path is ever
required, first **capture a GUI-produced `OfficerRights` blob** (`certutil -getreg
CA\OfficerRights`) as the reference to build against — do not hand-roll blind.

**CA left pristine:** `OfficerRights` absent, CA Security back to its original
four entries, `revoker-test` deleted, batch-logon grant reverted, CRL republished.
The one ACME spike cert used for the (failed) allow-test was placed on hold and
then removed-from-CRL (reason 8) — ADCS keeps its DB `Disposition` at 21
historically but it is off the CRL and valid; it is a throwaway gMSA test cert.

### Live proof — 2026-07-23 (enforcement PROVEN; one viability blocker OPEN)

An operator applied the restriction via the certsrv.msc GUI (`revoker-test` →
`ACME-ServerAuth` only) and captured a matrix of GUI-produced `OfficerRights`
blobs. Running the harness against that GUI config:

- **Template-scoped revocation IS ENFORCED.** The restricted officer revoking a
  **non-ACME (`Machine`) cert** is denied with
  **`0x80094009 CERTSRV_E_RESTRICTEDOFFICER`**. Combined with Finding 1 (docs),
  template scoping is now confirmed both documentarily and empirically.
- **Exact GUI format decoded** (fixes the two bugs in my rejected blob): SD
  control `0x8004`, ACL rev 2, one callback ACE per (officer, template),
  **AccessMask `0x00010000`** (not `0xFFFFFFFF`/`2`), opaque =
  `[SidCount u32][subject SIDs][template UTF-16LE+null]`, **"all subjects" =
  SidCount 1 + Everyone `S-1-1-0`** (not SidCount 0 — that was the rejection),
  "all templates" = an Everyone entry with no template bytes, deny =
  `DENIED_CALLBACK`. A byte-correct headless builder is now writable and
  offline-validatable against the captures.
- **GOTCHA (union semantics):** officer rights are evaluated across the caller's
  entire token; a restricted principal that also belongs to an **unrestricted
  cert-manager group** can revoke anything. **The revoker gMSA must not be a
  member of any broader cert-manager group.**
- **GOTCHA:** the revoker needs **`Certificate Service DCOM Access`** or the
  revoke fails `0x8007000d INVALID_DATA`.
- **VIABILITY CONFIRMED (blocker resolved).** A *cleanly* provisioned restricted
  officer (freshly created, only its own ACME entry, with DCOM access + batch
  logon) revokes its **allowed** template with **`exit 0` (success)** and is denied
  the **disallowed** template with **`CERTSRV_E_RESTRICTEDOFFICER`**. The earlier
  `INVALID_DATA` was an artifact of a principal churned mid-test (group removal +
  DCOM add + replication), not the subject restriction — the GUI-default `Everyone`
  subject works fine against a gMSA-requested cert. **The design works.**
- **Final format fix for a headless builder:** the SD **must carry an owner SID
  (`S-1-5-32-544`, BUILTIN\Administrators)** — a self-relative SD with no owner is
  rejected (`0x80070057`). Full recipe: control `0x8004`, owner `S-1-5-32-544`, no
  group, ACL rev 2, per-officer callback ACE mask `0x00010000`, opaque
  `[SidCount][subject SIDs][template UTF-16+null]`, all-subjects = SidCount 1 +
  Everyone, all-templates = Everyone entry with no template, deny = DENIED_CALLBACK.
  A builder producing a CA-accepted, correctly-enforcing blob is validated live.

## Downstream work items (gated on WI-021)

- **WI-022** — `Revoke-Cert.ps1` requester hardening: assert
  `RequesterName == WORK-DOMAIN\gMSA-acme-ra$` in `Confirm-SerialAtCa` before revoke;
  add a `-RequesterName` parameter (default the gMSA). Pure defense-in-depth;
  no issuance-path change.
- **WI-023** — `GET /admin/revocations/pending` read-only endpoint on
  `routes/admin.py` (Kerberos-auth, restricted to the revoker principal),
  emitting the `reconcile_revocation.py` drift set.
- **WI-024** — the CA-side pull agent (scheduled task on the CA as
  `gMSA-acme-revoker$`): pull → per-serial requester check → `Revoke-Cert.ps1` →
  reflect closure back to the RA audit (`ca_crl_updated=true`). Dry-run default.
- **WI-025** — provisioning runbook for `gMSA-acme-revoker$` + the officer
  restriction (GUI walkthrough + optional reviewed builder), in
  `docs/operations.md` ## Revocation runbook.
- **Threat-model addendum** — `docs/threat-model.md` §E gains the "automated,
  template-bounded, CA-side" option alongside today's manual out-of-band path,
  with the new credential's blast-radius analysis.

## What this plan explicitly rejects

- **Granting the enrollment gMSA officer rights + an in-band leg.** The
  `RevocationLeg` protocol allows this drop-in, but it is the exact
  privilege-concentration the tenet forbids.
- **An RA-side OCSP/CRL surface.** Issued certs' AIA/CDP point at the CA's chain
  (no new intermediate), so relying parties won't consult an RA-published status.

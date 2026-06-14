# Configuring the ADCS enrollment surface (Mode A and Mode C)

How to stand up the `/certsrv/` Web Enrollment surface that acme-adcs-ra submits
CSRs to, in the two supported topologies. **Mode A** puts Web Enrollment on the
issuing CA itself; **Mode C** puts it on a separate host to keep the CA role-pure.

> **Status / honesty:** the cmdlets below are the canonical ADCS steps, but exact
> flags and — for Mode C — the delegation configuration **must be validated on
> the lab (CA01) before they are trusted for production.** The lab spike
> (`plans/001`) exists to do exactly that. Treat this as the runbook to *execute
> and correct*, not as verified-as-written.
>
> Placeholders: `CA01` = issuing CA host; `WORK-DOMAIN.local` = AD domain;
> `CONTOSO-CA01-CA` = the CA's config name (`certutil -getreg CommonName`);
> `gMSA-acme-ra$` = the RA's group Managed Service Account.

---

## Shared prerequisites (both modes)

### 1. A scoped issuing template

Duplicate "Web Server" → e.g. **`ACME-ServerAuth`**:
- **Compatibility:** CA and recipient set to your current OS baseline.
- **Extensions → Application Policies (EKU):** **Server Authentication only.**
  Remove Client Authentication. (This is the blast-radius bound — see
  `architecture.md`.)
- **Subject Name:** *Supply in the request* (subject + SAN come from the CSR).
- **Security:** grant **`gMSA-acme-ra$`** *Read* + *Enroll* only. No Autoenroll,
  no broad groups.
- **Issuance Requirements:** no manager approval (the RA is the gate); CA
  certificate manager approval would break automation.
- Publish the template on the CA: `Add-CATemplate -Name "ACME-ServerAuth"`.

### 2. The gMSA the RA runs as

```powershell
# Once per forest, if not already present:
Add-KdsRootKey -EffectiveImmediately   # (lab: -EffectiveTime ((Get-Date).AddHours(-10)))

New-ADServiceAccount -Name "gMSA-acme-ra" `
  -DNSHostName "acme-ra.WORK-DOMAIN.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "ACME-RA-Hosts"   # group containing the RA host(s)

# On the RA host:
Install-ADServiceAccount -Identity "gMSA-acme-ra"
Test-ADServiceAccount  -Identity "gMSA-acme-ra"
```

Run the acme-adcs-ra service under `WORK-DOMAIN\gMSA-acme-ra$` so its ambient
Kerberos identity is what authenticates to `/certsrv/`.

---

## Mode A — Web Enrollment on the CA (CA01)

Simplest, and matches the production CA's existing posture. **No Kerberos
delegation needed** — the enrollment app and the CA are the same machine, so the
request is submitted locally.

### A.1 Install + configure the role service (on CA01)

```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -CAConfig "CA01\CONTOSO-CA01-CA" -Force
```

This creates the `/certsrv/` IIS application on CA01 (CA01 already runs IIS for
the OCSP responder, so this is incremental, not net-new IIS).

### A.2 Lock down `/certsrv/` authentication (IIS on CA01)

- **Windows Authentication: enabled; Anonymous: disabled** on the `/certsrv/`
  app.
- Prefer **Negotiate (Kerberos)** providers; keep Negotiate above NTLM.
- Require **HTTPS** on the site (bind a server-auth cert; CA01 can issue its own).
- Restrict access to the RA host at the IIS/firewall layer (the RA is the only
  legitimate caller).

### A.3 Verify

From the RA host, running as the gMSA, a Negotiate-authenticated POST to
`https://CA01/certsrv/certfnsh.asp` with a test CSR should return an issued cert.
(The spike automates this with `requests-negotiate-sspi`.) Confirm the cert
appears in the CA database with requester = `gMSA-acme-ra$`.

**Trade-off:** adds an enrollment surface to the CA box. Bounded by gMSA-only
Enroll + the server-auth-only template.

---

## Mode C — separate enrollment host (CA stays role-pure)

Keeps Web Enrollment / CES off the CA. The catch: a separate enrollment host
enrolls **on behalf of** the requester, so it needs **Kerberos constrained
delegation** to the CA. This is the real added complexity vs. Mode A.

### Option C1 — Web Enrollment on a separate member server

On a separate host (e.g. `ENROLL01`):

```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -CAConfig "CA01\CONTOSO-CA01-CA" -Force
```

Then configure **constrained delegation** so `ENROLL01` (or the app-pool/gMSA
identity) may impersonate to the CA's enrollment service:

- On the `ENROLL01` computer (or service) account, allow delegation to the CA's
  service:
  ```powershell
  Set-ADComputer ENROLL01 -Add @{ 'msDS-AllowedToDelegateTo' =
    'HOST/CA01.WORK-DOMAIN.local','RPCSS/CA01.WORK-DOMAIN.local' }
  # Use "Kerberos only" (constrained), not unconstrained delegation.
  ```
- Ensure correct SPNs exist for CA01 and for the enrollment site.

Web Enrollment's on-behalf-of model is exactly why this delegation is required;
getting the SPNs/delegation right is the bulk of Mode C's effort and the thing to
prove on the lab.

### Option C2 — Certificate Enrollment Web Service (CES)

CES is the supported, "designed for a separate host" enrollment service
(MS-WSTEP/SOAP). On the CES host:

```powershell
Install-WindowsFeature ADCS-Enroll-Web-Svc -IncludeManagementTools
Install-AdcsEnrollmentWebService `
  -CAConfig "CA01\CONTOSO-CA01-CA" `
  -AuthenticationType Kerberos `
  -ServiceAccountName "WORK-DOMAIN\gMSA-acme-ra$"
# CES likewise requires constrained delegation to the CA (renewal-on-behalf-of).
```

**Cost:** CES speaks **WSTEP (SOAP)**, not the simple `/certsrv/` POST — so the
RA's enrollment leg would implement WSTEP instead of the certfnsh.asp form, which
is more protocol work and is **not** the acme2certifier reference path. Choose C2
only if a role-pure CA is worth the heavier client.

### C verify

Same as A.3, but targeting the separate host, and additionally confirm the
delegation actually lets the enrollment host forward to CA01 (the failure mode is
a Kerberos delegation/SPN error, not an auth-to-the-frontend error).

---

## Choosing A vs C

| | Mode A (on CA) | Mode C (separate host) |
|---|---|---|
| CA stays role-pure | no | yes |
| Kerberos delegation needed | **no** | **yes** (the main effort) |
| Matches prod CA posture | yes (prod already has it) | no |
| Reference impl path | yes (`/certsrv/` POST) | C1 yes / C2 no (WSTEP) |
| Recommended first | **spike here** | migrate later if role-purity matters |

Recommendation: **spike Mode A on CA01** to prove the end-to-end round-trip with
the fewest moving parts, then evaluate Mode C for the "real" deployment if keeping
the CA role-pure is worth the delegation work.

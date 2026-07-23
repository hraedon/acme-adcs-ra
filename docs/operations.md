# Operations runbook — acme-adcs-ra

This runbook covers the operator-owned prerequisites the
[pre-pilot checklist](pre-pilot-checklist.md) names as blockers. It is the
single reference for EAB lifecycle, network allowlist / rate limiting,
scheduled maintenance, the admin token + reclaim runbook, monitoring/SLOs,
retention/archival, the revocation runbook, and backup/restore.

All identifiers here are placeholders (`WORK-DOMAIN.local`, `CA01`,
`CONTOSO-CA01-CA`, `ACME-ServerAuth`). Real values live in gitignored local
config / `samples/`.

## EAB lifecycle

External Account Binding (EAB) is the *who-is-allowed* gate (threat-model
§4.B). Each authorized ACME client gets a kid + MAC key + SAN scope. A stolen
EAB key allows rogue account creation within that kid's SAN scope until it is
rotated, so kids must be high-entropy and the MAC key must be treated like a
password.

### Minting a new EAB credential

Use `scripts/eab.py` to mint a high-entropy kid (UUID4, 32 hex chars, 128
bits) and MAC key (base64url of 32 random bytes, ≥256 bits). The helper prints
stdout-only env-var lines you paste into the locked-down `acme-ra.env`:

```bash
python scripts/eab.py
```

Output (example — the real kid/key are freshly generated each run):

```
# !!! TREAT LIKE A PASSWORD — never commit, never paste into chat/tickets. !!!
# !!! ACL the env file to the gMSA + Administrators only.                  !!!
ACME_RA_EAB_ALLOWLIST=[{"kid":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4","mac_key":"ZmFrZS1tYWMta2V5LTMyLWJ5dGVzLWxvbmctYW5kLXNlY3VyZQ"}]
ACME_RA_SAN_SCOPES__a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4__DNS_PATTERNS=["*.WORK-DOMAIN.local"]
```

After pasting:
1. Merge the `ACME_RA_EAB_ALLOWLIST` JSON array into the existing value in
   `acme-ra.env` (append the new object; do not overwrite other kids).
2. Replace the placeholder DNS patterns with the real SAN scope for this
   client (e.g. `["*.WORK-DOMAIN.local", "srv01.WORK-DOMAIN.local"]`).
3. ACL `acme-ra.env` to the gMSA + Administrators only (the installer lays
   it down locked; re-check after editing).
4. Restart the RA app pool so the new env vars take effect.
5. Configure the ACME client (Certify the Web) with the kid + MAC key.

The helper never logs secrets, never writes to disk, and never accepts a MAC
key as input — the MAC key is always freshly generated.

### Rotating an EAB credential

Rotation is a dual-credential cutover: the old kid stays valid until the
client is switched over, then it is removed.

```bash
python scripts/eab.py --rotate OLDKID1234567890abcdef1234567890ab
```

This mints a new credential and prints a rotation checklist. Follow it:

1. Merge the new entry into `ACME_RA_EAB_ALLOWLIST` in `acme-ra.env` as a
   JSON array (do not remove the old kid during the cutover — both must be
   valid).
2. Add `ACME_RA_SAN_SCOPES__<NEW_KID>__DNS_PATTERNS` for the new account.
3. Restart the RA app pool.
4. Re-issue the ACME client's EAB credential (kid + MAC key) and point the
   client at the new kid.
5. Confirm the new account can create an account + issue a test cert.
6. Once the old account is no longer used, remove the old kid's
   `ACME_RA_EAB_ALLOWLIST__<i>__*` entries and its SAN scope, restart the RA,
   and confirm the old account can no longer create new orders (existing
   orders/certs remain valid).
7. Keep the old kid's audit trail for the standard audit retention period.

### When to rotate

- **Suspected or confirmed compromise** of the MAC key or the client that
  holds it (the primary driver — rotate immediately and audit `account-created`
  events for the affected kid).
- **Client decommissioning** (rotate to retire the kid cleanly).
- **Routine rotation** per your org's secrets policy (e.g. annually).

### Auditing EAB scopes

The challenge is intentionally a no-op (enterprise trust model), so the
kid→scope mapping *is* the entire authorization surface. Run the audit
subcommand periodically to confirm no scope has quietly widened and that
every configured kid is accounted for:

```bash
python scripts/eab.py audit --env acme-ra.env --db acme_ra.db
```

Output (example — placeholders only; the real kid prefix comes from
`acme-ra.env`):

```
EAB scope audit — kid → SAN scope → last-used (no MAC keys shown)

KID          SAN SCOPE PATTERNS                            LAST USED             FLAGS
-----------  --------------------------------------------  --------------------  --------
a1b2c3d4...  *.WORK-DOMAIN.local, srv01.WORK-DOMAIN.local  2026-01-03T00:00:00Z  WILDCARD
b2c3d4e5...  exact.WORK-DOMAIN.local                       2026-02-01T00:00:00Z
c3d4e5f6...  (no scope — fail-closed)                      never                 NO SCOPE

3 kid(s): 1 wildcard, 1 no-scope, 1 never-used.
```

- **KID** — first 8 chars + `...` (the full kid is never printed; cross-reference
  with `acme-ra.env` to identify the account).
- **SAN SCOPE PATTERNS** — the DNS patterns this kid may request. A kid with no
  scope configured shows `(no scope — fail-closed)` and the `NO SCOPE` flag
  (no SANs are allowed for it).
- **LAST USED** — the most recent `account-created` or `order-created`
  timestamp for this kid in the RA store. `never` means no account has ever
  been created with this kid (it may be a freshly minted, not-yet-deployed
  credential, or a stale entry that should be cleaned up).
- **FLAGS** — `WILDCARD` if any pattern is a leftmost-label wildcard
  (`*.example.com`), the widest blast radius. `NO SCOPE` if the kid has no
  SAN scope configured.

The audit **never prints MAC key material** and is strictly read-only — it
does not write to the store. `--env` and `--db` are optional; if omitted the
config is read from `ACME_RA_*` environment variables and the store from
`ACME_RA_DB_PATH` (or the default `acme_ra.db`).

**What to look for:**

- A `WILDCARD` scope you did not expect (e.g. `*.corp.local`) — the widest
  blast radius; confirm it is intended.
- A `NO SCOPE` kid — this kid can authenticate but issue nothing; either add a
  scope or remove it from the allowlist.
- A `never`-used kid that has been configured for a long time — may indicate
  a stale entry or a client that was never switched over after rotation.

## Network allowlist and in-app rate limiting

The RA has an **in-app per-account rate limit** (WI-016) that bounds order
creation per EAB kid per rolling window, plus an optional global backstop.
This is defense-in-depth that does not depend on the operator's reverse-proxy
config being present or correct: even a directly-fronted RA, or one whose
proxy rule was fat-fingered, is protected so a leaked EAB credential cannot
mint an unbounded cert flood before the network layer notices.

The installer deliberately does not restrict the endpoint itself
(threat-model §4.G). Three operator controls bound this: the in-app rate
limit (how many orders per kid), a network allowlist (who may reach the RA
at all), and reverse-proxy rate limiting (how fast they may go).

### In-app rate limit (WI-016)

The in-app rate limit is configured via environment variables in
`acme-ra.env`:

| Env var | Default | Description |
|---|---|---|
| `ACME_RA_RATE_LIMIT_ORDERS_PER_WINDOW` | `50` | Max new orders per EAB kid per window. `0` = disabled. |
| `ACME_RA_RATE_LIMIT_WINDOW_SECONDS` | `3600` | Rolling window duration in seconds. |
| `ACME_RA_RATE_LIMIT_GLOBAL_PER_WINDOW` | `0` | Global backstop across all accounts. `0` = disabled. |
| `ACME_RA_RATE_LIMIT_OVERRIDES__<KID>` | (default) | Per-kid override: `ACME_RA_RATE_LIMIT_OVERRIDES__a1b2c3d4=10` sets kid `a1b2c3d4`'s limit to 10. |

On breach, the RA returns RFC 8555 `rateLimited` (HTTP 429) with a
`Retry-After` header and emits a SIEM audit event (`order-rate-limited`)
with the account, window, count, and scope (`per-account` or `global`).

**This is in addition to, not instead of, the reverse-proxy guidance below.**
The in-app limit bounds order creation (the expensive path that reaches
ADCS); the proxy limit bounds raw request rate (including polls and
challenge POSTs). Both should be configured.

### Network allowlist (`<ipSecurity>`)

Add to `deploy/iis/web.config` under `<system.webServer><security>` (requires
the "IP and Domain Restrictions" role service, installed by
`install-windows.ps1 -InstallPrereqs`). Set `allowUnlisted="false"` and add
the authorized client IP(s):

```xml
<security>
  <requestFiltering removeServerHeader="true" />
  <ipSecurity allowUnlisted="false">
    <!-- Authorized ACME client(s) only. -->
    <add ipAddress="10.0.0.50" allowed="true" />
    <!-- Add more client IPs as needed. -->
  </ipSecurity>
</security>
```

> **SNI-shared-443 caveat.** If the RA shares port 443 by SNI with
> cert-watch / gpo-lens on the same IIS site (the `-SharePort443 -HostName`
> install mode), do **not** blanket-block 443 at the firewall or site level
> — that would also block the sibling tools. Apply `<ipSecurity>` at the
> application/site level scoped to the RA's SNI hostname, or use a
> per-hostname firewall rule. The default unrestricted behavior is kept so a
> misconfigured allowlist cannot lock the sibling tools out by accident.

### Reverse-proxy rate limiting

Apply per-account and per-IP rate limits at the reverse proxy / load balancer
in front of the RA. The in-app per-account rate limit above bounds **order
creation**; the proxy limit additionally bounds **raw request rate** (polls,
challenge POSTs, finalize retries), which the in-app limit does not cover.
Without a proxy limit, a flood of in-window non-order requests still reaches
the ADCS CA, so both should be configured.

- **nginx:** `limit_req_zone` keyed on the ACME account URL (from the JWS
  `kid`) for per-account, and on `$remote_addr` for per-IP. Example:

  ```nginx
  # Per-IP: 10 req/s burst 20.
  limit_req_zone $binary_remote_addr zone=acme_ip:10m rate=10r/s;
  # Per-account: 2 req/s burst 5 (tune to your client's renewal cadence).
  limit_req_zone $http_authorization zone=acme_acct:10m rate=2r/s;

  location / {
    limit_req zone=acme_ip burst=20 nodelay;
    limit_req zone=acme_acct burst=5 nodelay;
    proxy_pass http://127.0.0.1:<HTTP_PLATFORM_PORT>;
  }
  ```

- **IIS Dynamic IP Restrictions:** enable dynamic mode, restrict by IP and by
  request path, with a per-IP concurrent-connection cap. This is the
  per-IP control when IIS is the only proxy.
- **Azure Application Gateway / other LB:** configure per-backend-pool
  rate-limit rules keyed on the client IP and the `Authorization` /
  `content-type: application/jose+json` signature.

Tune the limits to your client's real renewal cadence (Certify the Web
renews on a schedule, so the steady-state rate is very low). Alert on
`limit_req` rejections — a spike there is a probe or a runaway client.

## Scheduled maintenance tasks

Two admin endpoints must be driven by an external cron (threat-model §4.G):
nonce GC and expired-order sweep (RFC 8555 §7.1.6). The probabilistic 1%
nonce cleanup on `create_nonce` is a safety net only — wire the cron.

`scripts/Register-MaintenanceTasks.ps1` registers two Windows Scheduled Tasks
that call these endpoints on a cadence (default 15 minutes):

```powershell
# Register both tasks (run as the gMSA so the task can read acme-ra.env if
# needed; the admin token is passed as a parameter — do NOT commit it):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
    -IntervalMinutes 15 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$"

# Dry run (does not register anything):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
    -WhatIf
```

**Task-user choice.** Run the tasks as the gMSA (the same identity the RA app
pool uses) so the task can read the env file if the token is sourced there,
and so the task has no more privilege than the RA itself. Alternatively, run
as `NT AUTHORITY\SYSTEM` if the gMSA is not desired for scheduled tasks;
either way the admin token is passed in the task action's headers, not stored
in a file the task reads.

After registering, verify:

```powershell
Get-ScheduledTask -TaskName "acme-adcs-ra-nonce-cleanup" | Select-Object TaskName, State
Get-ScheduledTask -TaskName "acme-adcs-ra-expired-order-sweep" | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName "acme-adcs-ra-nonce-cleanup" | Select-Object NextRunTime
```

Each task invokes `Invoke-RestMethod` with `Authorization: Bearer <token>`.
The admin token is a high-value secret — see the admin-token runbook below
for rotation/ACL rules. The task action does not log the token.

## Admin token and reclaim runbook

`ACME_RA_ADMIN_TOKEN` gates the `/acme/admin/*` endpoints (nonce cleanup,
expired-order sweep, stuck-`processing` reclaim, order listing). A holder can
reconcile a stuck order to `ready`, the one action that can enable a
re-enroll — so the token is a high-value secret, treated like an EAB MAC key.

### Setting and ACL-ing the token

1. Generate a high-entropy token (≥256 bits). `python -c "import secrets;
   print(secrets.token_urlsafe(32))"` is sufficient.
2. Set `ACME_RA_ADMIN_TOKEN=<token>` in `acme-ra.env` (the locked-down env
   file, readable by the gMSA + Administrators only).
3. Do NOT put the token in `deploy/iis/web.config` (that file is
   checked-in-adjacent and carries only non-secret operator settings).
4. Restart the RA app pool so the token takes effect.
5. Distribute the token only to the operators who need to run
   `Register-MaintenanceTasks.ps1` or drive the admin endpoints — and no
   further.

### Rotating the admin token

1. Generate a new high-entropy token.
2. Update `ACME_RA_ADMIN_TOKEN` in `acme-ra.env`.
3. Restart the RA app pool.
4. Re-register the scheduled tasks with the new token
   (`Register-MaintenanceTasks.ps1 -AdminToken <new>`).
5. Confirm the old token is rejected (`GET /acme/admin/orders` with the old
   token → 401).

### The reclaim endpoint (double-issuance gate)

`POST /acme/admin/orders/{id}/reclaim-processing` (admin-token-gated)
reconciles an order wedged in `processing` after a crash mid-enrollment. It
has two branches:

- **Cert recorded, status flip missed** (crash window between
  `create_certificate` and the status flip): the endpoint CAS-closes the
  loop to `valid` (`admin-order-reclaimed`, `had_certificate=true`). No
  re-enrollment, no operator judgment needed.
- **No cert recorded** (enrollment did not visibly complete): the endpoint
  CAS-reverts the order to `ready` (`admin-order-reclaimed`,
  `had_certificate=false`). **Before this `ready` branch the operator MUST
  confirm from the ADCS CA database that no cert was issued for the order's
  ReqID** — this is the one operator action that can enable a re-enroll, and
  it is the operator's double-issuance gate, not the server's. Re-finalizing
  would otherwise double-issue if the CA accepted the first request and the
  RA crashed before recording the cert.

No-op, lost-race, and not-found reclaim attempts are audited
(`admin-order-reclaim-noop` / `-denied`) so a stolen admin token probing
order IDs is visible to SIEM.

## Monitoring and SLOs

### Stuck-processing orders (pilot condition)

Monitor time-in-`processing` p99 and alert when it exceeds a threshold (e.g.
5 minutes). The `processing` state is the crash window; a stuck order there
means a potential double-issuance risk if an operator reclaims without
checking the CA DB.

- `GET /acme/admin/orders?status=processing` (admin-token-gated) returns the
  minimal admin view (no SANs/cert URLs): id, account_id, status,
  processing_started_at, created_at, expires.
- Alert on `processing_started_at` age: any order in `processing` for more
  than N minutes should page the on-call (the operator decides N based on
  the enrollment leg's expected latency — typically a few minutes).

### Nonce-table growth

The probabilistic 1% cleanup on `create_nonce` is a safety net. The primary
control is the `DELETE /acme/admin/nonces` cron (see Scheduled maintenance
tasks above). Monitor:
- The `admin-nonce-cleanup` audit event's `details.deleted` count (a sudden
  drop to 0 while traffic is steady may indicate the cron stopped firing).
- Direct count: `SELECT COUNT(*) FROM nonces` (the table is indexed on
  `created_at`; a steady-state count above ~10k suggests the cron is
  misfiring or traffic spiked).

### SIEM delivery

- The SIEM startup probe logs **ERROR** on init if the JSONL sink is
  unwritable or the HEC/syslog config is invalid; the sink is set to
  `enabled=False` and issuance continues (fail-open applies to *emission*,
  not to the local audit record).
- **Runtime SIEM failures log at WARNING, not ERROR.** Therefore: the
  production monitoring stack MUST alert on the RA logger at WARNING+ (not
  ERROR-only) — this is a pilot condition, not a runbook footnote.
- Alert on any `certificate-issued` event with `outcome != success` (there
  is no such event today — a failure surfaces as `finalize-enrollment-denied`
  or `finalize-enrollment-race`; alert on those categories at ERROR+).

### Request / error rate SLOs

- Monitor the ACME endpoint request rate and error rate (4xx/5xx) at the
  reverse proxy. A spike in 4xx (especially `badNonce`, `malformed`) may
  indicate a misbehaving client or a probe; a spike in 5xx indicates an RA
  or CA problem.
- Alert on any 5xx from the ACME surface (the RA should never 500 in normal
  operation — `server_internal` is a bug or a CA-side failure).

## Retention and archival

### audit_log table

The `audit_log` table is the authoritative local audit (the SIEM JSONL is a
secondary emission). It grows unbounded by default. Retention guidance:

- **Keep hot** for the incident-review window (e.g. 90 days) for fast query.
- **Archive cold** after the hot window: export rows older than N days to a
  write-once / append-only sink (e.g. a compressed JSONL in cold storage)
  and delete them from the live SQLite. Keep the archived sink on
  tamper-evident storage.
- **Never delete** `certificate-issued` / `certificate-revoked` events until
  the corresponding certificates have expired AND been removed from the CRL
  (the audit is the matching half of the revocation trail; see the
  revocation runbook below).

A retention script is operator-owned (not shipped) — the schema is stable
(`SELECT * FROM audit_log WHERE timestamp < ?`), so a simple cron/export
suffices.

### certificates table

The `certificates` table holds every issued cert PEM + metadata. It is
needed for revocation lookups (serial → cert) and audit. Retention guidance:

- **Keep** all rows for at least the certificate validity period + the CRL
  overlap (so revoked certs remain queryable until they fall off the CRL).
- **Archive** expired-and-not-revoked cert rows to cold storage after the
  validity period + overlap, then delete from the live SQLite. Keep
  revoked cert rows until the revocation is no longer on the CRL.
- The `serial_number` index supports fast revocation lookup; the table is
  not on the hot path (only `revoke_cert` and `GET /acme/cert/{id}` read it).

### SIEM JSONL sink

- The JSONL sink (`<db>.siem.jsonl`, next to the DB) is the secondary
  emission. Back it up with the DB (see Backup and restore below).
- Rotate / compress old JSONL on a schedule (operator-owned) so it does not
  grow unbounded. The SIEM ingest should be the authoritative copy; the
  local JSONL is the fail-open buffer.

## Revocation runbook

CA-side revocation is **out-of-band, operator-run** (WI-010, threat-model
§4.E). The RA's `revokeCert` endpoint records the revocation in the RA store
only — it does **not** write the CA CRL. The operator closes the loop by
running `scripts/Revoke-Cert.ps1`.

### The two halves of the revocation trail

1. **RA audit event** (`certificate-revoked`, `outcome=success`): recorded by
   the RA's `revokeCert` endpoint. The `details` dict honestly records:
   - `revocation_scope`: `"ra-store-only"` (the RA store was flipped; the CA
     CRL was NOT written).
   - `ca_crl_updated`: `"false"` (the audit log never implies the CA CRL was
     written when it was not).
   - `serial`: the cert's hex serial (what `Revoke-Cert.ps1` consumes).
   - `req_id`: the ADCS ReqID if the enrollment leg recorded it (the
     preferred identifier for `Revoke-Cert.ps1`).
   - `reason`: the RFC 8555 reason code (0-6, 8-10; reason 7 is rejected —
     see below).
2. **CA-DB operator record**: `scripts/Revoke-Cert.ps1` (run by a CA
   officer, NOT the gMSA) performs `certutil -revoke` against the CA and
   republishes the CRL. The CA database records the operator identity. This
   is the matching out-of-band half.

Keep both records together in incident review.

### Reason 7 is rejected

RFC 5280 reason 7 ("unused") is rejected by the RA's `revokeCert` route AND
by `scripts/Revoke-Cert.ps1` (because `certutil` rejects it). The valid set
is `{0,1,2,3,4,5,6,8,9,10}`. This prevents a silent break in the
out-of-band revocation loop: an accepted reason 7 would cause
`Revoke-Cert.ps1` to fail on the recorded reason.

### Steps to revoke a cert

1. The ACME client (or an operator driving `revokeCert`) revokes the cert
   via the RA. The RA records `revocation_scope=ra-store-only`,
   `ca_crl_updated=false`, and the response carries an
   `out_of_band_revocation` hint naming the runbook and the serial/ReqID.
2. A CA officer runs `scripts/Revoke-Cert.ps1` with the serial or ReqID:

   ```powershell
   powershell -File .\scripts\Revoke-Cert.ps1 `
       -CaConfig 'CA01\WORK-DOMAIN-CA' -Serial '1A2B3C' -Reason 1
   ```

   (Run as a CA officer, NOT the gMSA — the gMSA holds no CA-officer
   rights, by design.)
3. **Verify the CRL republished.** `Revoke-Cert.ps1` runs
   `certutil -CRL republish` and prints the outcome. Confirm the CRL
   publication succeeded before considering the revocation complete — the RA
   audit cannot see the CA side.
4. Update the incident record to note the out-of-band step is done and the
   CRL is published.

### What the RA cannot see

The RA's audit log records `ca_crl_updated=false` until the operator runs
`Revoke-Cert.ps1`. The RA has no way to know whether the CRL was actually
republished — the operator must verify this on the CA side. The RA's
`GET /acme/cert/{id}` returns 410 Gone for revoked certs (RA-store level);
clients that check the CA's CRL will see the revocation only after
`Revoke-Cert.ps1` runs.

### Revocation reconciliation (WI-017)

Because revocation is out-of-band, the RA store and the CA database can
silently diverge: an operator may call `revokeCert` (RA store flipped) but
forget the out-of-band `Revoke-Cert.ps1` step (CA CRL not written), or the
CA may be revoked directly without the RA knowing. Run the reconciliation
tool periodically (e.g. daily, or after each revocation) to catch drift:

```powershell
powershell -File .\scripts\Reconcile-Revocation.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -DbPath 'C:\acme-adcs-ra\acme_ra.db'
```

Or run the Python reconciler directly against a pre-exported CA-DB dump:

```bash
python scripts/reconcile_revocation.py --db acme_ra.db --ca-export ca_dump.txt
```

The tool classifies each certificate into three buckets:

- **in-sync** — both RA and CA agree (both revoked or both active).
- **revoked-in-RA-but-active-at-CA** — the dangerous one: the operator
  called `revokeCert` but the out-of-band CA step was never done. The cert
  is revoked in the RA (GET → 410) but still valid on the CA's CRL. Run
  `Revoke-Cert.ps1` immediately.
- **revoked-at-CA-but-valid-in-RA** — the CA revoked a cert the RA still
  shows valid. Investigate whether the cert was revoked directly at the CA
  without going through the RA.

The tool is **read-only**: it never revokes, reactivates, or writes to
either store. Exit code: `0` = all in-sync, `1` = drift found, `2` = error.
Use `--json` for machine-readable output (e.g. for SIEM ingestion).

### Automated revocation (WI-022/023/024/025)

The out-of-band revocation loop (above) is **automated** in v1.5, closing the
functional gap without granting the enrollment gMSA any CA-officer rights.
The loop:

1. **RA `revokeCert`** records the revocation in the RA store
   (`revocation_scope=ra-store-only`, `ca_crl_updated=false`) — unchanged.
2. **Pull agent** (`scripts/Sync-Revocations.ps1`, WI-024) runs as a
   scheduled task on a **utility host** (not the CA) under a dedicated
   `gMSA-acme-revoker$`. Each cycle it `GET`s the RA's pending set
   (`GET /acme/admin/revocations/pending`, WI-023 — admin-token-gated),
   then for each serial calls `Revoke-Cert.ps1` (which self-checks the
   requester, WI-022) against the CA via remote-capable
   `certutil -revoke -config` (no Kerberos double-hop).
3. **Confirm callback**: on success the agent `POST`s to
   `/acme/admin/revocations/<serial>/confirm` so the RA audit flips
   `ca_crl_updated=true` and the serial drops out of the pending set
   (idempotent — the agent is safe to run repeatedly).

The authority to revoke lives **on the CA side**, under a separate
template-bounded principal (`gMSA-acme-revoker$`), never on the RA host.
The enrollment gMSA holds no CA-officer rights — the cardinal invariant
holds (threat-model §E).

#### Two hard provisioning constraints for `gMSA-acme-revoker$`

Both were proven load-bearing in the Plan-004 live spike; skipping either
silently defeats or breaks the restriction:

1. **NOT a member of any broader certificate-manager group.** Officer
   rights are evaluated across the caller's *entire* token (union
   semantics). A restricted officer that is *also* a member of an
   unrestricted certificate-manager group can revoke anything — the
   restriction is silently defeated. Provision the revoker as a plain
   domain principal with *only* its `ManageCertificates` grant and the
   `OfficerRights` restriction; do not nest it in any broader role group.
2. **Member of `Certificate Service DCOM Access`.** Without it the
   revoke fails `0x8007000d ERROR_INVALID_DATA` — a visible failure, not
   a silent bypass, but the loop will not complete. Add the gMSA to the
   `Certificate Service DCOM Access` built-in group on the CA.

#### Provisioning the officer restriction

`scripts/Set-OfficerRights.ps1` (WI-025) productionizes the Plan-004
builder — it writes the CA's `OfficerRights` registry value (a
self-relative security descriptor with one callback ACE per officer) that
scopes the revoker to `ACME-ServerAuth` only. Run **on the CA host**:

```powershell
# 1. Grant the revoker ManageCertificates on the CA Security descriptor
#    (use certsrv.msc or PSPKI; this is the coarse role grant, distinct
#    from the template-scoped OfficerRights below):
Add-CAAccessControlEntry -User "WORK-DOMAIN\gMSA-acme-revoker$" `
    -AccessType Allow -AccessMask ManageCertificates

# 2. Add the revoker to Certificate Service DCOM Access (constraint 2):
net localgroup "Certificate Service DCOM Access" "WORK-DOMAIN\gMSA-acme-revoker$" /add

# 3. Scope the revoker to the ACME-ServerAuth template only (constraint 1
#    is enforced by this restriction; confirm the gMSA is in no broader
#    cert-manager group before proceeding):
powershell -ExecutionPolicy Bypass -File .\scripts\Set-OfficerRights.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -OfficerSid 'S-1-5-21-<revoker-gMSA-sid>' `
    -TemplateOid '<ACME-ServerAuth-template-OID>'

# 4. Verify by readback:
powershell -File .\scripts\Get-OfficerRights.ps1 -CaConfig 'CA01\WORK-DOMAIN-CA'
```

`Set-OfficerRights.ps1` restarts `certsvc` (required for the change to
take effect) and verifies the value by readback. To remove the restriction
later: re-run with `-Remove` (if it was the last ACE, the `OfficerRights`
value is deleted and the CA reverts to unrestricted — logged visibly).

The GUI alternative (`certsrv.msc` → Certificate Managers tab) is correct
by construction and is the reference path; the script reproduces the same
byte-level ACE the GUI produces (proven in Plan 004).

#### Scheduling the agent

Register `Sync-Revocations.ps1` as a Windows Scheduled Task on the utility
host, running as `gMSA-acme-revoker$`:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\acme-adcs-ra\scripts\Sync-Revocations.ps1 -RaBaseUrl 'https://ra.WORK-DOMAIN.local' -AdminToken '<admin-token>' -CaConfig 'CA01\WORK-DOMAIN-CA' -Execute"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName "acme-adcs-ra-sync-revocations" `
    -Action $action -Trigger $trigger -Settings $settings `
    -User "WORK-DOMAIN\gMSA-acme-revoker$" -Force
```

The admin token is embedded in the task action's arguments (not written to
a file the task reads); rotate it by re-registering (see the admin-token
runbook). Tune the interval to your latency requirement (default 5 minutes
shown; the RA audit records `ca_crl_updated` lag so you can measure the
actual cadence).

#### Dry-run → execute promotion

`Sync-Revocations.ps1` is **dry-run by default** (fail-visible). Without
`-Execute` it fetches the pending set and prints what it would do, making
no change. Promotion path:

1. Deploy the script and the scheduled task **without** `-Execute`
   (report-only). Confirm the dry-run output shows the expected pending
   serials and the correct `Revoke-Cert.ps1` invocation.
2. Review the first few cycles' dry-run logs against
   `Reconcile-Revocation.ps1` (the `revoked_in_ra_active_at_ca` bucket
   should match the dry-run pending set).
3. Arm the task by re-registering with `-Execute`. The first cycle after
   arming should revoke the pending serials and confirm them back to the RA
   (`ca_crl_updated=true` in the audit).

#### Monitoring

Alert on:

- **Agent exit codes** (the scheduled task's last result):
  - `0` = success (all pending revoked, or dry-run completed, or nothing
    pending).
  - `1` = RA unreachable — the agent could not fetch the pending set.
    Investigate network / RA health.
  - `2` = partial failure — one or more serials failed to revoke. The
    per-serial log lines name the failing serial and the `Revoke-Cert.ps1`
    exit code; investigate (common causes: requester mismatch = exit 5 =
    the serial was not issued by the RA's gMSA; certutil error = CA-side
    issue).
- **RA audit events**: `certificate-revoked` with
  `ca_crl_updated=false` lingering longer than the agent interval × 2
  means the loop is stuck (the agent is not closing the confirm callback).
- **The `revoked_in_ra_active_at_ca` reconciliation bucket** (run
  `Reconcile-Revocation.ps1` periodically) — if it grows, the agent is
  not keeping up or is failing silently. This is the independent
  cross-check (it reads the CA DB directly, not the agent's self-report).

#### Deployment variant: single-identity (enrollment gMSA as its own revoker)

**WI-033 / WI-034.** An opt-in variant in which the **same** gMSA used for
enrollment is also granted the template-scoped OfficerRights and runs the
revocation pull agent on the RA host in `-LocalMode`. Choose this only when
the RA runs on a single host, the operator accepts the compromise-correlation
risk, and operational simplicity outweighs the independence guarantee. The
two-identity design (`gMSA-acme-revoker$` on a utility host) remains the
**recommended default**; see threat-model §E for the full trade-off analysis.

**The explicit trade-off.** One credential compromise grants both issue and
revoke capability, enabling a mint-and-swap attack that the two-identity
design prevents. The template boundary and requester boundary are preserved;
compromise independence is not. Full analysis: threat-model §E.

##### Provisioning the enrollment gMSA as its own revoker

Apply the same steps as for the dedicated revoker, but target
`WORK-DOMAIN\gMSA-acme-ra$` instead of `WORK-DOMAIN\gMSA-acme-revoker$`:

```powershell
# 1. Grant the enrollment gMSA ManageCertificates on the CA Security descriptor
#    (the coarse role grant; the template-scoped OfficerRights below is the
#    actual restriction):
Add-CAAccessControlEntry -User "WORK-DOMAIN\gMSA-acme-ra$" `
    -AccessType Allow -AccessMask ManageCertificates

# 2. Add the enrollment gMSA to Certificate Service DCOM Access (constraint 2):
net localgroup "Certificate Service DCOM Access" "WORK-DOMAIN\gMSA-acme-ra$" /add

# 3. Scope the enrollment gMSA to the ACME-ServerAuth template only
#    (constraint 1 is enforced by this restriction; confirm the gMSA is in no
#    broader cert-manager group before proceeding):
powershell -ExecutionPolicy Bypass -File .\scripts\Set-OfficerRights.ps1 `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -OfficerSid 'S-1-5-21-<enrollment-gMSA-sid>' `
    -TemplateOid '<ACME-ServerAuth-template-OID>'

# 4. Verify by readback:
powershell -File .\scripts\Get-OfficerRights.ps1 -CaConfig 'CA01\WORK-DOMAIN-CA'
```

**The two hard provisioning constraints still apply** (union semantics; DCOM
access) — same as the two-identity design; see `### Two hard provisioning
constraints for gMSA-acme-revoker$` above.

##### Scheduling the agent on the RA host

Use `Register-MaintenanceTasks.ps1` to register the revocation sync task
alongside the nonce-sweep and expired-order-sweep tasks. The task runs as the
enrollment gMSA on the RA host and passes `-LocalMode` to
`Sync-Revocations.ps1`. `-LocalMode` does **not** change how revocation
happens — `Sync-Revocations.ps1` invokes `Revoke-Cert.ps1` (and
`certutil -revoke -config <CaConfig>`) identically in both topologies; the CA
is always reached over RPC/DCOM per `-CaConfig`, whether the agent sits on a
utility host or on the RA host. The flag is a deployment-intent signal: it
records that the agent is running under the enrollment gMSA (which is also the
revoker) and adjusts the run banner accordingly. Register in dry-run mode
first (report-only), then re-register without `-DryRun` to arm it:

```powershell
# Step 1: register in dry-run mode (report-only — no revocations applied):
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken "<admin-token>" `
    -IntervalMinutes 5 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
    -RegisterRevocationSync `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -RequesterName "WORK-DOMAIN\gMSA-acme-ra$" `
    -LocalMode -DryRun

# Step 2: after dry-run review, re-register without -DryRun to arm the task:
powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
    -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
    -AdminToken "<admin-token>" `
    -IntervalMinutes 5 `
    -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
    -RegisterRevocationSync `
    -CaConfig 'CA01\WORK-DOMAIN-CA' `
    -RequesterName "WORK-DOMAIN\gMSA-acme-ra$" `
    -LocalMode
```

This registers the `acme-adcs-ra-sync-revocations` task. With `-DryRun` the
task action passes `-DryRun` to `Sync-Revocations.ps1` (report-only); without
it the task action passes `-Execute` (live). Rotate the admin token by
re-registering the tasks (see the admin-token runbook).

**`-RequesterName` is required in practice.** Replace `WORK-DOMAIN\...` with the
**real** `DOMAIN\account` under which the RA enrolls, exactly as it appears in
the CA database `Requester` column (e.g. `CONTOSO\gMSA-acme-ra$`). The WI-022
requester check in `Revoke-Cert.ps1` refuses to revoke any cert whose CA-DB
requester does not match this value; if you leave the committed placeholder,
**every** revoke is rejected with "Requester mismatch". `Register-MaintenanceTasks.ps1`
forwards `-RequesterName` into the scheduled-task action.

**gMSA task logon type.** The revocation-sync task runs as a gMSA, which is
never interactively logged on. `Register-MaintenanceTasks.ps1` registers it (and
the nonce/sweep tasks) with `LogonType=Password` so the host retrieves the
managed password — do not change the principal to Interactive or the task will
register but silently never run.

**CRL freshness (`-PublishCrl`, off by default).** By default the sync agent
revokes each cert at the CA but does **not** republish the CRL: the revocation
is recorded immediately in the CA database and becomes visible on the next
**scheduled** CRL publication. This is deliberate least-privilege — `certutil
-CRL republish` requires the **Manage-CA** role, which the template-scoped
officer identity does not (and should not) hold. Pass `-PublishCrl` to force an
immediate republish, but only if you have granted the identity CRL-publish
rights. In the **single-identity** topology that means the internet-facing
enrollment identity also holds Manage-CA (able to edit CA configuration,
including its own `OfficerRights`) — **strongly discouraged**; it collapses the
escalation bound. `-PublishCrl` is more defensible for the **dedicated
two-identity revoker**, where CRL freshness may be worth the narrower blast
radius of a revoke-only account holding Manage-CA. Choose it deliberately and
record the decision (see threat-model §E). Default (scheduled CRL) is the
recommended posture for both topologies.

##### Monitoring differences

- The CA-DB requester for **both issuance and revocation** is
  `gMSA-acme-ra$` — the reconciliation cross-check
  (`Reconcile-Revocation.ps1`) is the primary way to distinguish issuance from
  revocation in the CA DB, because the CA DB alone cannot tell them apart by
  identity.
- The `revoked_in_ra_active_at_ca` bucket still works as the independent
  cross-check (it reads the CA DB directly, not the agent's self-report).
- Agent exit codes are the same as the two-identity design (0/1/2/5).

##### Dry-run → execute promotion

`Register-MaintenanceTasks.ps1` supports `-DryRun` for the revocation-sync
task: in that mode the task action passes `-DryRun` (not `-Execute`) to
`Sync-Revocations.ps1`, so it fetches the pending set and prints what it would
do without making any change.

1. Register the task with `-DryRun` (see the scheduling example above).
2. Review the dry-run output and `Reconcile-Revocation.ps1` (the pending set
   should match the `revoked_in_ra_active_at_ca` bucket).
3. Re-register without `-DryRun` to arm the task. The first cycle after arming
   should revoke the pending serials and confirm them back to the RA
   (`ca_crl_updated=true` in the audit).

## Backup and restore

### What to back up

1. **SQLite DB** (`acme_ra.db`): the authoritative audit + every issued cert
   PEM + account JWKs + the EAB kid map + orders/authorizations. Back up
   with the DB cold (or use SQLite's online backup API / `.backup` command to
   avoid a torn copy).
2. **`.env` / `acme-ra.env`**: the EAB MAC keys, SIEM HEC token, admin
   token. This is the secrets-at-rest file — back it up encrypted, ACL'd to
   the backup operator + gMSA only.
3. **SIEM JSONL sink** (`<db>.siem.jsonl`): the secondary emission log.
   Back it up alongside the DB (or rely on the SIEM ingest as the
   authoritative copy, keeping the local JSONL as the fail-open buffer).

### Backup procedure

1. Snapshot the SQLite DB (e.g. `sqlite3 acme_ra.db ".backup acme_ra.db.bak"`
   or a file-system snapshot). The DB is in WAL mode; a raw file copy while
   the RA is running may be torn — use the `.backup` command or stop the RA.
2. Copy `acme-ra.env` to the encrypted backup (it is already ACL'd; ensure
   the backup target is too).
3. Copy the SIEM JSONL sink (or confirm the SIEM has ingested up to the
   current tail).
4. Store all three on tamper-evident, backed-up storage (the audit is the
   authoritative record — treat it as such).

### Restore procedure

1. Stop the RA app pool.
2. Restore `acme_ra.db` from the backup to the DB path in `web.config`.
3. Restore `acme-ra.env` to the env-file path in `web.config`
   (`ACME_RA_DOTENV`); re-ACL it to the gMSA + Administrators only.
4. Restore the SIEM JSONL sink (or accept the SIEM as the authoritative
   copy and let the RA append new events).
5. Start the RA app pool.
6. **Validate the restore:**
   - `GET /directory` returns JSON (the RA is up).
   - `GET /acme/admin/orders?status=processing` (with the admin token)
     returns the expected shape (the DB is readable).
   - Spot-check a recent `certificate-issued` audit event via
     `store.list_audit_events` (or the SIEM) to confirm the audit trail is
     intact.
   - Confirm the EAB allowlist loaded (a `newAccount` with a known kid
     succeeds; an unknown kid fails with `badExternalAccountBinding`).
7. If the restore is from before a known incident, note the gap in the
   audit trail (the SIEM may have events the DB restore lacks — reconcile).

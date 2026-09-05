# Reproof handoff — 2026-09-05

This maintenance change builds on `325eeff` on `crl-watermark-and-sampler`.
Use the final committed candidate and record its hash in the validation log.
It is not a new release or a claim of live ADCS validation.

## Changes to verify

Issued-certificate SAN, EKU, and CA-capability checks now live in
`src/acme_adcs_ra/issued_certificate_validation.py`. Their logic and the
finalization call order are unchanged, including failure responses, audit,
quarantine, and queued revocation. No storage schema, policy, enrollment
scheduling, installer, dependency, or configuration-value changes were made.

The CRL sampler timing fix changes only its test clock. Operator documentation
now distinguishes tagged v1.12.0 from the unreleased watermark, records the
server's pruning refusal, and treats the disputed lab age ceiling as interim.

## Local evidence

The three extracted validator bodies were compared structurally with their
original implementations, excluding names and docstrings, and were identical.
Independent review found no change to validation order or quarantine handling.
The architecture checks continue to scan the new module.

- Python 3.12 full suite: **1,015 passed, 1 skipped**. The existing Starlette
  `httpx` deprecation warning remains.
- Pester 5.7.1 under Linux PowerShell: **482 passed, 4 skipped**.
- Repository-wide Ruff and strict mypy: passed (35 source files typed).
- `git diff --check`: passed. The local identifier gate had no configured
  denylist and skipped; no claim of an active identifier scan is made.

Hosted CI, native Windows PowerShell 5.1, and live ADCS checks were not run.
The full Python suite includes the wheel-build and architecture guard checks.

## Lab reproof

Run the full [live reproof procedure](live-reproof-runbook.md) on the exact
candidate, starting from a known configuration. In particular:

- Confirm the installed wheel contains the new module and the service starts
  under the enrollment identity. Complete normal issuance and certificate
  retrieval, including SAN, serverAuth-only EKU, and existing-chain checks.
- Complete the independent-client record in §A.2, including renewal and client
  revocation. Verify CA revocation and publication separately from the client's
  success response.
- Complete the existing quarantine, orphan recovery, and enrollment-lease
  checks in the full lab procedure. The extraction preserves their behavior;
  local tests do not replace the integration proof.
- Finish the previously owed monotonic-watermark proof. Record its first-use
  baseline, acceptance of current evidence, refusal of regression, and
  persistence across a service restart. This control predates this maintenance
  change but remains unreleased and not live-proven in the local record.
- Preserve sampler evidence across at least two publication cycles before
  settling the lab's CRL-age setting. No new age value is proposed here.
- Preserve post-run evidence before restore, remove throwaway credentials,
  and reconcile RA/CA state under the existing teardown procedure.

No remote host was contacted and no Vault credential was retrieved for this
maintenance change. Native Windows and live ADCS validation remain with the
operator.

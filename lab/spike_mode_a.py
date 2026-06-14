#!/usr/bin/env python3
"""acme-adcs-ra - Mode A enrollment spike (plan 001, WI-1).

The project's feasibility gate: prove that a process running as the gMSA can
submit a CSR to ``/certsrv/`` on the issuing CA over Negotiate/SSPI and get
back an ADCS-issued certificate on the existing chain, with requester =
``gMSA-acme-ra$`` in the CA database.

This is a LAB script.  Run it on the **domain-joined RA host, as the gMSA**
(``WORK-DOMAIN\\gMSA-acme-ra$``).  It is NOT part of the RA package (it lives
under ``lab/``, outside the no-signing-key guardrail's ``src/`` scan scope) and
it generates a throwaway client CSR + key purely to exercise the enrollment leg.

The ``certfnsh.asp`` payload is borrowed from magnuswatn/certsrv, the proven
reference implementation (see docs/architecture.md).

Configuration is via env vars so that NO real identifiers are committed:
  ACME_RA_SPIKE_HOST       CA host FQDN              (default ca01.work-domain.local)
  ACME_RA_SPIKE_TEMPLATE   certificate template name (default ACME-ServerAuth)
  ACME_RA_SPIKE_SAN        SAN / CN to request       (default spike.acme-ra.test)
  ACME_RA_SPIKE_CA_BUNDLE  PEM bundle to verify TLS  (default: OS trust store)
  ACME_RA_SPIKE_OUT        output directory          (default ./spike-out)

Troubleshooting:
  * 401 loop / auth fail      -> you are not running as the gMSA, or the host is
                                 not domain-joined / cannot reach a DC.
  * TLS error                 -> ADCS uses a private CA; set ACME_RA_SPIKE_CA_BUNDLE
                                 to the CA's cert chain.
  * "Certificate Pending"     -> the template still has CA-manager approval on;
                                 turn it off (the RA is the gate).
  * "denied" / disposition    -> gMSA lacks Enroll on the template, or the SAN
                                 falls outside template policy.
  * Kerberos fails, NTLM ok   -> in IIS Windows Auth set EPA to "Accept" (not
                                 "Required"); Windows SSPI usually handles EPA,
                                 but if Negotiate falls back to NTLM, drop NTLM.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("spike")

HOST = os.environ.get("ACME_RA_SPIKE_HOST", "ca01.work-domain.local")
TEMPLATE = os.environ.get("ACME_RA_SPIKE_TEMPLATE", "ACME-ServerAuth")
SAN = os.environ.get("ACME_RA_SPIKE_SAN", "spike.acme-ra.test")
CA_BUNDLE = os.environ.get("ACME_RA_SPIKE_CA_BUNDLE")
OUT = Path(os.environ.get("ACME_RA_SPIKE_OUT", "./spike-out"))
TIMEOUT = 30


def build_csr(san: str) -> tuple[str, bytes]:
    """Generate a throwaway RSA-2048 key + PKCS#10 CSR (CN=san, serverAuth SAN).

    This is CLIENT-side CSR generation (what every ACME client does). The RA
    itself never generates keys or CSRs.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return csr_pem, key_pem


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if sys.platform != "win32":
        log.error(
            "This spike uses requests-negotiate-sspi (Windows SSPI). "
            "Run it on the domain-joined RA host, as the gMSA."
        )
        return 2

    import requests
    from requests_negotiate_sspi import HttpNegotiateAuth

    OUT.mkdir(parents=True, exist_ok=True)
    log.info("target  : https://%s/certsrv/", HOST)
    log.info("template: %s", TEMPLATE)
    log.info("SAN/CN  : %s", SAN)
    log.info("auth    : ambient Windows identity (MUST be gMSA-acme-ra$)")

    session = requests.Session()
    session.auth = HttpNegotiateAuth()  # passwordless; uses the gMSA's ambient identity
    session.headers["User-agent"] = "acme-adcs-ra-spike/0.1 (Mode A)"
    session.verify = CA_BUNDLE if CA_BUNDLE else True

    csr_pem, key_pem = build_csr(SAN)
    (OUT / "spike.csr.pem").write_text(csr_pem)
    (OUT / "spike.key.pem").write_bytes(key_pem)
    log.info("generated CSR + key")

    try:
        # 1. Submit the CSR to certfnsh.asp (payload per magnuswatn/certsrv).
        data = {
            "Mode": "newreq",
            "CertRequest": csr_pem,
            "CertAttrib": f"CertificateTemplate:{TEMPLATE}\r\n",
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }
        resp = session.post(f"https://{HOST}/certsrv/certfnsh.asp", data=data, timeout=TIMEOUT)
        resp.raise_for_status()
        body = resp.text
        m = re.search(r"certnew\.cer\?ReqID=(\d+)&", body)
        if not m:
            if re.search(r"Certificate Pending", body, re.I):
                rid = re.search(r"Your Request Id is (\d+)", body)
                raise RuntimeError(
                    f"Request pending CA-manager approval (ReqID={rid.group(1) if rid else '?'}). "
                    "Turn off manager approval on the template - the RA is the gate."
                )
            msg = re.search(r'The disposition message is "([^"]+)', body)
            raise RuntimeError(f"CA denied the request: {msg.group(1) if msg else 'unknown'}")
        req_id = int(m.group(1))
        log.info("CA accepted the CSR - ReqID=%d", req_id)

        # 2. Fetch the issued certificate (PEM/base64).
        cert_r = session.get(
            f"https://{HOST}/certsrv/certnew.cer",
            params={"ReqID": req_id, "Enc": "b64"},
            timeout=TIMEOUT,
        )
        cert_r.raise_for_status()
        if cert_r.headers.get("Content-Type") != "application/pkix-cert":
            raise RuntimeError(
                f"Unexpected content-type fetching cert: {cert_r.headers.get('Content-Type')}"
            )
        cert_pem = cert_r.content
        (OUT / "spike.cert.pem").write_bytes(cert_pem)
        log.info("saved issued cert -> %s", OUT / "spike.cert.pem")

        # 3. Fetch the CA chain (PKCS#7) for chain verification.
        arc = session.get(f"https://{HOST}/certsrv/certcarc.asp", timeout=TIMEOUT)
        arc.raise_for_status()
        renewals = (re.search(r"var nRenewals=(\d+);", arc.text) or re.match("0", "0")).group(
            1
        ) if re.search(r"var nRenewals=(\d+);", arc.text) else "0"
        chain_r = session.get(
            f"https://{HOST}/certsrv/certnew.p7b",
            params={"ReqID": "CACert", "Renewal": renewals, "Enc": "b64"},
            timeout=TIMEOUT,
        )
        chain_r.raise_for_status()
        (OUT / "spike.chain.p7b").write_bytes(chain_r.content)
        log.info("saved CA chain (p7b) -> %s", OUT / "spike.chain.p7b")
    except Exception as exc:  # noqa: BLE001 - lab script, surface any failure
        log.error("enrollment failed: %s", exc)
        return 1

    # 4. Inspect the issued cert so we can eyeball EKU/SAN/issuer.
    cert = x509.load_pem_x509_certificate(cert_pem)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        eku_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtendedKeyUsageOID.EXTENDED_KEY_USAGE
        )
        ekus = [e.dotted_string for e in eku_ext.value]
    except x509.ExtensionNotFound:
        ekus = []
    not_after = cert.not_valid_after_utc
    log.info("issued cert parsed:")
    log.info("  CN     = %s", cn)
    log.info("  SANs   = %s", sans)
    log.info("  EKU    = %s (1.3.6.1.5.5.7.3.1 = serverAuth)", ekus)
    log.info("  issuer = %s", cert.issuer.rfc4514_string())
    log.info("  valid  -> %s", not_after.isoformat())

    now = datetime.now(timezone.utc)
    if not_after < now:
        log.warning("issued cert is ALREADY EXPIRED (clock/template issue)")
    if sans != [SAN]:
        log.warning("issued SANs != requested (%r) - template may be overriding", SAN)

    print("\nSUCCESS - enrollment round-trip complete.")
    print(f"Artifacts in: {OUT.resolve()}")
    print("\nNow CONFIRM the requester in the CA database (the audit hook):")
    print(
        f'  certutil -view -restrict "RequestID={req_id}" '
        "-out RequestID Requester CommonName CertificateTemplate RequestDisposition"
    )
    print("  Expected: Requester = WORK-DOMAIN\\gMSA-acme-ra$")
    print(
        "\nIf Requester is anything else, Mode A is NOT behaving as local-enrollment"
        " - stop and investigate before building the ACME server on this assumption."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

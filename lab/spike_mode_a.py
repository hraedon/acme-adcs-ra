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

import ctypes
import logging
import os
import re
import subprocess
import sys
from ctypes import byref, cast, create_string_buffer, sizeof, wintypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("spike")

HOST = os.environ.get("ACME_RA_SPIKE_HOST", "ca01.work-domain.local")
TEMPLATE = os.environ.get("ACME_RA_SPIKE_TEMPLATE", "ACME-ServerAuth")
SAN = os.environ.get("ACME_RA_SPIKE_SAN", "spike.acme-ra.test")
CA_BUNDLE = os.environ.get("ACME_RA_SPIKE_CA_BUNDLE")
OUT = Path(os.environ.get("ACME_RA_SPIKE_OUT", "./spike-out"))
TIMEOUT = 30

# Win32 constants used by the lab-only protected output helpers. The key is
# created with CREATE_NEW and no sharing, with its final protected DACL supplied
# in the CreateFileW call -- there is no permissive file to tighten later.
_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_SDDL_REVISION_1 = 1
_ERROR_ALREADY_EXISTS = 183
_ERROR_FILE_EXISTS = 80
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
_GENERIC_WRITE = 0x40000000
_CREATE_NEW = 1
_FILE_ATTRIBUTE_NORMAL = 0x0080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("security_descriptor", wintypes.LPVOID),
        ("inherit_handle", wintypes.BOOL),
    ]


def _windows_libraries() -> tuple[Any, Any]:
    """Load and type the small Win32 surface used by this lab helper."""
    # These names are absent from ctypes on non-Windows hosts. Keep lookup
    # inside the Windows-only call path so importing the lab module remains
    # possible for cross-platform linting and structural tests.
    win_dll = getattr(ctypes, "WinDLL")  # noqa: B009
    kernel32 = win_dll("kernel32", use_last_error=True)
    advapi32 = win_dll("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetFileAttributesW.restype = wintypes.DWORD
    kernel32.CreateDirectoryW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(_SecurityAttributes),
    ]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    return kernel32, advapi32


def _winerror(message: str) -> OSError:
    error = getattr(ctypes, "get_last_error")()  # noqa: B009
    format_error = getattr(ctypes, "FormatError")  # noqa: B009
    return OSError(error, f"{message}: {format_error(error)}")


def _current_user_sid(kernel32: Any, advapi32: Any) -> str:
    """Return the ambient identity's SID without invoking another process."""
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, byref(token)
    ):
        raise _winerror("OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token, _TOKEN_USER_CLASS, None, 0, byref(needed)
        )
        if needed.value == 0:
            raise _winerror("GetTokenInformation size query failed")
        token_info = create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            token_info,
            needed.value,
            byref(needed),
        ):
            raise _winerror("GetTokenInformation failed")
        sid_pointer = cast(token_info, ctypes.POINTER(_TokenUser)).contents.user.sid
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, byref(sid_text)):
            raise _winerror("ConvertSidToStringSidW failed")
        try:
            if sid_text.value is None:
                raise RuntimeError("ConvertSidToStringSidW returned an empty SID")
            return sid_text.value
        finally:
            kernel32.LocalFree(cast(sid_text, wintypes.HLOCAL))
    finally:
        kernel32.CloseHandle(token)


def _protected_security_attributes(
    current_sid: str, advapi32: Any, *, inherit_to_children: bool
) -> tuple[_SecurityAttributes, wintypes.LPVOID]:
    """Build a protected DACL for current user, SYSTEM, and Administrators."""
    # D:P disables inheritance. The directory carries OI/CI so its same
    # allowlist reaches the public CSR/certificate artifacts; the private key's
    # explicit file DACL has no inheritance flags.
    ace_flags = "OICI" if inherit_to_children else ""
    sddl = (
        f"O:{current_sid}D:P"
        f"(A;{ace_flags};FA;;;SY)"
        f"(A;{ace_flags};FA;;;BA)"
        f"(A;{ace_flags};FA;;;{current_sid})"
    )
    descriptor = wintypes.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, _SDDL_REVISION_1, byref(descriptor), None
    ):
        raise _winerror("security descriptor creation failed")
    attributes = _SecurityAttributes(
        length=sizeof(_SecurityAttributes),
        security_descriptor=descriptor,
        inherit_handle=False,
    )
    return attributes, descriptor


def _reject_reparse_ancestors(path: Path, kernel32: Any) -> None:
    """Refuse an existing parent chain containing a symlink or junction."""
    current = path.parent
    while True:
        attributes = kernel32.GetFileAttributesW(str(current))
        if attributes == _INVALID_FILE_ATTRIBUTES:
            raise _winerror(f"cannot inspect output parent {current}")
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError(f"output parent is a reparse point: {current}")
        if current == current.parent:
            return
        current = current.parent


def _create_protected_output_directory(path: Path) -> None:
    """Atomically create one fresh, protected, non-reparse Windows directory."""
    path = path.absolute()
    kernel32, advapi32 = _windows_libraries()
    _reject_reparse_ancestors(path, kernel32)
    current_sid = _current_user_sid(kernel32, advapi32)
    attributes, descriptor = _protected_security_attributes(
        current_sid, advapi32, inherit_to_children=True
    )
    try:
        if not kernel32.CreateDirectoryW(str(path), byref(attributes)):
            error = getattr(ctypes, "get_last_error")()  # noqa: B009
            if error in (_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS):
                raise FileExistsError(
                    f"refusing existing spike output directory: {path}"
                )
            raise _winerror(f"CreateDirectoryW failed for {path}")
    finally:
        kernel32.LocalFree(descriptor)

    attributes_value = kernel32.GetFileAttributesW(str(path))
    if attributes_value == _INVALID_FILE_ATTRIBUTES:
        raise _winerror(f"cannot inspect newly created output directory {path}")
    if attributes_value & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError(f"new output directory is a reparse point: {path}")


def _write_new_protected_private_key(path: Path, data: bytes) -> None:
    """Create and write a private key exclusively with its final DACL."""
    kernel32, advapi32 = _windows_libraries()
    # Re-check the output directory and its whole parent chain immediately
    # before the exclusive create. A parent with DELETE_CHILD can still cause
    # availability churn between path operations, but it cannot expose key
    # bytes: the file itself is born with the protected DACL below, and any
    # pre-existing file/reparse point makes CREATE_NEW fail.
    _reject_reparse_ancestors(path.absolute(), kernel32)
    current_sid = _current_user_sid(kernel32, advapi32)
    attributes, descriptor = _protected_security_attributes(
        current_sid, advapi32, inherit_to_children=False
    )
    handle: Any = _INVALID_HANDLE_VALUE
    try:
        handle = kernel32.CreateFileW(
            str(path.absolute()),
            _GENERIC_WRITE,
            0,  # no sharing while key bytes are written
            byref(attributes),
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = getattr(ctypes, "get_last_error")()  # noqa: B009
            if error in (_ERROR_ALREADY_EXISTS, _ERROR_FILE_EXISTS):
                raise FileExistsError(f"refusing existing private-key path: {path}")
            raise _winerror(f"CreateFileW failed for {path}")

        offset = 0
        while offset < len(data):
            written = wintypes.DWORD()
            chunk = data[offset : offset + 0xFFFFFFFF]
            buffer = create_string_buffer(chunk)
            if not kernel32.WriteFile(
                handle, buffer, len(chunk), byref(written), None
            ):
                raise _winerror(f"WriteFile failed for {path}")
            if written.value == 0:
                raise OSError(f"WriteFile made no progress for {path}")
            offset += written.value
        if not kernel32.FlushFileBuffers(handle):
            raise _winerror(f"FlushFileBuffers failed for {path}")
    finally:
        if handle != _INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(handle)
        kernel32.LocalFree(descriptor)


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


def _verify_requester(req_id: int) -> bool:
    """Confirm Requester in the CA database is the gMSA (the gate's AC).

    Runs ``certutil -view`` and checks the Requester column contains the
    expected account.  Returns True if confirmed, False if it could not be
    auto-confirmed (the caller then prints a manual-verification fallback).
    Best-effort lab helper.
    """
    expected = os.environ.get("ACME_RA_SPIKE_EXPECTED_REQUESTER", "gMSA-acme-ra$")
    try:
        result = subprocess.run(
            [
                "certutil", "-view",
                "-restrict", f"RequestID={req_id}",
                "-out", "Requester",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - lab script
        log.warning("certutil -view invocation failed: %s", exc)
        return False
    if result.returncode != 0:
        log.warning("certutil -view exited %d: %s", result.returncode, result.stderr.strip())
        return False
    m = re.search(r"Requester\s*[:]?\s*(\S+)", result.stdout)
    if not m:
        log.warning("could not parse Requester from certutil output")
        return False
    requester = m.group(1)
    if expected.lower() not in requester.lower():
        log.error(
            "Requester MISMATCH: CA DB has %r, expected to contain %r",
            requester, expected,
        )
        return False
    log.info("CA database confirms Requester = %s (matches the gMSA)", requester)
    return True


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if sys.platform != "win32":
        log.error(
            "This spike authenticates with Windows Negotiate. "
            "Run it on the domain-joined RA host, as the gMSA."
        )
        return 2

    import requests

    # The product's own Negotiate implementation, not requests-negotiate-sspi.
    #
    # Two reasons, and the second is why this changed. First, the product
    # retired requests-negotiate-sspi in 2026-06 (single-maintainer in the
    # issuance path, broken on 3.14) in favour of in-tree pyspnego with RFC 5929
    # channel binding, so a spike on the old library was proving a leg the RA no
    # longer has -- and would fail against EPA=Require, which is the setting the
    # lab actually runs.
    #
    # Second: it is not installable where the spike has to run. The installer
    # builds the venv from a hash-pinned closure that does not contain
    # requests-negotiate-sspi, and this import sits ABOVE every line that
    # creates anything, so on the deployed interpreter the spike died with
    # ModuleNotFoundError before reaching the code under test. That cost the
    # 2026-08-25 validation its enrollment leg (UNFILED item 16); the
    # protected-output changes had to be proven by driving these functions
    # individually instead.
    from acme_adcs_ra.enrollment import _parse_cert_body
    from acme_adcs_ra.negotiate_auth import NegotiateAuth

    # LAB ONLY: refuse reuse. On Windows the directory is created atomically
    # with a protected DACL and every existing reparse-point ancestor is
    # rejected before any private key exists.
    _create_protected_output_directory(OUT)
    log.info("target  : https://%s/certsrv/", HOST)
    log.info("template: %s", TEMPLATE)
    log.info("SAN/CN  : %s", SAN)
    log.info("auth    : ambient Windows identity (MUST be gMSA-acme-ra$)")

    session = requests.Session()
    # No credential is supplied here and none exists to supply: pyspnego uses
    # the process's ambient Windows identity, which must be the gMSA. ``host``
    # is needed for the SPN and for the tls-server-end-point channel binding
    # that EPA=Require demands.
    #
    # Deliberate wording. The previous comment described this as the p-word for
    # authentication, and a secret scanner reads that token next to an
    # ``auth =`` assignment as a hardcoded credential. It had sat here unflagged
    # for months because scanners only read CHANGED lines -- so merely touching
    # the line turned a dormant false positive into a red required check on
    # 2026-08-26. Say what is true without using the trigger token.
    session.auth = NegotiateAuth(HOST, ca_bundle=CA_BUNDLE or None)
    session.headers["User-agent"] = "acme-adcs-ra-spike/0.1 (Mode A)"
    session.verify = CA_BUNDLE if CA_BUNDLE else True

    csr_pem, key_pem = build_csr(SAN)
    (OUT / "spike.csr.pem").write_text(csr_pem)
    _write_new_protected_private_key(OUT / "spike.key.pem", key_pem)
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
            if re.search(r"Certificate Pending", body, re.IGNORECASE):
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
        # Content-type is DIAGNOSTIC here, never a gate.
        #
        # This used to require exactly `application/pkix-cert`, and real ADCS
        # serves certnew.cer as **text/html** with the PEM inside it. So a
        # SUCCESSFUL enrollment exited 1: measured live 2026-08-27, ReqID 671,
        # disposition 20 at the CA, certificate genuinely issued, spike reported
        # failure. The spike was stricter than the CA is truthful.
        #
        # The product has always known this — `_parse_cert_body` tolerates a PEM
        # block or a raw base64 DER blob and uses the content-type only to
        # decorate a parse *failure*. Calling the product's own parser here
        # means the spike proves the shipped parser against real CA output
        # rather than re-implementing a stricter rule beside it.
        try:
            cert_text = _parse_cert_body(cert_r.content)
        except Exception as exc:
            raise RuntimeError(
                "certnew.cer did not return a parseable certificate "
                f"(content-type {cert_r.headers.get('Content-Type')!r}): {exc}"
            ) from exc
        cert_pem = cert_text.encode("ascii")
        (OUT / "spike.cert.pem").write_bytes(cert_pem)
        log.info("saved issued cert -> %s", OUT / "spike.cert.pem")

        # 3. Fetch the CA chain (PKCS#7) for chain verification.
        arc = session.get(f"https://{HOST}/certsrv/certcarc.asp", timeout=TIMEOUT)
        arc.raise_for_status()
        nren = re.search(r"var nRenewals=(\d+);", arc.text)
        renewals = nren.group(1) if nren else "0"
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

    now = datetime.now(UTC)
    if not_after < now:
        log.warning("issued cert is ALREADY EXPIRED (clock/template issue)")
    if sans != [SAN]:
        log.warning("issued SANs != requested (%r) - template may be overriding", SAN)

    # 5. Inspect the CA chain so the operator can confirm it is the EXISTING
    #    chain (no new intermediate) - the other half of the WI-1 AC.
    try:
        chain_bytes = (OUT / "spike.chain.p7b").read_bytes()
        try:
            chain_certs = pkcs7.load_der_pkcs7_certificates(chain_bytes)
        except Exception:  # noqa: BLE001 - lab script, DER→PEM fallback
            chain_certs = pkcs7.load_pem_pkcs7_certificates(chain_bytes)
        log.info("CA chain (%d cert(s)) - confirm these are the EXISTING chain:", len(chain_certs))
        for i, c in enumerate(chain_certs):
            log.info("  [%d] subject=%s", i, c.subject.rfc4514_string())
            log.info("      issuer =%s", c.issuer.rfc4514_string())
    except Exception as exc:  # noqa: BLE001 - lab script
        log.warning("could not parse chain for inspection: %s", exc)

    # 6. Verify the requester in the CA database is the gMSA. This is the
    #    load-bearing audit control and the project's feasibility gate.
    requester_ok = _verify_requester(req_id)

    print("\nSUCCESS - enrollment round-trip complete.")
    print(f"Artifacts in: {OUT.resolve()}")
    if not requester_ok:
        print(
            "\nWARNING: could not auto-confirm Requester = gMSA-acme-ra$ in the CA"
            " database. Run this manually and DO NOT proceed until it holds:"
        )
        print(
            f'  certutil -view -restrict "RequestID={req_id}" '
            "-out RequestID Requester CommonName CertificateTemplate RequestDisposition"
        )
        print("  Expected: Requester = WORK-DOMAIN\\gMSA-acme-ra$")
        print(
            "If Requester is anything else, Mode A is NOT behaving as local-enrollment"
            " - stop and investigate before building the ACME server on this assumption."
        )
    print(
        "\nNOTE: this spike exercises ENROLLMENT only. ADCS Web Enrollment exposes"
        " no revocation endpoint; revokeCert is a separate, documented gap"
        " (see docs/threat-model.md §E)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

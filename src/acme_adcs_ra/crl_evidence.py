"""Independent CRL evidence for CA-side revocation confirmations.

The RA holds no CA rights, so it cannot ask the CA "did you revoke this?".
That is why the WI-024 confirmation callback exists: the CA-side pull agent
runs ``certutil -revoke`` and then tells the RA it succeeded. The RA used to
take that entirely on faith and write ``revocation-ca-confirmed`` — an audit
event asserting an external security event it had not observed.

There is exactly one check available to the RA that does **not** depend on the
calling agent's honesty: the CRL. It is published by the CA, signed by the CA's
own key, and readable without any privilege. If a serial appears on a validly
signed CRL, the certificate really is revoked, no matter what the agent claims.

This module fetches and verifies that evidence. It is deliberately strict:

* the CRL's signature is verified against the **issuing CA certificate taken
  from the certificate's own stored chain** — not against whatever the CRL
  claims about itself, and not against a separately configured trust anchor
  that could drift from the chain the certificate was actually issued under;
* freshness is checked independently of the signature, because a signed CRL
  stays cryptographically valid for ever: ``nextUpdate`` must be present and
  in the future, ``thisUpdate`` must not be in the future, and the document
  must be within an absolute age ceiling. A replayed pre-revocation CRL is
  exactly what an attacker suppressing a revocation would like the RA to keep
  accepting, and ``nextUpdate`` alone is under the CA's control;
* every failure returns "no evidence" rather than raising, so the caller
  decides whether missing evidence is fatal (``require_crl_evidence``) or
  merely downgrades the audit record to ``agent-asserted``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast
from urllib.parse import ParseResult, urljoin, urlparse

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("acme_adcs_ra.crl_evidence")

# Tolerance for a CA clock running slightly ahead of the RA's.
_CLOCK_SKEW = timedelta(minutes=5)

# Verification outcomes recorded in the audit trail.
CRL_VERIFIED = "crl-verified"
AGENT_ASSERTED = "agent-asserted"

# How many ``Location`` hops a CRL retrieval will follow. A CDP that needs more
# than a couple is misconfigured; the cap is here because the chain is chosen by
# whoever answers the CDP, not by the operator.
_MAX_CRL_REDIRECTS = 4

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class CrlEvidence:
    """The result of checking a serial against the CA's published CRL."""

    # True only when a validly signed, in-date CRL lists this serial.
    revoked: bool
    # True when a CRL was fetched and verified, whatever it said about the
    # serial. False means we learned nothing (fetch/parse/signature failure).
    checked: bool
    detail: str
    crl_number: str | None = None
    this_update: str | None = None
    next_update: str | None = None

    @property
    def verification(self) -> str:
        return CRL_VERIFIED if (self.checked and self.revoked) else AGENT_ASSERTED


def _issuer_public_key(cert_pem: str, chain_pem: list[str]) -> object | None:
    """Find the public key that signed *cert_pem*, from its own stored chain.

    The chain is what the CA returned at issuance, so it is the authoritative
    statement of which CA certificate this leaf was issued under.

    **Matching is by signature, not by name.** Selecting the first chain entry
    whose subject equalled the leaf's issuer was wrong in a case ADCS produces
    routinely: a **CA key renewal** keeps the subject DN and changes the key, so
    a chain carrying both generations has two equally good name matches and only
    one of them actually signed this leaf. Picking the wrong one made the CRL
    signature check fail, which withholds evidence — safe, but it presents as an
    unexplained refusal to confirm, and under
    ``require_crl_evidence`` it wedges revocation confirmation entirely.

    ``verify_directly_issued_by`` checks the signature (and the issuer/subject
    correspondence) rather than trusting the name, so the right generation is
    selected even when several share a DN.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except ValueError:
        return None
    for pem in chain_pem:
        # A chain entry may itself hold several concatenated PEM certificates.
        try:
            candidates = x509.load_pem_x509_certificates(pem.encode("utf-8"))
        except ValueError:
            continue
        for candidate in candidates:
            if candidate.subject != leaf.issuer:
                continue
            try:
                leaf.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                # Right name, wrong key — keep looking for the generation that
                # actually signed this leaf.
                continue
            return candidate.public_key()
    return None


def _abort_transfer(
    response: requests.Response, timed_out: threading.Event
) -> None:
    """Tear the transport down so a worker blocked in ``recv`` returns.

    ``response.close()`` alone is not enough: it releases the connection back
    to the pool and closes the buffered reader, but a thread already parked
    inside a socket read is not woken by that. ``shutdown(SHUT_RDWR)`` on the
    socket itself is — on POSIX the pending ``recv`` returns end-of-stream
    immediately. Reaching the socket means going through urllib3's internals,
    so every step is guarded: failing to abort must never raise into the timer
    thread, where nothing could handle it. The flag is set first so the reader
    reports a deadline rather than a fetch failure either way.

    **Windows needs the close as well, and that is not a detail** (2026-08-18).
    Winsock does not wake a ``recv`` parked in another thread on ``shutdown``;
    only ``closesocket`` does. So on the RA's *production* platform this
    watchdog set its flag and then achieved nothing: the read stayed parked
    until the per-read timeout expired. CI measured a 0.5s total deadline
    overshooting to 8.0s — exactly the per-read bound, i.e. precisely the
    behaviour the watchdog was added to eliminate. The control existed on Linux
    and was absent where the RA actually runs.
    """
    timed_out.set()
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        if sys.platform == "win32":
            # The blocked ``recv`` fails immediately with an OSError once the
            # handle is gone; the reader sees ``timed_out`` set and reports a
            # deadline, so the exact error does not matter.
            with contextlib.suppress(OSError):
                sock.close()
        # Deliberately NOT response.close() here as well. Closing from this
        # thread while the worker is inside ``read1`` frees the file object
        # out from under it, which surfaces as an AttributeError deep in
        # http.client rather than a clean end-of-stream. The shutdown is
        # sufficient on POSIX, and the reader's own ``contextlib.closing``
        # does the closing on the thread that owns the read.
        #
        # Closing the *socket* on POSIX is avoided for a different reason:
        # retiring an fd that another thread is blocked in ``read()`` on
        # invites an fd-reuse race, and ``shutdown`` already works there.
        return
    # No socket to reach (a mock, or urllib3 internals moved): fall back to
    # the blunt instrument, which at least stops a fresh read from starting.
    with contextlib.suppress(Exception):
        response.close()


def _effective_port(parsed: ParseResult) -> int | None:
    """The port a URL actually connects to, filling in the scheme default."""
    if parsed.port is not None:
        return parsed.port
    return _DEFAULT_PORTS.get(parsed.scheme)


def _resolve_addresses(host: str, port: int | None) -> frozenset[str]:
    """The set of IP addresses *host* currently resolves to, or empty on failure."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return frozenset()
    return frozenset(str(info[4][0]) for info in infos)


def _vet_redirect(
    location: str,
    current_url: str,
    origin: ParseResult,
    pinned_addresses: frozenset[str] = frozenset(),
) -> tuple[str | None, str]:
    """Resolve a ``Location`` and decide whether it may be followed.

    Returns ``(url, "")`` when the hop is allowed and ``(None, reason)`` when it
    is not.

    The operator picked the configured CDP, so that URL is trusted. A
    ``Location`` header is picked by whoever *answers* that CDP — a hostile or
    on-path CRL server — so following it wherever it points turns the RA into a
    blind SSRF probe against anything its network can reach. The rule is
    therefore: a redirect may change only the **path** of the configured origin,
    plus the one documented http→https upgrade.

    Two ways the first version of this was too loose (2026-08-18 rescan F2):

    * **The port.** It accepted the target scheme's default port as an
      alternative to the origin's, which was meant to allow 80→443 on an upgrade
      but also allowed the reverse move: a CDP configured on
      ``http://host:8080`` could redirect to ``http://host:80``, and
      ``https://host:8443`` to ``https://host:443``. Same host, different port,
      different service — exactly what the check claimed to forbid. The upgrade
      is now spelled out as precisely that one transition.
    * **The name.** Comparing hostname text does not bind the address the hop
      actually connects to, and each hop resolves the name again. An attacker
      controlling DNS for the configured CDP name can answer the second lookup
      with any address. *pinned_addresses* is what the host resolved to at the
      start of the retrieval; a hop whose resolution has moved outside that set
      is refused.
    """
    target = urljoin(current_url, location)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, f"target is not an http(s) URL with a host: {target!r}"
    origin_host = (origin.hostname or "").lower()
    if parsed.hostname.lower() != origin_host:
        return None, (
            f"target leaves the configured CRL host "
            f"({origin_host!r} -> {parsed.hostname.lower()!r})"
        )
    if origin.scheme == "https" and parsed.scheme == "http":
        return None, "target downgrades https to http"

    origin_port = _effective_port(origin)
    allowed_ports = {origin_port}
    if (
        origin.scheme == "http"
        and parsed.scheme == "https"
        and origin_port == _DEFAULT_PORTS["http"]
    ):
        # The one documented transition: a CDP on plain http's default port
        # redirecting to https on *its* default port. Nothing else.
        allowed_ports.add(_DEFAULT_PORTS["https"])
    port = _effective_port(parsed)
    if port not in allowed_ports:
        return None, (
            f"target changes the port ({origin_port} -> {port}); same host, "
            "different service"
        )

    if pinned_addresses:
        now = _resolve_addresses(parsed.hostname, port)
        if not now:
            return None, f"target host {parsed.hostname!r} no longer resolves"
        if not now <= pinned_addresses:
            # DNS moved under us between the first request and this hop.
            return None, (
                f"target host {parsed.hostname!r} now resolves outside the "
                f"addresses seen at the start of this retrieval "
                f"({sorted(now - pinned_addresses)} not in {sorted(pinned_addresses)})"
            )
    return target, ""


class _LiveTransfer:
    """The response the deadline watchdog should tear down, if one exists yet.

    The watchdog is armed *before* the first request so that DNS, connect, TLS
    and the status/header exchange count against the total deadline as well —
    previously the clock only started once a final response object was in hand,
    which left everything before that point outside every control the function
    advertises. Each hop registers its response here as soon as it has one.
    """

    def __init__(self) -> None:
        self.response: requests.Response | None = None


def _past_deadline(timed_out: threading.Event, deadline: float) -> bool:
    """Whether a failed retrieval should be reported as a deadline expiry.

    Two mechanisms can terminate a transfer at the deadline and they race
    (2026-08-18 rescan, found on Windows CI):

    * the watchdog tears the socket down and sets *timed_out* — definitive; and
    * the per-hop socket timeout expires on its own, because it is **clamped to
      the wall-clock remaining**. Nothing sets the flag in that case, so the
      outcome used to be reported as a generic "CRL read failed" — which is what
      the flag exists to prevent, and which made the reason nondeterministic
      between platforms. Linux happened to lose the race the other way.

    The clock comparison is exact rather than approximate, and does not need a
    tolerance: the clamped timeout is ``deadline - t0`` for some ``t0`` taken
    before the read begins at ``t1 >= t0``, so it cannot expire before
    ``t1 + (deadline - t0) >= deadline``. When the clamp is *not* what bound the
    read (``timeout_seconds`` was the smaller of the two), expiry says nothing
    about the deadline and the real transport error is reported instead.
    """
    return timed_out.is_set() or time.monotonic() >= deadline


def _abort_live(live: _LiveTransfer, timed_out: threading.Event) -> None:
    """Deadline expiry: flag it, and tear down the transfer if one is up."""
    response = live.response
    if response is None:
        # No response object yet, so there is no socket to reach: requests is
        # still inside its own connect/header read and does not hand back a
        # handle until that completes. Setting the flag is what is available,
        # and every check after that point sees it and bails without reading a
        # byte of body. The residual — a peer that never finishes sending
        # headers — is bounded by the per-read timeout, by http.client's
        # header-size caps, and by the gate's dedicated executor and admission
        # ceiling, which keep it off the issuance path entirely.
        timed_out.set()
        return
    _abort_transfer(response, timed_out)


def fetch_crl_evidence(
    *,
    crl_url: str,
    serial_number: int,
    cert_pem: str,
    chain_pem: list[str],
    timeout_seconds: float = 10.0,
    max_bytes: int = 10 * 1024 * 1024,
    max_age_seconds: int = 7 * 24 * 3600,
    total_timeout_seconds: float = 30.0,
    follow_redirects: bool = False,
) -> CrlEvidence:
    """Check whether *serial_number* is on the CA's published CRL.

    Never raises: any failure is reported as ``checked=False`` with a reason.

    ``timeout_seconds`` is what ``requests`` understands: a bound on the
    connect and on each individual socket read. ``total_timeout_seconds`` is
    the wall-clock bound on the whole retrieval, and it is the one that
    matters for availability — a server that emits one byte just before every
    read timeout never trips the per-read bound and can hold the calling
    worker indefinitely (2026-08-16 rescan F4).

    ``follow_redirects`` defaults to **False** (2026-08-18 rescan F2). Every
    redirect is a destination chosen by whoever answers the configured CDP, and
    a CDP that redirects at all is unusual — so the default removes the hop
    rather than policing it. Enabled, hops are held to the configured origin:
    same host, same port (bar one documented http:80 → https:443 upgrade), and
    the host must keep resolving inside the address set seen at the start.
    """
    parsed = urlparse(crl_url)
    # A CRL is signed, so plain HTTP is normal and safe for CDPs; anything
    # that is not an HTTP(S) URL (file://, etc.) is not.
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL URL must be http(s) with a host: {crl_url!r}",
        )

    def deadline_evidence(received: int, cause: str | None = None) -> CrlEvidence:
        detail = (
            f"CRL retrieval exceeded its {total_timeout_seconds}s total "
            f"deadline after {received} bytes"
        )
        if cause:
            # Keep the underlying transport error visible: the deadline is the
            # right *reason*, but which mechanism actually tore the transfer
            # down is worth having when diagnosing a CDP.
            detail += f" ({cause})"
        return CrlEvidence(revoked=False, checked=False, detail=detail)

    origin = parsed
    # Resolved once, before the first request, and only when a redirect could
    # actually use it — this is what a later hop's resolution is held against so
    # DNS cannot move the destination mid-chain. An empty set (resolution failed
    # here) means the check below is skipped rather than blocking the fetch: the
    # request itself is about to fail on the same lookup and will say so.
    pinned_addresses: frozenset[str] = frozenset()
    if follow_redirects:
        pinned_addresses = _resolve_addresses(parsed.hostname, _effective_port(parsed))
    deadline = time.monotonic() + total_timeout_seconds
    # Set by the watchdog below, and the reason a torn-down transfer is
    # reported as a deadline rather than as a fetch failure.
    timed_out = threading.Event()
    live = _LiveTransfer()
    # 2026-08-17 F3 established that the deadline needs an enforcer that does
    # not depend on the read loop getting to run: for a **non-chunked,
    # Content-Length** response the underlying read waits for a full 64 KiB, and
    # a peer dribbling a byte every 20ms satisfies each socket read (so the
    # per-read timeout keeps resetting) while never delivering enough to yield a
    # chunk. Shutting the socket down from a timer thread is the only thing that
    # reliably interrupts a blocked read we are not the ones performing.
    #
    # 2026-08-18 F1 moved the arming to *here*, before the first request, rather
    # than after a final response object existed. Connect, TLS and the header
    # exchange are attacker-influenced work too, and a redirect chain used to
    # happen entirely inside `requests.get` — outside this deadline, outside the
    # byte budget, and against destinations nothing had validated.
    watchdog = threading.Timer(
        total_timeout_seconds, _abort_live, args=(live, timed_out)
    )
    watchdog.daemon = True
    watchdog.start()
    body = b""
    url = crl_url
    try:
        for _hop in range(_MAX_CRL_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if timed_out.is_set() or remaining <= 0:
                return deadline_evidence(len(body))
            # allow_redirects=False is the load-bearing part. With the default,
            # requests resolves the whole chain inside this one call: it reads
            # each redirect's body and issues each subsequent request itself,
            # so neither the destination check below nor the byte budget nor
            # the deadline ever saw any of it.
            response = requests.get(
                url,
                # Clamp to what is left, so no single hop can be granted more
                # socket patience than the whole retrieval has remaining.
                timeout=min(timeout_seconds, remaining),
                stream=True,
                allow_redirects=False,
            )
            live.response = response
            # Closed on every exit path, including the deadline and size
            # bail-outs: with stream=True the transfer is only actually torn
            # down when the response is closed, so an early `return` that
            # leaked it would keep the socket — and the trickle — alive. It is
            # also what discards a redirect's body unread.
            with contextlib.closing(response):
                if timed_out.is_set():
                    return deadline_evidence(len(body))

                if 300 <= response.status_code < 400:
                    if not follow_redirects:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=(
                                f"CRL fetch returned {response.status_code} and "
                                "redirects are disabled. Point "
                                "revocation_confirm_crl_url at the final CRL URL, "
                                "or set "
                                "revocation_confirm_crl_follow_redirects=true if "
                                "this CDP must redirect."
                            ),
                        )
                    location = response.headers.get("Location")
                    if not location:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=(
                                f"CRL fetch returned {response.status_code} "
                                "with no Location header"
                            ),
                        )
                    target, refusal = _vet_redirect(
                        location, url, origin, pinned_addresses
                    )
                    if target is None:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=f"CRL fetch refused a redirect: {refusal}",
                        )
                    url = target
                    continue

                response.raise_for_status()

                # ``read1`` returns as soon as the socket has data, rather than
                # waiting to fill a chunk, so the deadline check below also runs
                # once per socket read instead of once per 64 KiB. Belt and
                # braces with the watchdog: this exits cleanly on the common
                # trickle, the watchdog guarantees the pathological one.
                while not timed_out.is_set():
                    chunk = response.raw.read1(65536, decode_content=True)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > max_bytes:
                        return CrlEvidence(
                            revoked=False,
                            checked=False,
                            detail=f"CRL exceeded {max_bytes} bytes",
                        )
                    if time.monotonic() >= deadline:
                        return deadline_evidence(len(body))
                if timed_out.is_set():
                    return deadline_evidence(len(body))
                break
        else:
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=(
                    f"CRL fetch exceeded {_MAX_CRL_REDIRECTS} redirects "
                    f"without reaching a document"
                ),
            )
    except requests.RequestException as exc:
        # A watchdog teardown surfaces here as a broken/incomplete read on a
        # Content-Length response. Report what actually happened.
        if _past_deadline(timed_out, deadline):
            return deadline_evidence(len(body), str(exc))
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL fetch failed: {exc}"
        )
    except Exception as exc:
        # Reading through ``response.raw`` means urllib3's exceptions, not
        # requests' — a transport torn down mid-read surfaces as
        # ``ProtocolError``/``IncompleteRead``, and http.client can contribute
        # its own low-level errors. urllib3 is only a transitive dependency
        # here (via requests), so catching its hierarchy by name would mean
        # importing something this project does not declare. Everything is "no
        # evidence" either way; the caller decides whether that is fatal.
        if _past_deadline(timed_out, deadline):
            return deadline_evidence(len(body), str(exc))
        logger.warning("CRL read failed", exc_info=True)
        return CrlEvidence(
            revoked=False, checked=False, detail=f"CRL read failed: {exc}"
        )
    finally:
        if watchdog is not None:
            watchdog.cancel()

    crl: x509.CertificateRevocationList | None = None
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            crl = loader(body)
            break
        except ValueError:
            continue
    if crl is None:
        return CrlEvidence(
            revoked=False, checked=False, detail="CRL is neither valid DER nor PEM"
        )

    public_key = _issuer_public_key(cert_pem, chain_pem)
    if public_key is None:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                "could not locate the issuing CA certificate in the stored "
                "chain, so the CRL signature cannot be verified"
            ),
        )
    if not crl.is_signature_valid(public_key):  # type: ignore[arg-type]
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail="CRL signature does not verify against the certificate's issuer",
        )

    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    now = datetime.now(UTC)

    # Freshness, three ways. A signed CRL stays cryptographically valid forever,
    # so signature verification alone says nothing about *when* it was true — an
    # attacker who can replay an old, genuinely-signed CRL could otherwise keep
    # feeding the RA a pre-revocation view indefinitely.
    if next_update is None:
        # Without nextUpdate there is no expiry, so the document would be
        # accepted for ever. ADCS always sets it; a CRL that does not is not
        # something to accept as evidence.
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail="CRL has no nextUpdate, so its freshness cannot be established",
            this_update=this_update.isoformat() if this_update else None,
        )
    if next_update < now:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=f"CRL expired at {next_update.isoformat()}",
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat(),
        )
    if this_update is not None:
        if this_update > now + _CLOCK_SKEW:
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=f"CRL thisUpdate {this_update.isoformat()} is in the future",
                this_update=this_update.isoformat(),
                next_update=next_update.isoformat(),
            )
        # nextUpdate alone is under the CA's control and can be set arbitrarily
        # far out; an independent ceiling on age bounds how stale a view the RA
        # will act on regardless.
        age = now - this_update
        if age > timedelta(seconds=max_age_seconds):
            return CrlEvidence(
                revoked=False,
                checked=False,
                detail=(
                    f"CRL is {int(age.total_seconds())}s old, over the "
                    f"{max_age_seconds}s freshness limit"
                ),
                this_update=this_update.isoformat(),
                next_update=next_update.isoformat(),
            )

    crl_number: str | None = None
    try:
        crl_number = str(
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        pass

    # A delta CRL is not standalone evidence. It carries only the CHANGES since
    # its base CRL, and it is the one document where `removeFromCRL` is allowed
    # to appear (RFC 5280 §5.3.1) — an entry there can mean "this certificate
    # came OFF the revocation list". Treating a delta as a base CRL therefore
    # gets the answer backwards in exactly the case that matters. The RA has no
    # base CRL to apply it to, so it refuses to draw a conclusion.
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        pass
    else:
        return CrlEvidence(
            revoked=False,
            checked=False,
            detail=(
                "CRL is a delta CRL (DeltaCRLIndicator present); it lists only "
                "changes since a base CRL and cannot prove a serial's current "
                "revocation state. Point revocation_confirm_crl_url at the base CRL."
            ),
            crl_number=crl_number,
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat() if next_update else None,
        )

    entry = crl.get_revoked_certificate_by_serial_number(serial_number)

    # Presence on a CRL is not the same as being revoked. `removeFromCRL`
    # (reason 8) means the opposite: a certificate that was on hold has been
    # REINSTATED, and relying parties should stop treating it as revoked. The
    # RA already refuses reason 8 on the ACME revoke route for this reason
    # (2026-08-14 F3); accepting it as *evidence* of revocation is the same
    # defect facing the other way, and it would drain a still-valid certificate
    # off the pending-revocation queue while recording `crl-verified`.
    #
    # This state is reachable in practice, not hypothetically: `certutil
    # -revoke <serial> 8` after a hold is the documented un-hold, and it is how
    # this project's own lab has released test certificates.
    reason: x509.ReasonFlags | None = None
    if entry is not None:
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        except x509.ExtensionNotFound:
            reason = None  # absent reason means unspecified, which IS a revocation

    if entry is not None and reason is x509.ReasonFlags.remove_from_crl:
        return CrlEvidence(
            revoked=False,
            checked=True,
            detail=(
                "serial is listed on the CRL with reason removeFromCRL, which "
                "means the certificate was taken OFF hold and is NOT revoked"
            ),
            crl_number=crl_number,
            this_update=this_update.isoformat() if this_update else None,
            next_update=next_update.isoformat() if next_update else None,
        )

    return CrlEvidence(
        revoked=entry is not None,
        checked=True,
        detail=(
            f"serial is listed on the CRL (reason={reason.name if reason else 'unspecified'})"
            if entry is not None
            else "serial is NOT listed on the CRL"
        ),
        crl_number=crl_number,
        this_update=this_update.isoformat() if this_update else None,
        next_update=next_update.isoformat() if next_update else None,
    )


_T = TypeVar("_T")


class CrlEvidenceGateBusy(Exception):
    """The gate is at its admission ceiling; shed the request, do not queue it.

    Raised rather than returning "no evidence" on purpose. Absent evidence is a
    statement about the CRL, and under ``require_crl_evidence`` it would be
    recorded as one — but being too busy to look says nothing about whether the
    certificate is revoked. The caller turns this into a retryable status.
    """


class CrlEvidenceGate:
    """Run CRL evidence fetches off the shared enrollment worker pool.

    Two separate problems, one owner (2026-08-16 rescan F4):

    *Pool isolation.* ``run_in_threadpool`` hands work to AnyIO's default
    thread limiter — the same finite set of tokens that ``finalize`` uses for
    the synchronous ADCS enrollment call. CRL retrieval is an outbound fetch
    of an operator-configured URL whose duration a third party influences, so
    letting it draw from that pool means a slow CRL host can queue issuance
    behind it. This gate owns a small dedicated executor instead: a stalled
    CRL can exhaust *this* pool, and issuance is unaffected.

    *Single flight.* Confirmations are idempotent but the idempotence check
    (``ca_crl_updated``) only helps once a reconciliation has committed, so N
    concurrent confirmations for one serial all passed the check and all
    fetched. Concurrent callers for the same key now share one retrieval, and
    a flood of confirmations for a single serial costs exactly one fetch.

    *Admission control* (2026-08-17 F3). ``max_workers`` bounds how many
    retrievals *run*, not how many are accepted. ``ThreadPoolExecutor``'s work
    queue is an unbounded ``SimpleQueue``, and every waiting caller also
    retains a suspended request task, so distinct keys arriving faster than
    they complete grow both without limit. ``max_pending`` is the ceiling on
    distinct flights in progress; past it, :meth:`run` raises
    :class:`CrlEvidenceGateBusy` and the caller sheds the request instead of
    queueing it. Callers joining an *existing* flight are never rejected —
    they cost nothing new.

    Cancellation-safe: a caller that disconnects does not cancel the shared
    retrieval out from under the callers still waiting on it.
    """

    def __init__(self, max_workers: int = 2, max_pending: int = 32) -> None:
        self._max_workers = max_workers
        self._max_pending = max_pending
        self._executor: ThreadPoolExecutor | None = None
        self._inflight: dict[str, asyncio.Future[Any]] = {}
        self._closed = False

    def set_limits(self, *, max_workers: int, max_pending: int) -> None:
        """Size the gate from config, before the pool is first used.

        ``ServerContext`` builds a gate eagerly so a directly-constructed
        context is always usable; ``create_app`` calls this to apply the
        operator's settings. Once the pool exists its size is fixed — resizing
        under live confirmations would be a needless race, and the RA reads
        config once at startup anyway. The admission ceiling is not tied to the
        pool, so it always takes effect.
        """
        self._max_pending = max_pending
        if self._executor is None:
            self._max_workers = max_workers

    @property
    def inflight(self) -> int:
        """Distinct retrievals currently in progress."""
        return len(self._inflight)

    def _pool(self) -> ThreadPoolExecutor:
        # Lazy: an RA with no CRL configured never spawns the threads.
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="ra-crl-evidence",
            )
        return self._executor

    async def run(
        self, key: str, fn: Callable[..., _T], /, *args: Any
    ) -> _T:
        """Run ``fn(*args)`` on the dedicated pool, single-flighted on *key*."""
        if self._closed:
            raise RuntimeError("CrlEvidenceGate is closed")
        pending = self._inflight.get(key)
        # A *finished* entry is not a flight to join. ``add_done_callback`` on
        # a Future is dispatched through ``call_soon``, so between a retrieval
        # completing and its cleanup callback running there is a window in
        # which the key is still mapped to a settled future — and a caller that
        # arrived in that window would be handed the previous fetch's result as
        # if it were fresh. Confirmations are exactly the workload that arrives
        # in bursts, so this is reachable, not theoretical.
        if pending is not None and pending.done():
            self._inflight.pop(key, None)
            pending = None
        if pending is None:
            # Admission control before submission, and only for work that is
            # genuinely new — a caller joining an existing flight adds nothing
            # to shed.
            if len(self._inflight) >= self._max_pending:
                raise CrlEvidenceGateBusy(
                    f"{len(self._inflight)} CRL evidence retrievals already in "
                    f"progress (limit {self._max_pending})"
                )
            pending = asyncio.wrap_future(self._pool().submit(fn, *args))
            self._inflight[key] = pending
            # Clear on completion rather than in a caller's ``finally``: the
            # first caller may be cancelled while later ones still await the
            # same retrieval, and popping the key early would let a third
            # caller start a duplicate fetch. Single-threaded event loop, so
            # no lock is needed around the dict.
            #
            # The identity check is what makes this safe against its own
            # lateness (2026-08-18 F3). ``add_done_callback`` is dispatched
            # through ``call_soon``, so a caller can observe the settled future
            # in the branch above, pop it, and install a *successor* under the
            # same key before this callback ever runs. An unconditional
            # ``pop(key)`` would then evict that live successor: further callers
            # would submit duplicates for a serial already being fetched, and
            # the successor would drop out of the ``max_pending`` accounting
            # while still holding a worker.
            def _clear(finished: asyncio.Future[Any], k: str = key) -> None:
                if self._inflight.get(k) is finished:
                    del self._inflight[k]

            pending.add_done_callback(_clear)
        # shield() so that one caller's cancellation (a client disconnect)
        # leaves the shared retrieval running for the others.
        return cast("_T", await asyncio.shield(pending))

    def close(self) -> None:
        """Stop accepting work and release the threads, if any were started."""
        self._closed = True
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

# Security review — 2026-08-18 rescan

Scope: a standard repository-mode rescan (Codex, in collaboration with Daybreak
Blue) of `d26b892`, the branch that closed the 2026-08-18 findings. **All five
of those were confirmed closed.** Two new findings: one medium, one low, both
high confidence.

Baseline at review time: 710 pytest + 1 skipped. After the fixes: **733 pytest +
1 skipped**, ruff and mypy clean.

**Both findings are defects the 2026-08-18 fixes introduced.** That is worth
saying plainly rather than burying: the medium is a *repair* migration that
could crash the RA or preserve the exact bypass it was written to remove, and
the low is a hole in the origin check I added to close an SSRF. A fix is new
code and gets the same scrutiny as old code.

## Finding 1 (medium) — the twin migration crashed startup or preserved the bypass

`_migrate_accounts_canonical_jwk` canonicalized account JWKs row by row while
its duplicate detection was only advisory. On a database holding one key under
both a canonical and a non-canonical encoding, the outcome depended on row order
and on whether the UNIQUE thumbprint index already existed — and both outcomes
were wrong:

- **Index present.** Rewriting the non-canonical row to its twin's canonical
  thumbprint raised `UNIQUE constraint failed: accounts.jwk_thumbprint` straight
  out of `Store.__init__`. An uncaught `IntegrityError` during startup, from the
  migration whose job was to repair the database. The RA does not start.
- **Index absent.** The twin was logged, the subsequent index creation failed and
  was suppressed by design, and the RA came up **serving both rows with the same
  canonical key**. Deactivating one still left the other usable — precisely the
  deactivation bypass the 08-18 F5 fix existed to close, now preserved *by the
  migration that was supposed to remove it*.

The root cause was mutating while walking, with collision handling as a log
line. The in-memory `canonical_seen` check only ever saw rows processed so far,
while the UPDATE collided against rows the loop had not reached.

**Fixed** as a two-pass, fail-closed migration:

- **Pass 1 reads and canonicalizes everything in memory. No writes.** Rows are
  grouped by the thumbprint each one *will* hold — the canonical thumbprint for a
  readable JWK, the stored one for a row that cannot be parsed. Unreadable rows
  take part in the grouping too, or the index could still fail after the
  migration had declared the database clean.
- **Collision policy runs before any mutation.** Any group with more than one row
  raises `StoreMigrationError` naming the account ids, stating that nothing was
  modified, and telling the operator what to do. A duplicate account key makes
  deactivation unenforceable; that is a security-invariant violation and an
  operator decision, not something to log past.
- **Pass 2 applies the rewrites**, every thumbprint now known unique, via one
  `executemany`.
- **A post-migration invariant** re-checks for duplicate thumbprints in SQL and
  refuses to serve if any remain. Cheap, runs on every start, and it is what
  would catch a future insert path that forgot to canonicalize.

An unreadable stored JWK is logged loudly but does **not** block startup on its
own: `authenticate_account` rebuilds the key from that same JSON and the strict
decoder rejects it, so the row cannot authenticate and is not a bypass risk.
It is inert, not dangerous.

## Finding 2 (low) — the redirect origin check was incomplete

Two holes in the same-host rule added for 08-18 F1.

**The port.** `_vet_redirect` accepted the *target scheme's default port* as an
alternative to the configured origin's:

```python
if port not in (_effective_port(origin), _DEFAULT_PORTS[parsed.scheme]):
```

That was meant to permit an http:80 → https:443 upgrade. It also permitted the
reverse move: a CDP configured on `http://host:8080` could redirect to
`http://host:80`, and `https://host:8443` to `https://host:443`. Same host,
different port, different service — exactly what the check's own comment claimed
to forbid. My own test only covered the direction that happened to be refused
(default port → custom port), which is why it passed.

**The name.** Hostname string equality does not bind the address a hop actually
connects to, and each hop issues a fresh `requests.get` and so a fresh DNS
lookup. An attacker controlling DNS for the configured CDP name could answer the
second lookup with any address.

**Fixed** three ways, strictest first:

- **Redirects are now off by default** — new
  `revocation_confirm_crl_follow_redirects`, default `false`. Every redirect is a
  destination chosen by whoever answers the CDP, and a CDP that redirects at all
  is unusual, so the default removes the hop rather than trying to police it. A
  3xx now returns "no evidence" with a detail naming both ways out: point
  `revocation_confirm_crl_url` at the final URL, or set the flag.
- **The port rule is exact.** The effective port must equal the origin's, with
  the one documented exception spelled out as itself: origin `http` on port 80
  redirecting to `https` on 443. Nothing else, and the upgrade does not apply
  from a custom port.
- **The resolved address is pinned.** The host is resolved once before the first
  request; a hop whose resolution has moved outside that address set is refused,
  as is a host that stops resolving.

**Deliberately not done: a private/loopback/link-local address block.** The
report suggests rejecting unapproved resolved addresses. The RA's CDP is
legitimately an internal host on a private address in every deployment this
project targets, so a blanket block would break the normal case, and an
operator-approved network allowlist is more configuration surface than a low
finding justifies. Pinning the address set addresses the security-relevant
delta — the destination *changing* mid-chain — without that. If a deployment
wants a hard egress boundary, the threat model already puts that at the network
layer.

There is a residual TOCTOU: the pin check resolves, then `requests` resolves
again for the connection. An attacker alternating between two addresses could
still win the race. Closing it properly means connecting to a validated address
and verifying the peer, which needs a custom transport adapter — noted rather
than done, at low severity, behind a default-off flag.

## Verification

`tests/test_security_review_2026_08_18_rescan.py` — 23 tests. Each was
mutation-checked; notably, reverting the collision refusal reproduces the
report's exact `sqlite3.IntegrityError: UNIQUE constraint failed:
accounts.jwk_thumbprint`, and reverting the refusal *and* the post-migration
invariant together reproduces the fail-open half (7 tests fail).

Mutations exercised: collision refusal removed; collision refusal and
post-migration invariant both removed; the scheme-default-port alternative
restored; address pinning disabled; `follow_redirects` defaulted to true.

Suite after the fixes: 733 pytest + 1 skipped, ruff clean, mypy clean. The
2026-08-18 redirect tests were updated to opt into `follow_redirects=True` —
their subject is the opt-in path, which still needs covering.

No live IIS/ADCS proof. Both open questions from the report are for the operator:
whether any production CDP uses a non-default port or DNS outside the RA
operator's trust domain, and whether any deployed database contains legacy
alternate-encoding account twins. **The second one now matters at startup** — a
database with a staged twin will refuse to start on this branch, by design. An
offline canonical-thumbprint collision audit before deploying is the right
precaution, and the refusal message is written to be actionable if it fires.

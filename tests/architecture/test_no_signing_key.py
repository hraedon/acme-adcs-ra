"""Architecture guardrail: no certificate-signing primitive is reachable from src/.

Threat model and scope
----------------------
This guard catches **accidental** introduction of certificate-signing primitives
into the issuance path (CertificateBuilder, .sign(), pyOpenSSL, shell-out to
openssl, dynamic-code-loading tricks).  It is **NOT** a defense against a
determined adversary who controls the source repository — that threat is
addressed by code review and the gMSA/template privilege scoping described in
AGENTS.md.  The complementary control in ``test_no_signing_dependencies.py``
asserts the dependency set contains no signing-capable library, so even a
hidden import of e.g. pyOpenSSL would fail at install time.

Approach
--------
1. AST-scan every .py under ``src/acme_adcs_ra/`` for forbidden nodes.
2. Maintain a forbidden-symbol list (imports and attribute accesses).
3. Detect ``.sign()`` calls whose receiver name suggests cert-minting.
4. Block dynamic-code-loading modules (importlib.util, ctypes, pickle, …)
   with an allowlist for legitimate data-only uses (importlib.resources).
5. Walk assignment RHS to catch aliasing of forbidden names.
6. Detect wildcard imports from denied modules.
7. Flag dangerous getattr calls with signing-symbol string literals.
8. Positive control: synthesize known-bad snippets and assert the detector
   flags them (so the test can't silently become a no-op).
9. Negative control: verify that legitimate CSR/JWS/importlib.resources
   code is NOT flagged.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "acme_adcs_ra"

# ---------------------------------------------------------------------------
# Explicit allowlist for .sign() calls
# ---------------------------------------------------------------------------

# Empty by design. The RA never signs anything. If a future change genuinely
# needs to call .sign() (highly unlikely), add a (file_path, qualified_name)
# tuple here with a comment explaining the security review that approved it.
ALLOWED_SIGN_CALLS: set[tuple[str, str]] = set()

# ---------------------------------------------------------------------------
# Forbidden-symbol definitions
# ---------------------------------------------------------------------------

# Modules / module-prefixes that must never be imported or invoked in
# src/acme_adcs_ra/.  This is the single named denylist; extend here.
# NOTE: ``cryptography.x509`` and ``cryptography.hazmat.primitives.asymmetric``
# are NOT on this list — they are needed for CSR parsing and JWS verification.
# The symbol-level rules (FORBIDDEN_IMPORTS, FORBIDDEN_ATTR_NAMES) and the
# .sign() call ban catch the signing primitives within them.
FORBIDDEN_MODULE_DENYLIST: frozenset[str] = frozenset(
    {
        # Signing-capable crypto libraries
        "OpenSSL",  # pyOpenSSL signing primitives
        "asn1crypto",  # low-level crypto / key handling
        # Dynamic code loading / native FFI / serialization-of-code
        "ctypes",
        "cffi",
        "marshal",
        "pickle",
        "_pickle",
        "runpy",
        "imp",
        # Shell-out / command execution (no openssl ca, no work-arounds)
        "subprocess",
    }
)

# Allowlist for importlib submodules — only data-loading is permitted.
IMPORTLIB_ALLOWED: frozenset[str] = frozenset({"importlib.resources"})

# Dynamic execution / reflection primitives that bypass static import scans.
FORBIDDEN_DYNAMIC_EXECUTION: frozenset[str] = frozenset(
    {"__import__", "eval", "exec", "compile"}
)

# Forbidden attribute-based calls — these are ast.Call nodes whose func is an
# ast.Attribute with .attr in this set, regardless of receiver.  Catches
# importlib.util.spec_from_file_location, spec.loader.exec_module, etc.
FORBIDDEN_ATTR_CALLS: frozenset[str] = frozenset(
    {
        # importlib code-loading
        "import_module",
        "spec_from_file_location",
        "module_from_spec",
        "exec_module",
        # generic dynamic exec
        "exec",
        "eval",
        "compile",
        # native code loading
        "_load_unlocked",
    }
)

# OS shell-out / process-execution attribute names (when called on os or as
# from-os imports).
OS_SHELL_OUT_ATTRS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        # exec* family
        "execv",
        "execl",
        "execve",
        "execle",
        "execlp",
        "execvp",
        "execvpe",
        "execlpe",
        # spawn* family
        "spawnv",
        "spawnl",
        "spawnve",
        "spawnle",
        "spawnvp",
        "spawnlp",
        "spawnvpe",
        "spawnlpe",
        # fork / posix_spawn
        "fork",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
    }
)

# Attribute names on the RHS of assignments that indicate aliasing of a
# dangerous callable.  Catches: ``f = os.system``, ``f = obj.exec_module``.
ASSIGNMENT_RHS_FORBIDDEN_ATTRS: frozenset[str] = (
    OS_SHELL_OUT_ATTRS | FORBIDDEN_ATTR_CALLS
)

# Name-ids on the RHS of assignments that indicate aliasing of a forbidden
# callable.  Catches: ``f = os.system`` when os.system was imported directly,
# or ``f = exec``.
ASSIGNMENT_RHS_FORBIDDEN_NAMES: frozenset[str] = frozenset(
    {"system", "popen", "__import__", "eval", "exec", "compile"}
) | OS_SHELL_OUT_ATTRS | FORBIDDEN_ATTR_CALLS

# String literals in getattr(obj, "LiteralName") that flag a signing symbol.
GETATTR_FORBIDDEN_LITERALS: frozenset[str] = frozenset(
    {
        "CertificateBuilder",
        "CertificateSigningRequestBuilder",
        "sign",
        "import_module",
        "spec_from_file_location",
        "module_from_spec",
        "exec_module",
    }
)

FORBIDDEN_IMPORTS: dict[str, set[str]] = {
    # module -> set of names that must not be imported
    "cryptography.x509": {
        "CertificateBuilder",
        "CertificateSigningRequestBuilder",
    },
}

FORBIDDEN_ATTR_NAMES: set[str] = {
    "CertificateBuilder",
    "CertificateSigningRequestBuilder",
}

# When a .sign() call's receiver name (lowercased) contains any of these
# keywords, we flag it as a *particularly* suspicious cert-minting call.
# This is defense-in-depth behind the primary "no .sign() calls at all" rule.
_SIGN_RECEIVER_KEYWORDS: frozenset[str] = frozenset(
    {
        "builder",
        "cert",
        "certificate",
        "csr",
        "private_key",
        "privkey",
        "signing_key",
        "ca_key",
    }
)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _enclosing_qualname(tree: ast.AST, node: ast.AST) -> str:
    """Return the dotted qualified name of the callable/class enclosing *node*."""
    # Build child -> parent map
    parent: dict[ast.AST, ast.AST | None] = {tree: None}
    for parent_node in ast.walk(tree):
        for child in ast.iter_child_nodes(parent_node):
            parent[child] = parent_node

    parts: list[str] = []
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parts.append(current.name)
        elif isinstance(current, ast.ClassDef):
            parts.append(current.name)
        current = parent.get(current)
    return ".".join(reversed(parts))


def _node_is_dotted_name(node: ast.AST, name: str) -> bool:
    """Check whether *node* represents ``name`` as a dotted attribute chain."""
    parts = name.split(".")
    current: ast.AST = node
    for i, part in enumerate(reversed(parts)):
        if isinstance(current, ast.Attribute):
            if current.attr != part:
                return False
            current = current.value
        elif isinstance(current, ast.Name):
            # A Name is only valid as the leftmost component.
            return current.id == part and i == len(parts) - 1
        else:
            return False
    return isinstance(current, ast.Name) and current.id == parts[0]


def _module_matches_denylist(mod: str | None) -> str | None:
    """Return the matching denylist entry if *mod* (or a prefix) is forbidden."""
    if mod is None:
        return None
    for entry in FORBIDDEN_MODULE_DENYLIST:
        # Exact module match or importing a submodule of a banned prefix.
        if mod == entry or mod.startswith(entry + "."):
            return entry
    return None


def _is_importlib_allowed(mod: str | None) -> bool:
    """Return True if *mod* is an allowed importlib submodule."""
    if mod is None:
        return False
    # Exact match or submodule of an allowed prefix
    for allowed in IMPORTLIB_ALLOWED:
        if mod == allowed or mod.startswith(allowed + "."):
            return True
    return False


# ---------------------------------------------------------------------------
# AST scanner
# ---------------------------------------------------------------------------


def _scan_source(source: str, filename: str = "<test>") -> list[str]:
    """Return a list of human-readable violation strings found in *source*."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    for node in ast.walk(tree):
        # --- 1. Forbidden imports (fine-grained symbol list) -----------------
        if isinstance(node, ast.ImportFrom):
            # Symbol-level bans (e.g. CertificateBuilder from cryptography.x509)
            if node.module in FORBIDDEN_IMPORTS:
                for alias in node.names:
                    if alias.name in FORBIDDEN_IMPORTS[node.module]:
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden import "
                            f"'from {node.module} import {alias.name}'"
                        )

            # Module-level denylist (OpenSSL, subprocess, ctypes, pickle, …)
            if match := _module_matches_denylist(node.module):
                violations.append(
                    f"{filename}:{node.lineno}: forbidden import "
                    f"'from {node.module} import ...' (denylist entry: {match})"
                )

            # from os import <shell-out>
            if node.module == "os":
                for alias in node.names:
                    if alias.name in OS_SHELL_OUT_ATTRS:
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden import "
                            f"'from os import {alias.name}'"
                        )

            # importlib — allowlist approach
            if node.module is not None and (
                node.module == "importlib" or node.module.startswith("importlib.")
            ):
                if not _is_importlib_allowed(node.module):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import "
                        f"'from {node.module} import ...' "
                        f"(importlib submodule not in allowlist)"
                    )

            # Wildcard import from denied module or any wildcard import that
            # could pull in denied symbols.
            if node.names and any(alias.name == "*" for alias in node.names):
                # Flag wildcard imports from any denied module
                if _module_matches_denylist(node.module) or (
                    node.module in FORBIDDEN_IMPORTS
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wildcard import "
                        f"'from {node.module} import *' (denied module)"
                    )
                # Also flag wildcard from importlib (not in allowlist)
                if node.module is not None and (
                    node.module == "importlib"
                    or node.module.startswith("importlib.")
                ):
                    if not _is_importlib_allowed(node.module):
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden wildcard import "
                            f"'from {node.module} import *' (importlib not allowlisted)"
                        )
                # And wildcard from os (could pull in system, popen, exec*, etc.)
                if node.module == "os":
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wildcard import "
                        f"'from os import *' (OS shell-out risk)"
                    )

        # Also catch: import cryptography.x509 (then use .CertificateBuilder)
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod in FORBIDDEN_IMPORTS:
                    forbidden = FORBIDDEN_IMPORTS[mod]
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import "
                        f"'import {mod}' (provides {', '.join(sorted(forbidden))})"
                    )

                if match := _module_matches_denylist(mod):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import "
                        f"'import {mod}' (denylist entry: {match})"
                    )

                # importlib — allowlist approach
                if mod == "importlib" or mod.startswith("importlib."):
                    if not _is_importlib_allowed(mod):
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden import "
                            f"'import {mod}' (importlib submodule not in allowlist)"
                        )

        # --- 2. Forbidden attribute access -----------------------------------
        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTR_NAMES:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden attribute access "
                    f"'.{node.attr}'"
                )

        # --- 3. .sign() calls: primary rule is NONE are allowed --------------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "sign":
                qualname = _enclosing_qualname(tree, node)
                if (filename, qualname) not in ALLOWED_SIGN_CALLS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden .sign() call "
                        f"(enclosing callable: {qualname or '<module>'})"
                    )

                # Defense-in-depth: flag especially suspicious receivers.
                receiver = node.func.value
                receiver_name = ""
                if isinstance(receiver, ast.Name):
                    receiver_name = receiver.id.lower()
                elif isinstance(receiver, ast.Attribute):
                    receiver_name = receiver.attr.lower()

                if any(kw in receiver_name for kw in _SIGN_RECEIVER_KEYWORDS):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden .sign() call "
                        f"on '{receiver_name}' — could mint a certificate"
                    )

            # os.system(...) / os.popen(...) / os.execv(...) / os.fork() / etc.
            if node.func.attr in OS_SHELL_OUT_ATTRS:
                if _node_is_dotted_name(node.func, f"os.{node.func.attr}"):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden call "
                        f"'os.{node.func.attr}(...)' (shell/process execution)"
                    )

            # Forbidden attribute-based calls (import_module, exec_module, etc.)
            if node.func.attr in FORBIDDEN_ATTR_CALLS:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden call "
                    f"'...{node.func.attr}(...)' (dynamic code loading/execution)"
                )

        # --- 4. Dynamic execution / reflection primitives --------------------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_DYNAMIC_EXECUTION:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden call "
                    f"'{node.func.id}(...)' (dynamic execution/reflection)"
                )

        # --- 5. Dangerous getattr with string-literal signing symbol ---------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "getattr":
                # Only flag if the second argument is a string literal that
                # names a signing/dangerous symbol.  getattr(cfg, "name") is fine.
                if (
                    len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                    and node.args[1].value in GETATTR_FORBIDDEN_LITERALS
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden call "
                        f"'getattr(..., \"{node.args[1].value}\")' "
                        f"(signing/dangerous symbol access)"
                    )

        # --- 6. Assignment-RHS walk (aliasing bypass) ------------------------
        # Flatten tuple/list unpacking and starred targets so that
        # ``a, f = 1, os.system`` is caught, not just ``f = os.system``.
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            rhs_leaves: list[ast.AST] = []
            stack: list[ast.AST] = [node.value]
            while stack:
                cur = stack.pop()
                if isinstance(cur, (ast.Tuple, ast.List)):
                    stack.extend(cur.elts)
                elif isinstance(cur, ast.Starred):
                    stack.append(cur.value)
                else:
                    rhs_leaves.append(cur)
            for rhs in rhs_leaves:
                if isinstance(rhs, ast.Name):
                    if rhs.id in ASSIGNMENT_RHS_FORBIDDEN_NAMES:
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden assignment "
                            f"aliasing '{rhs.id}' (dangerous callable)"
                        )
                elif isinstance(rhs, ast.Attribute):
                    if rhs.attr in ASSIGNMENT_RHS_FORBIDDEN_ATTRS:
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden assignment "
                            f"aliasing '...{rhs.attr}' (dangerous callable)"
                        )

    return violations


def _scan_file(path: Path) -> list[str]:
    """Scan a single Python file for violations."""
    return _scan_source(path.read_text(encoding="utf-8"), filename=str(path))


def _scan_package() -> list[str]:
    """Scan all .py files under ``src/acme_adcs_ra/`` for violations."""
    violations: list[str] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        violations.extend(_scan_file(py_file))
    return violations


# ---------------------------------------------------------------------------
# Test snippets for positive / negative controls
# ---------------------------------------------------------------------------

_BAD_SNIPPETS: list[tuple[str, str]] = [
    # --- H4: symbol-level bans in cryptography.x509 ---
    (
        "import_certificate_builder",
        textwrap.dedent("""\
            from cryptography.x509 import CertificateBuilder
            b = CertificateBuilder()
        """),
    ),
    (
        "attr_access_certificate_builder",
        textwrap.dedent("""\
            import cryptography.x509
            b = cryptography.x509.CertificateBuilder()
        """),
    ),
    (
        "import_csr_builder",
        textwrap.dedent("""\
            from cryptography.x509 import CertificateSigningRequestBuilder
        """),
    ),
    # --- .sign() calls ---
    (
        "builder_sign_call",
        textwrap.dedent("""\
            builder = SomeBuilder()
            cert = builder.sign(private_key, hashes.SHA256())
        """),
    ),
    (
        "private_key_sign_call",
        textwrap.dedent("""\
            private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        """),
    ),
    (
        "key_sign_call",
        textwrap.dedent("""\
            key.sign(data, algorithm)
        """),
    ),
    (
        "issuer_sign_call",
        textwrap.dedent("""\
            issuer.sign(payload, algorithm)
        """),
    ),
    (
        "ca_key_sign_call",
        textwrap.dedent("""\
            ca_key.sign(payload, algorithm)
        """),
    ),
    # --- C1/C2: importlib code-loading ---
    (
        "import_importlib_util",
        textwrap.dedent("""\
            import importlib.util
        """),
    ),
    (
        "from_importlib_util_import",
        textwrap.dedent("""\
            from importlib.util import spec_from_file_location
        """),
    ),
    (
        "importlib_util_spec_call",
        textwrap.dedent("""\
            import importlib.util
            spec = importlib.util.spec_from_file_location("m", "/tmp/m.py")
        """),
    ),
    (
        "exec_module_call",
        textwrap.dedent("""\
            spec.loader.exec_module(mod)
        """),
    ),
    (
        "importlib_import_module_call",
        textwrap.dedent("""\
            importlib.import_module("cryptography.x509")
        """),
    ),
    # --- C3: assignment-RHS bypass ---
    (
        "assign_os_system_alias",
        textwrap.dedent("""\
            import os
            f = os.system
            f("openssl ca")
        """),
    ),
    (
        "assign_dunder_import_alias",
        textwrap.dedent("""\
            f = __import__
            f("cryptography.x509")
        """),
    ),
    (
        "assign_exec_module_alias",
        textwrap.dedent("""\
            f = loader.exec_module
            f(mod)
        """),
    ),
    (
        "assign_tuple_unpack_alias",
        textwrap.dedent("""\
            import os
            a, f = 1, os.system
            f("openssl ca")
        """),
    ),
    # --- Dynamic execution ---
    (
        "exec_string",
        textwrap.dedent("""\
            exec("from cryptography.x509 import CertificateBuilder")
        """),
    ),
    # --- H5: targeted getattr ban ---
    (
        "getattr_certificate_builder",
        textwrap.dedent("""\
            getattr(m, "CertificateBuilder")
        """),
    ),
    (
        "getattr_sign",
        textwrap.dedent("""\
            getattr(obj, "sign")
        """),
    ),
    # --- Shell-out ---
    (
        "subprocess_shell_out",
        textwrap.dedent("""\
            import subprocess
            subprocess.run(["openssl", "ca"])
        """),
    ),
    (
        "pyopenssl_import",
        textwrap.dedent("""\
            from OpenSSL import crypto
        """),
    ),
    (
        "os_system_call",
        textwrap.dedent("""\
            import os
            os.system("openssl ca")
        """),
    ),
    # --- H1: os.exec*/spawn*/fork/posix_spawn ---
    (
        "os_execv",
        textwrap.dedent("""\
            os.execv("/usr/bin/openssl", ["openssl", "ca"])
        """),
    ),
    (
        "os_fork",
        textwrap.dedent("""\
            os.fork()
        """),
    ),
    (
        "os_posix_spawn",
        textwrap.dedent("""\
            os.posix_spawn("/usr/bin/openssl", [], {})
        """),
    ),
    (
        "from_os_execv",
        textwrap.dedent("""\
            from os import execv
        """),
    ),
    # --- H2: ctypes/cffi/marshal/pickle/runpy/imp ---
    (
        "import_ctypes",
        textwrap.dedent("""\
            import ctypes
        """),
    ),
    (
        "import_cffi",
        textwrap.dedent("""\
            import cffi
        """),
    ),
    (
        "import_marshal",
        textwrap.dedent("""\
            import marshal
        """),
    ),
    (
        "import_pickle",
        textwrap.dedent("""\
            import pickle
        """),
    ),
    (
        "import_runpy",
        textwrap.dedent("""\
            import runpy
        """),
    ),
    (
        "import_imp",
        textwrap.dedent("""\
            import imp
        """),
    ),
    # --- H3: wildcard import from denied module ---
    (
        "wildcard_from_os",
        textwrap.dedent("""\
            from os import *
        """),
    ),
    (
        "wildcard_from_openssl",
        textwrap.dedent("""\
            from OpenSSL import *
        """),
    ),
    (
        "wildcard_from_subprocess",
        textwrap.dedent("""\
            from subprocess import *
        """),
    ),
]

_GOOD_SNIPPETS: list[tuple[str, str]] = [
    # --- H4 negative: legitimate crypto use ---
    (
        "verify_is_legitimate",
        textwrap.dedent("""\
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        """),
    ),
    (
        "unrelated_sign_variable",
        textwrap.dedent("""\
            sign = "something"
            result = sign + " else"
        """),
    ),
    (
        "load_pem_x509_csr_allowed",
        textwrap.dedent("""\
            from cryptography.x509 import load_pem_x509_csr
            csr = load_pem_x509_csr(pem_bytes)
        """),
    ),
    (
        "import_asymmetric_ec_allowed",
        textwrap.dedent("""\
            from cryptography.hazmat.primitives.asymmetric import ec
            key = ec.generate_private_key(ec.SECP256R1())
        """),
    ),
    (
        "public_key_verify_allowed",
        textwrap.dedent("""\
            from cryptography.hazmat.primitives.asymmetric import padding
            public_key.verify(data, sig, padding.PKCS1v15(), hash_alg)
        """),
    ),
    # --- C1/C2 negative: importlib.resources is allowed ---
    (
        "importlib_resources_allowed",
        textwrap.dedent("""\
            import importlib.resources
            p = importlib.resources.files("acme_adcs_ra.fixtures")
        """),
    ),
    (
        "from_importlib_resources_allowed",
        textwrap.dedent("""\
            from importlib.resources import files
            p = files("acme_adcs_ra.fixtures")
        """),
    ),
    # --- H5 negative: generic getattr is allowed ---
    (
        "getattr_generic_allowed",
        textwrap.dedent("""\
            getattr(cfg, "name")
        """),
    ),
    (
        "getattr_model_field_allowed",
        textwrap.dedent("""\
            value = getattr(model, field_name)
        """),
    ),
]


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


class TestNoSigningKey:
    """Cardinal architecture guardrail: no cert-minting primitive in src/."""

    def test_src_clean(self) -> None:
        """No forbidden signing primitive exists anywhere under src/acme_adcs_ra/."""
        violations = _scan_package()
        assert violations == [], (
            "Forbidden signing primitives found:\n" + "\n".join(violations)
        )

    @pytest.mark.parametrize(
        "label,snippet",
        _BAD_SNIPPETS,
        ids=[label for label, _ in _BAD_SNIPPETS],
    )
    def test_detector_catches_violations(self, label: str, snippet: str) -> None:
        """Positive control: the detector DOES flag known-bad code."""
        violations = _scan_source(snippet, filename=f"<positive-control:{label}>")
        assert violations, (
            f"Detector failed to catch known-bad snippet [{label}]:\n{snippet}"
        )

    @pytest.mark.parametrize(
        "label,snippet",
        _GOOD_SNIPPETS,
        ids=[label for label, _ in _GOOD_SNIPPETS],
    )
    def test_detector_allows_legitimate_code(self, label: str, snippet: str) -> None:
        """Negative control: legitimate code (verify, CSR parse, etc.) is NOT flagged."""
        violations = _scan_source(snippet, filename=f"<negative-control:{label}>")
        assert not violations, (
            f"Detector falsely flagged legitimate code [{label}]:\n{snippet}"
            f"\nViolations: {violations}"
        )

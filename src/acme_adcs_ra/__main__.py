"""Console entry point. Charter stage — the server is not implemented yet.

The first code lands only after the Mode A lab spike proves the enrollment leg
end to end (see plans/001-spike-and-mvp.md).
"""

from __future__ import annotations

import sys


def main() -> int:
    sys.stderr.write(
        "acme-adcs-ra is at charter stage — no server yet. "
        "See plans/001-spike-and-mvp.md (the Mode A lab spike is the feasibility gate).\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

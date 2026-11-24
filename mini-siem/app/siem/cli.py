"""Admin command line, run on the server with:

    sudo docker compose run --rm emergency breakglass <email>

Commands:
    breakglass <email>   Create a one-time emergency login code (valid 10 minutes).
    verify-audit         DATABASE-ONLY consistency check (cannot detect a rewritten chain).

For the authoritative, checkpoint-anchored verification use the worker:
    sudo docker compose exec worker python -m siem.worker --verify-once
"""
from __future__ import annotations

import sys

from . import audit, auth, db
from .config import db_dsn, env


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    emergency = argv[0] == "breakglass"
    dsn = db_dsn("SIEM_DB_EMERGENCY_USER", "db_emergency_password") if emergency else db_dsn("SIEM_DB_APP_USER", "db_app_password")
    db.init_pool(dsn, min_size=1, max_size=1)
    try:
        cmd = argv[0]
        if cmd == "breakglass" and len(argv) == 2:
            token = auth.create_breakglass_token(argv[1])
            print("One-time break-glass code (valid 10 minutes, single use):\n")
            print(f"  {token}\n")
            print(f"Open https://{env('SIEM_HOSTNAME', required=True)}/breakglass and paste the code.")
            print("This action has been logged as CRITICAL.")
            return 0
        if cmd == "verify-audit":
            ok, bad = audit.verify_chain()
            print("Database-only chain consistent (NOT anchored; run the worker's --verify-once)"
                  if ok else f"Audit chain BROKEN at id {bad}")
            return 0 if ok else 1
        print(__doc__)
        return 2
    finally:
        db.close_pool()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

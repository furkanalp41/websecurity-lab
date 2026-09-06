# SPDX-License-Identifier: MIT
"""Wait for Postgres, then create and seed the feed + users tables (idempotent).

A RANDOM per-container secret is generated here and stored as the admin user's
`recovery_code`. It never touches the image or the source tree: it lives only in
this container's Postgres data directory (a tmpfs) and can be recovered solely
through the LIMIT/OFFSET SQL injection in /feed. This is why a code lifted from
another learner's instance can never validate on yours.

The code is a 24-character alphanumeric string that is guaranteed to contain at
least one letter, so a `CAST(recovery_code AS integer)` always fails and the
error-oracle exploit is fully deterministic.
"""
import os
import secrets
import string
import time

from sqlalchemy import create_engine, text

DB_URL = os.environ["DATABASE_URL"]

_ALPHABET = string.ascii_letters + string.digits

FEED_ROWS = [
    ("Welcome to Streamline", "The activity feed you never asked for."),
    ("Deploy #128 shipped", "Rolled out the new pagination widget."),
    ("Weekly standup notes", "Backlog groomed; two tickets closed."),
    ("New teammate onboarded", "Say hi to the newest engineer."),
    ("Incident postmortem", "Root cause: someone concatenated a query."),
    ("Design review", "Discussed the feed layout refresh."),
    ("Docs updated", "Pagination docs now mention ?page and ?size."),
    ("Coffee machine fixed", "Priority one resolved."),
    ("Sprint retro", "What went well, what did not."),
    ("Roadmap sync", "Q3 themes locked in."),
    ("Bug bash results", "Twelve issues filed, three critical."),
    ("Release notes drafted", "Pending final review."),
]

# Non-admin users seeded alongside the single admin so the feed has a believable
# user base. Their recovery codes are decoys and are never checked by /solve.
DECOY_USERS = [
    ("mara", "member"),
    ("devon", "member"),
    ("priya", "editor"),
    ("sam", "viewer"),
]


def _new_recovery_code() -> str:
    """24 alphanumeric chars, guaranteed to include a letter (so text->int fails)."""
    while True:
        code = "".join(secrets.choice(_ALPHABET) for _ in range(24))
        if any(c.isalpha() for c in code):
            return code


def main() -> None:
    engine = create_engine(DB_URL, pool_pre_ping=True)
    for attempt in range(60):
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS feed "
                        "(id serial PRIMARY KEY, title text NOT NULL, body text NOT NULL)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS users "
                        "(id serial PRIMARY KEY, username text NOT NULL, "
                        "role text NOT NULL, recovery_code text NOT NULL)"
                    )
                )

                feed_count = conn.execute(text("SELECT count(*) FROM feed")).scalar_one()
                if feed_count == 0:
                    conn.execute(
                        text("INSERT INTO feed (title, body) VALUES (:t, :b)"),
                        [{"t": t, "b": b} for (t, b) in FEED_ROWS],
                    )

                users_count = conn.execute(text("SELECT count(*) FROM users")).scalar_one()
                if users_count == 0:
                    conn.execute(
                        text(
                            "INSERT INTO users (username, role, recovery_code) "
                            "VALUES (:u, :r, :c)"
                        ),
                        {"u": "admin", "r": "admin", "c": _new_recovery_code()},
                    )
                    conn.execute(
                        text(
                            "INSERT INTO users (username, role, recovery_code) "
                            "VALUES (:u, :r, :c)"
                        ),
                        [
                            {"u": u, "r": r, "c": _new_recovery_code()}
                            for (u, r) in DECOY_USERS
                        ],
                    )
            print("[seed] feed ready", flush=True)
            return
        except Exception:  # noqa: BLE001 -- transient startup errors while Postgres boots
            if attempt == 0:
                print("[seed] waiting for database...", flush=True)
            time.sleep(1)
    raise SystemExit("[seed] database never became ready")


if __name__ == "__main__":
    main()

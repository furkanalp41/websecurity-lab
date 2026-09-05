# SPDX-License-Identifier: MIT
"""Wait for Postgres, then create and seed the posts table (idempotent)."""
import os
import time

from sqlalchemy import create_engine, text

DB_URL = os.environ["DATABASE_URL"]


def main() -> None:
    engine = create_engine(DB_URL, pool_pre_ping=True)
    for attempt in range(60):
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS posts "
                        "(id serial PRIMARY KEY, title text, author text, published date)"
                    )
                )
                count = conn.execute(text("SELECT count(*) FROM posts")).scalar_one()
                if count == 0:
                    conn.execute(
                        text(
                            "INSERT INTO posts (title, author, published) VALUES "
                            "('Welcome to the archive', 'admin', DATE '2024-01-01'), "
                            "('SQL for beginners', 'editor', DATE '2024-02-01'), "
                            "('Old news', 'guest', DATE '2024-03-01')"
                        )
                    )
            print("[seed] posts ready")
            return
        except Exception as exc:  # noqa: BLE001
            if attempt == 0:
                print("[seed] waiting for database...")
            time.sleep(1)
    raise SystemExit("[seed] database never became ready")


if __name__ == "__main__":
    main()

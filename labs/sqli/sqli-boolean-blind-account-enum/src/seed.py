# SPDX-License-Identifier: MIT
"""Wait for Postgres, then create and seed the users table (idempotent).

The admin row carries a fixed, realistic bcrypt-style password hash. The first 32
characters of that hash are the secret the lab asks the learner to reconstruct with
the boolean-blind oracle. The hash is NOT the flag and never leaves the database in
one piece — it must be extracted one character at a time through /forgot.
"""
import asyncio
import os

import asyncpg

DB_URL = os.environ["DATABASE_URL"]

# Fixed 60-char bcrypt-shaped hash: "$2b$12$" + 22-char salt + 31-char digest.
# Every character is drawn from the bcrypt alphabet ($ . / A-Z a-z 0-9), so the
# blind character-search in the exploit stays within a known, ordered charset.
ADMIN_HASH = "$2b$12$R9fK2mQ7pL4sX1vT8wZ0.cdEuHiNjOaPeRtYqWsFgDhBnMvCxZlKm"

# Decoy accounts so username enumeration through the oracle is meaningful. Their
# hashes are never the target.
EDITOR_HASH = "$2b$12$T3aB6cD9eF1gH4iJ7kL0.uMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQr"
GUEST_HASH = "$2b$12$Zz8Yy7Xx6Ww5Vv4Uu3.tSsRrQqPpOoNnMmLlKkJjIiHhGgFfEeDdCc"


async def seed() -> None:
    for attempt in range(60):
        try:
            conn = await asyncpg.connect(DB_URL)
        except Exception:  # noqa: BLE001 -- DB may still be starting
            if attempt == 0:
                print("[seed] waiting for database...")
            await asyncio.sleep(1)
            continue
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id serial PRIMARY KEY, "
                "username text UNIQUE NOT NULL, "
                "password_hash text NOT NULL, "
                "email text"
                ")"
            )
            count = await conn.fetchval("SELECT count(*) FROM users")
            if count == 0:
                await conn.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES "
                    "($1, $2, $3), ($4, $5, $6), ($7, $8, $9)",
                    "admin",
                    ADMIN_HASH,
                    "admin@lab.internal",
                    "editor",
                    EDITOR_HASH,
                    "editor@lab.internal",
                    "guest",
                    GUEST_HASH,
                    "guest@lab.internal",
                )
            print("[seed] users ready")
            return
        finally:
            await conn.close()
    raise SystemExit("[seed] database never became ready")


if __name__ == "__main__":
    asyncio.run(seed())

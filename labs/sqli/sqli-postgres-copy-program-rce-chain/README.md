# Postgres SQLi to COPY FROM PROGRAM Command Execution

> Track: `sqli` · Difficulty: **elite** · ~60 min · Free hints.

## Scenario

`Acme Metrics` is a small internal metrics microservice (FastAPI + asyncpg) backed
by PostgreSQL 16. Like a surprising number of Docker'd stacks, the app connects to
the database with the **`POSTGRES_USER` role — which is a superuser**. That single
mis-configuration turns an ordinary SQL injection into remote command execution:
a Postgres superuser can run `COPY ... FROM PROGRAM '<shell command>'`, executing
the command inside the database container.

Two endpoints build SQL by string concatenation:

```
GET  /metrics?category=<c>            -> returns rows (a VISIBLE injection)
POST /metrics/ingest {source,...}     -> fire-and-forget (no rows returned)
```

They are not the same kind of sink, and the difference matters (see the hints).

## Objective

Execute a command inside the Postgres container via `COPY ... FROM PROGRAM`, read
the flag that has been planted on the **database container's filesystem** at
`/labflag/flag.txt`, and submit it:

```
POST /solve    {"flag":"FLAG{...}"}   ->   {"solved":true,"flag":"...","completion":"<jwt>"}
```

The flag is written to the filesystem, **not** into any table — a plain SQL
`SELECT` will never find it. Only command execution recovers it. The flag
(`FLAG{<64 hex>}`) is unique to your container.

## Getting Started

1. Explore `GET /metrics?category=web`. It returns rows and reflects SQL errors —
   a classic visible injection. Confirm you can UNION extra columns out of it.
2. Now try to run stacked statements (`; CREATE TABLE ...`) through it. You will
   find the visible endpoint refuses multiple commands. Why? And which endpoint
   does **not** refuse them?
3. Once you can run stacked DDL, recall what a Postgres **superuser** can do that
   a normal role cannot. Get a command to run, capture its output, and read it
   back through the visible endpoint. Reveal the hints in order if you get stuck.

## A note on safety

This lab deliberately hands you command execution, but it stays **`risk: low`**.
`COPY ... FROM PROGRAM` runs your command as an unprivileged, non-root user and
needs no added Linux capabilities, so the container keeps `cap_drop: ALL`, a
read-only root filesystem, `no-new-privileges`, and process/memory caps. The
Postgres container also sits on a **no-egress network** — a shell you obtain
cannot reach the internet or pivot. Everything you can do is contained.

**CVE analog family.** Postgres `COPY FROM/TO PROGRAM` abuse by an over-privileged
application role is a recurring real-world finding (e.g. GitLab HackerOne
#827052). **CWE-89 → CWE-78 (OS command injection).** No vendor code is reproduced.

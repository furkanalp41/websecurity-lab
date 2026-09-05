# WebSecurity Lab

> A self-hosted, Docker-first, gamified web-security CTF platform. Clone it, run
> `./labctl serve`, and learn to hack the web — and to write the report — one lab at a time.

**541 labs across 20 tracks.** Every lab spins up in its own isolated Docker container on
your machine. No VPS, no account, no cost. A Matrix-themed hub turns the whole thing into a
game: a rabbit chases a golden carrot up a skill map, and the final track — **Report Studio** —
trains you to file a bug-bounty report that survives an adversarial triager.

## Quickstart

```bash
git clone https://github.com/furkanalp41/websecurity-lab.git
cd websecurity-lab
./scripts/bootstrap.sh     # preflight + build labctl + hub + generate the catalog
./labctl serve             # hub on http://localhost:5173, daemon on 127.0.0.1:5174
```

Prerequisites: Docker Engine 25+ (Compose v2), Node 24 (`.nvmrc`), Git. See `docs/` for the
full architecture, security model, and authoring guide.

## Status

Early bootstrap (`arch-000`). One reference lab is implemented and CI-green; the 541-lab
catalog is authored track by track under a two-session build/review protocol
(see `docs/two-session-protocol.md`). Contributions follow the per-lab quality bar in `CLAUDE.md`.

## Principles

Free labs, free hints, free solutions, forever. No streaks, no dark patterns, no telemetry by
default. Everything runs locally and offline-verifiable. The goal is to make you genuinely
capable in the real world — not to make you feel like you are.

## License

MIT © 2026 furkanalp41. See `LICENSE` and `NOTICES.md`.

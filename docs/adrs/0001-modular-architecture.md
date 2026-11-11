# ADR 0001: Modular architecture, almost everything can be turned off

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Scarf runs on small machines (a Raspberry Pi next to the rest of MangoStack) and in very different setups: some users want a search UI, others only point Sonarr/Radarr/FlexGet at the Torznab API. Every feature that is always on costs memory, disk writes, background requests to trackers and attack surface, even for users who never use it.

## Decision

The core of Scarf is the Torznab API in front of the indexer definitions. Everything else is an optional module that can be switched off with an environment variable, and nothing in the core depends on it.

| Module | Switch | When off |
|---|---|---|
| Web UI and its JSON API (login, search, logs, indexer settings) | `WEB_UI=false` | The routes are not registered; `UI_PASSWORD` is not required. |
| Result cache (SQLite) | `CACHE_ENABLED=false` | No database is opened; every request goes to the tracker. |
| Scheduled pre-fetch of the latest releases | `ENABLE_CRONJOBS=false` | No background requests. Also off whenever the cache is off, since it only fills the cache. |
| Cloudflare solver (FlareSolverr, or Parasol as a drop-in) | `FLARESOLVERR_URL` unset | Indexers that need it fail; the rest are unaffected. Opt-in per indexer with "Use FlareSolverr". |
| Each indexer | `enabled` in its definition, or the web UI | The definition is loaded but never queried or scheduled. |

Rules for new features:

- A new module gets its own switch, and its default must keep a fresh install useful without extra services.
- A module that is off must not open files, start goroutines or make network requests.
- Dependencies between modules are explicit (cron needs the cache) and logged at startup.
- The single static binary stays the deployment unit; optional external services (FlareSolverr/Parasol) are reached over HTTP, never linked in.

## Consequences

- Minimal installs (API only, no cache, no UI) stay small: one binary, no database, no background traffic.
- More configuration combinations to test. Startup logs the effective state of each module, so a misconfiguration is visible.
- Some features degrade instead of failing: without the cache, `latest` feeds hit the trackers on every request.

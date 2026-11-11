# ADR 0002: Adopt the Cardigann definition format

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Scarf has its own YAML format for indexer definitions. Every tracker has to be written and maintained by hand, and sites change often. Jackett and Prowlarr share the Cardigann format, with more than 500 definitions maintained by an active community ([Prowlarr/Indexers](https://github.com/Prowlarr/Indexers)). Scarf's format covers ~26 indexers and lacks features those definitions use: login flows, the download block, per-path inputs, keyword filters and a large filter library.

Constraints:

- The upstream definitions are GPL-licensed; Scarf is MIT.
- A search is as slow as the slowest enabled indexer, so many indexers is not a goal in itself.
- Scarf must stay small enough for a Raspberry Pi (see [ADR 0001](0001-modular-architecture.md)).

## Decision

Scarf adopts Cardigann as its definition format and retires its own, in the phases described in `docs/cardigann_migration_plan.md`:

1. Prototype: load public HTML definitions next to Scarf's own.
2. Coverage: JSON/XML responses, login, the download block, link fallback, remaining filters.
3. Upstream sync: download definitions from Prowlarr on demand.
4. Convert the remaining Scarf definitions and remove the old format.

Details of the decision:

- **Definitions are downloaded, not bundled.** Scarf never ships GPL files; the user fetches them from upstream (manually now, from the UI in phase 3). Only enabled definitions are parsed into memory.
- **Run the format natively in Go.** No Jackett or Prowlarr process and no .NET runtime. Where C# semantics leak into definitions (regex dialect, string escapes, date formats), Scarf emulates them (`regexp2`, template rewriting, .NET date layouts).
- **Reject, don't half-run.** A definition that needs a feature Scarf does not implement yet is refused at load time with a log line naming the feature.
- **Recommend 10–12 enabled indexers at most.** The UI will warn above that.
- **Scarf-only state stays out of upstream files.** `enabled` and user settings move out of the definition files before phase 3, so an upstream update never overwrites them.

## Consequences

- Access to hundreds of maintained definitions instead of writing each one; site changes are fixed upstream.
- The engine must track the Cardigann schema (Prowlarr's `v11`) and its quirks; the version is pinned and checked on download.
- The template, regex and filter emulation is a compatibility surface: it is tested against the real upstream definitions (`TestUpstreamDefinitions`), not only fixtures.
- About 2–3 MB more memory than the same indexers in Scarf's format (measured in phase 1).
- Users must fetch definitions themselves, an extra step compared with bundled files, made easier by the phase 3 UI.
- Scarf's own format is deprecated and removed in phase 4; existing definitions without an upstream equivalent are converted.

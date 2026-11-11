# Plan: adopt Cardigann as Scarf's definition format

Status: proposal. No code changes yet.

## Decision

Scarf will load Cardigann definitions (the YAML format used by Jackett and Prowlarr) and, after a transition, drop its own definition format. Keeping two formats long term would mean maintaining two engines, and Scarf's format is the less capable one.

## Why

- **Community-maintained definitions.** Scarf ships 26 hand-written definitions. Jackett and Prowlarr have hundreds, fixed by their communities when a site changes.
- **Fits Go.** Cardigann templates (`{{ .Keywords }}`, `{{ if }}`, `{{ range }}`) are close to Go's `text/template` and can run on it with a few extra functions. The original Cardigann was a Go project before Jackett adopted the format.
- **Small rewrite surface.** The indexer engine is about 1,800 lines (`indexer/definition.go`, `indexer/manager.go`). HTTP, caching, rate limiting, Torznab output and FlareSolverr support are reused unchanged.

## Constraints

1. **Licensing.** Jackett definitions are GPL-2.0 and Prowlarr definitions GPL-3.0; Scarf is MIT. Scarf will **not** bundle them. It downloads them at runtime from an upstream repository, the same way Prowlarr does. This also solves keeping them up to date.
2. **Memory.** Low memory use is Scarf's main selling point. Only enabled definitions are loaded; templates and selectors are compiled once at load time. Memory is measured on the Pi before each phase is accepted.
3. **Few indexers per instance.** The recommended setup is 10–12 enabled indexers at most: every search waits for the slowest indexer, so more indexers mean slower queries. The UI should say so, and per-indexer timeouts must stop one slow site from blocking the rest.

## Gaps to close

What Cardigann supports and Scarf's engine does not, today:

| Area | Cardigann | Scarf today |
|---|---|---|
| Templates | `text/template` style, `if`/`range`/`else`, `.Keywords`, `.Query.*`, `.Config.*`, `.Categories` | `.Query`, `.Season`, `.Episode`, `.IMDBID`; `download_selector` not templated |
| Filters | ~40 (`replace`, `re_replace`, `regexp`, `dateparse`, `timeago`, `fuzzytime`, `querystring`, `append`, `prepend`, `trim`, `split`, `urldecode`, `tolower`…) | only `remove` |
| Search paths | several `paths`, each with its own categories, `inputs`, `method`, `response.type` | one URL list |
| Keywords | `keywordsfilters` | none |
| Fields | `text:` constants, `optional: true`, `default:`, `case:` blocks, `attribute:` | selector + `@attr` |
| Rows | `rows.after`, `dateheaders`, `filters` on rows | `RowsSelector` |
| Responses | HTML and JSON (`attribute`, nested rows) | HTML and basic JSON |
| Links | several `links` with fallback | `links[0]` only |
| Login | `form`, `post`, `get`, `cookie`, `oneurl`; `error` and `test` blocks; captcha detection | POST + "body contains" check |
| Download | `download` block with `selectors`, `before`, `infohash` | `download_selector`, magnet preferred |
| Settings | `settings` with `text`, `password`, `checkbox`, `select`, `info` | `UserSetting` (subset) |

Scarf features with no Cardigann equivalent — `schedule`, `rate_limit`, `health_check`, the FlareSolverr toggle — become optional extension keys (for example under `x-scarf:`), which Jackett ignores, so a definition stays usable in both.

## Phases

### Phase 1 — prototype

- New package (e.g. `indexer/cardigann`) with the Cardigann schema and a loader that maps into Scarf's internal search model.
- Template engine on `text/template` with Cardigann's variables and helper functions.
- The 10–15 most used filters.
- HTML search for public indexers, single path, single link.
- **Acceptance:** load the upstream Jackett/Prowlarr versions of Scarf's current indexers unmodified and compare results against Scarf's own definitions on the same queries. Measure memory.

### Phase 2 — coverage

- JSON responses, `rows.after`, `dateheaders`, `case` fields, optional fields.
- All login modes, with `error` and `test` blocks.
- The `download` block.
- Multiple `paths`, `inputs`, `keywordsfilters`, multiple `links` with fallback.
- Remaining filters.
- **Acceptance:** private-tracker login works for at least one form-based and one cookie-based site.

### Phase 3 — upstream sync

- Configurable upstream source (Prowlarr's `Indexers` repo by default), pinned to a schema version.
- Download the index on demand from the UI, cache it on disk, enable indexers one at a time; only enabled definitions are parsed into memory.
- Update check (manual button, optional cron job).
- UI warning when more than ~12 indexers are enabled.
- Settings UI generated from each definition's `settings` block.

### Phase 4 — retire Scarf's format

- Convert the definitions that have no upstream equivalent to Cardigann with `x-scarf:` extensions.
- Mark Scarf's own format deprecated for one release: it still loads, with a log warning.
- Remove the old loader, `indexer/definition.go`'s old schema and `tools/convert.py`.
- Update `docs/indexer_definition_structure.md` and the README.

## Migration for users

- Existing per-indexer settings (credentials, enabled flag) are migrated by indexer key; where the key differs from upstream, a mapping table handles it.
- The deprecation release logs which definitions still use the old format.

## Open questions

- Upstream source: Prowlarr (GPL-3.0, more active, `v`-numbered schema directories) or Jackett (GPL-2.0)? Prowlarr looks like the better default.
- Which Cardigann schema version to target first.
- Whether to support Prowlarr's `.Query.*` additions only or also older Jackett-only variables.

# Cardigann definitions (prototype)

Scarf can load indexer definitions written in the Cardigann format used by Jackett and Prowlarr. This is phase 1 of the plan in `docs/cardigann_migration_plan.md`.

## Usage

Drop a Cardigann `.yml` file into the definitions directory. Scarf tells the formats apart by their top-level keys: Cardigann has `id` and `links`, Scarf's own format has `key`. The file name must match the definition's `id` (as upstream files already do), and it cannot share a name with a Scarf definition.

Add `enabled: true` at the end of the file, or enable the indexer from the web UI. Scarf writes the `enabled` flag and changed settings back into the file; Jackett and Prowlarr ignore those keys.

Every Cardigann indexer gets a "Use FlareSolverr" setting, which routes its requests through `FLARESOLVERR_URL`.

Scarf does not ship upstream definitions: they are GPL-licensed and Scarf is MIT. Fetch them from [Prowlarr/Indexers](https://github.com/Prowlarr/Indexers) (`definitions/v11/`).

## What works

- HTML search with several `paths`, path `categories`, `inputs` (including `$raw`), `inheritinputs`, GET and POST, headers.
- Templates: Go `text/template` with Cardigann's variables (`.Keywords`, `.Query.*`, `.Config.*`, `.Categories`, `.Result.*`), `re_replace` and `join`. Dashed names such as `.Config.filter-id` work. String literals keep backslashes as in C#.
- .NET-style regular expressions (lookbehind, `\p{IsCyrillic}` and other named blocks).
- Filters: `replace`, `re_replace`, `regexp`, `append`, `prepend`, `trim`, `tolower`, `toupper`, `split`, `urldecode`, `urlencode`, `querystring`, `dateparse`, `timeago`, `fuzzytime`, `diacritics`. Rows filter: `andmatch`.
- Fields in document order, `text`, `optional`, `default`, `case`, `attribute`, `remove`; `rows.after`; `keywordsfilters`.
- Legacy page encodings (`encoding: windows-1251`), for both responses and request parameters.
- Category mappings, rate limit (`requestDelay`), user settings in the web UI.

## Not yet (phase 2)

Definitions that need any of these are rejected at load time with a log line naming what is missing, so an indexer never half-works:

- `login` (private trackers)
- `download` block (download link fetched from the details page)
- JSON and XML responses
- `rows.dateheaders`, row filters other than `andmatch`
- Filters not listed above

Also pending: multiple `links` with fallback (the first link, or the `sitelink` setting, is used), and returning nothing for Torznab categories the indexer does not map.

## Test results

Run against the Prowlarr `v11` definitions of the indexers Scarf already has (November 2026). 19 of Scarf's 26 indexers exist upstream under the same name.

- **Load:** 9 of 19 load. The other 10 need JSON/XML responses (6), the download block (3) or login (1).
- **Parity:** nyaasi, acgrip, shanaproject and torrentkitty return the same number of results through the Prowlarr definitions as through Scarf's own (75, 30, 50 and 20 for "one piece").
- **TV search:** the Prowlarr definitions pass season and episode to the site; for nyaasi, "one piece" S23E04 returns 3 matching releases where Scarf's own definition returns the 75 unfiltered results.
- **noname-club:** works, including windows-1251 requests.
- **Cloudflare:** eztv, tokyotosho, uindex and btdirectory answer 403 with a Cloudflare challenge. Through [Parasol](https://github.com/pixelotes/parasol) with "Use FlareSolverr" on, all four work. eztv (1) and uindex (100) match Scarf's own definitions. tokyotosho returns 3 instead of 13 because Prowlarr's `andmatch` drops unrelated rows. btdirectory returns 15 instead of 20 because Scarf's definition repeats the same 15 infohashes.
- **Memory:** about 2–3 MB more RSS than the same indexers in Scarf's format (macOS, 4 indexers, cache off, after 12 searches: 32.6 MB vs 29.7 MB). Not measured on the Pi.

To repeat the tests:

```bash
CARDIGANN_DEFS=/path/to/definitions go test ./indexer/cardigann -run Upstream -v                          # load only
CARDIGANN_DEFS=/path/to/definitions CARDIGANN_LIVE=1 CARDIGANN_QUERY="one piece" go test ./indexer/cardigann -run Upstream -v
```

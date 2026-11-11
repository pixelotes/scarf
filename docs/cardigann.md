# Cardigann definitions

Scarf can load indexer definitions written in the Cardigann format used by Jackett and Prowlarr. Phases 1 to 3 of the plan in `docs/cardigann_migration_plan.md` are done; see also [ADR 0002](adrs/0002-adopt-cardigann-format.md).

## Usage

### From the Prowlarr catalog

In the web UI, open **Indexers** and press **Update catalog**. Scarf downloads the [Prowlarr/Indexers](https://github.com/Prowlarr/Indexers) tarball (one request, a few MB), keeps the `definitions/v11/*.yml` files in `DATA_DIR/upstream` and lists them. Filter the list and press **Add** to enable an indexer; private trackers open their settings right away. Only enabled indexers are parsed and kept in memory. Disabling one from the catalog unloads it.

**Update catalog** replaces the downloaded definitions with the current upstream ones; enabled indexers keep their settings. No previous version is kept. Nothing is downloaded automatically. `UPSTREAM_SYNC=false` turns the catalog off.

Scarf warns when more than 12 indexers are enabled: a search waits for the slowest indexer.

### By hand

Drop a Cardigann `.yml` file into the definitions directory. Scarf tells the formats apart by their top-level keys: Cardigann has `id` and `links`, Scarf's own format has `key`. The file name must match the definition's `id` (as upstream files already do). A file in the definitions directory takes precedence over the catalog definition with the same `id`.

### Enabled flags and settings

Enabled flags and settings, for both formats, are stored in `indexers.yml` in `DATA_DIR` (`STATE_FILE`), never in the definition files. The file holds credentials and is written with mode 0600. An `enabled` key or setting default written into a definition file by an older Scarf version is still read until the indexer is changed from the web UI. The web UI never receives saved passwords: it shows them as saved, and leaving the field empty keeps them.

Every Cardigann indexer gets a "Use FlareSolverr" setting, which routes its requests through `FLARESOLVERR_URL`.

Credentials for private trackers (`username`, `password`, `cookie`, `apikey`...) are set in the web UI or with environment variables named `<ID>_<SETTING>`, for example `HDSPACE_USERNAME`.

### Download proxy

Results from private trackers and from indexers with a `download` block do not carry the tracker's link. Their Torznab link points to Scarf instead (`/torznab/<id>/download?link=...&sig=...`). Scarf checks the signature, follows the `download` block with the indexer's session and streams the `.torrent`, or redirects to the magnet link. The links are signed with `JWT_SECRET`. If that variable is not set, a random secret is generated at startup, and links handed out before a restart stop working. Behind a reverse proxy, Scarf builds the links from `X-Forwarded-Proto` and `X-Forwarded-Host`.

Scarf does not ship upstream definitions: they are GPL-licensed and Scarf is MIT. The catalog downloads them at the user's request.

## What works

- HTML, JSON and XML responses. JSON rows with `attribute`, `multiple`, parent fields (`..name`), `count`, `noResultsMessage` and `:has(...)` / `:not(...)` conditions.
- Several `paths`, path `categories`, `inputs` (including `$raw`), `inheritinputs`, GET and POST, headers, templated methods.
- Login: `post`, `get`, `form` (hidden inputs, `selectorinputs`, `submitpath`) and `cookie`, with `error` and `test` blocks. When a search lands on the login page, Scarf signs in again and retries once.
- The `download` block: `before` requests, `selectors` in order, `infohash`, `.DownloadUri.*`.
- Multiple `links`: when a search fails on one link, the next is tried and remembered. The `sitelink` setting, when set, is used alone.
- Templates: Go `text/template` with Cardigann's variables (`.Keywords`, `.Query.*`, `.Config.*`, `.Categories`, `.Result.*`, `.DownloadUri.*`), `re_replace` and `join`. Dashed names such as `.Config.filter-id` work. Unknown `.Query` variables render empty. String literals keep backslashes as in C#.
- .NET-style regular expressions (lookbehind, `\p{IsCyrillic}` and other named blocks).
- Filters: `replace`, `re_replace`, `regexp`, `append`, `prepend`, `trim`, `tolower`, `toupper`, `split`, `urldecode`, `urlencode`, `querystring`, `dateparse`, `timeparse`, `timeago`, `fuzzytime`, `diacritics`, `validate`, `validfilename`, `htmldecode`, `htmlencode`, `jsonjoinarray`. Rows filter: `andmatch`.
- Fields in document order, `text`, `optional`, `default`, `case`, `attribute`, `remove`; `rows.after`, `rows.dateheaders`; `keywordsfilters`.
- Legacy page encodings (`encoding: windows-1251`), for both responses and request parameters.
- Category mappings, including several and parent Torznab categories in `cat`. An indexer that maps none of the requested categories is skipped. Also: rate limit (`requestDelay`) and user settings in the web UI.

## Not supported

Definitions that need any of these are rejected at load time with a log line naming what is missing, so an indexer never half-works:

- Login with a `captcha` (43 upstream definitions).
- Row filters other than `andmatch`.

## Test results

Run against the Prowlarr `v11` definitions (November 2026).

- **Load:** 538 of 581 definitions load; the other 43 need a captcha. Of the 19 that match indexers Scarf already has, all 19 load (9 in phase 1).
- **Parity:** nyaasi, acgrip, shanaproject and torrentkitty return the same number of results through the Prowlarr definitions as through Scarf's own (75, 30, 50 and 20 for "one piece").
- **JSON/XML (live):** yts, bangumi-moe, anibt, nekobt, thepiratebay, internetarchive and showrss return results.
- **TV search:** the Prowlarr definitions pass season and episode to the site; for nyaasi, "one piece" S23E04 returns 3 matching releases where Scarf's own definition returns the 75 unfiltered results.
- **noname-club:** works, including windows-1251 requests.
- **Link fallback:** tokyotosho's first link answers 403 (Cloudflare); a later mirror works without FlareSolverr.
- **Cloudflare:** eztv, uindex and btdirectory answer 403 with a Cloudflare challenge on every link. Through [Parasol](https://github.com/pixelotes/parasol) with "Use FlareSolverr" on, they work (phase 1 results: eztv 1 and uindex 100, the same as Scarf's own definitions; btdirectory 15 instead of 20, because Scarf's definition repeats the same 15 infohashes).
- **Login and download proxy:** covered by unit tests against a fake tracker (form login with CSRF token, wrong password, cookie login, expired session, `before` + `selectors`). Tested end to end against a local fake private tracker: Torznab search, then a proxied download through the `download` block; a tampered signature gets 403. Not yet tested against a real private tracker.
- **Memory:** about 2–3 MB more RSS than the same indexers in Scarf's format (phase 1, macOS, 4 indexers, cache off, after 12 searches: 32.6 MB vs 29.7 MB). Not measured on the Pi.

To repeat the tests:

```bash
CARDIGANN_DEFS=/path/to/definitions go test ./indexer/cardigann -run Upstream -v                          # load only
CARDIGANN_DEFS=/path/to/definitions CARDIGANN_LIVE=1 CARDIGANN_QUERY="one piece" go test ./indexer/cardigann -run Upstream -v
```

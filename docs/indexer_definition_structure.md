# 🧩 Indexer Definition File Structure

The power of Scarf lies in its YAML-based indexer definitions. Each `.yml` file in the `definitions` directory tells Scarf how to interact with a specific tracker. This guide breaks down the structure of these files.

---

### Top-Level Properties

These properties define the basic information and behavior of the indexer.

| Key           | Type     | Required | Description                                                               |
| :------------ | :------- | :------- | :------------------------------------------------------------------------ |
| `key`         | `string` | Yes      | A unique, lowercase identifier for the indexer (e.g., `bitsearch`).       |
| `name`        | `string` | Yes      | The human-readable name of the tracker (e.g., "BitSearch").               |
| `description` | `string` | Yes      | A brief description of the tracker.                                       |
| `type`        | `string` | Yes      | The type of tracker. Can be `public`, `private`, or `semiprivate`.        |
| `enabled`     | `bool`   | Yes      | Whether the indexer is enabled by default (`true` or `false`).            |
| `language`    | `string` | Yes      | The primary language of the tracker (e.g., `en-US`, `es-ES`).               |
| `schedule`    | `string` | No       | A cron expression for pre-fetching latest releases (e.g., `@hourly`).     |
| `rate_limit`  | `string` | No       | The minimum time to wait between requests (e.g., `2s`, `500ms`).          |

---

### `search` Block

This block contains all the logic for how to perform a search.

| Key       | Type     | Required | Description                                                               |
| :-------- | :------- | :------- | :------------------------------------------------------------------------ |
| `type`    | `string` | Yes      | The type of search to perform. Can be `html` or `json`.                   |
| `urls`    | `list`   | Yes      | A list of base URLs for searching. Scarf will try them in order.          |
| `params`  | `map`    | No       | A map of query parameters to add to GET requests.                         |
| `headers` | `map`    | No       | A map of custom HTTP headers to send with the request.                    |
| `modes`   | `map`    | No       | Defines supported search modes like `tv-search` and `movie-search`.       |
| `results` | `map`    | Yes      | Contains the logic for parsing the results from the response.             |

### `results` Block

This nested block within `search` defines how to extract data from the HTML or JSON response.

| Key                 | Type     | Description                                                               |
| :------------------ | :------- | :------------------------------------------------------------------------ |
| `rows_selector`     | `string` | **HTML Only**: A CSS selector to identify each result row in the HTML.    |
| `path`              | `string` | **JSON Only**: A gjson path to the array of results in the JSON.          |
| `download_selector` | `string` | A CSS selector used on a details page to find the final download/magnet link. |
| `fields`            | `map`    | A map defining how to extract each piece of data for a result.            |

### `fields` Block

This block contains CSS or gjson selectors for each piece of information. For HTML, you can append `@attr` to extract an attribute's value (e.g., `a@href`).

-   `title`
-   `download_url`
-   `details_url` (If present, Scarf will visit this URL to find the `download_url`)
-   `size`
-   `seeders`
-   `leechers`
-   `publish_date`

---

### Example: `bitsearch.yml`

```yaml
key: "bitsearch"
name: "BitSearch"
description: "BitSearch is a Public torrent meta-search engine"
type: "public"
enabled: true
language: "en-US"
schedule: "@every 1h"
rate_limit: 2s # Wait 2 seconds between searches

search:
  type: "html"
  urls:
    - "[https://bitsearch.to/search?q=](https://bitsearch.to/search?q=){{.Query}}&sort=seeders&order=desc"
  results:
    rows_selector: "div.space-y-4 > div.bg-white > div.items-start"
    # This selector is for the second step: finding the magnet link on the details page.
    download_selector: "a[href^='magnet:?xt']@href"
    fields:
      title:
        selector: "h3 > a"
      # This tells the app where to go for the second step.
      details_url:
        selector: "h3 > a@href"
      size:
        selector: "div.flex.flex-wrap > span:nth-child(2)  i.fas.fa-download ~ span"
      seeders:
        selector: " div.flex.flex-wrap  span.text-green-600 > span:nth-child(2)"
      leechers:
        selector: " div.flex.flex-wrap  span.text-red-600 > span:nth-child(2)"
      publish_date:
        selector: "div.space-y-2 > span:nth-child(3)"
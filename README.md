# 🧣 Scarf: Your Personal Meta-Indexer

Scarf is a versatile, self-hosted meta-indexer that acts as a bridge between your favorite media automation tools (like Sonarr, Radarr, Lidarr) and various public torrent trackers. 
It provides a clean, unified Torznab API, allowing you to search across multiple sites simultaneously.

## ✨ Features

* **Ultra-lightweight**: It's a single Go binary that usually takes around 10-15 MB or RAM and virtually no CPU.
* **Torznab API**: Provides a standard Torznab feed compatible with most media automation software.
* **Multi-Indexer Support**: Search across multiple public torrent sites at once.
* **Extensible Definition Files**: Easily add or modify indexers using simple YAML configuration files.
* **Web UI**: A simple web interface for manual searching, status checks, and log viewing.
* **Scheduled Caching**: Pre-fetches the latest releases from indexers to provide fast results.
* **Dockerized**: Easy to deploy and manage using the provided `Dockerfile`.
* **Secure**: Protect the web UI with a password and secure the Torznab API with a unique key.

---

## 🚀 Getting Started

The easiest way to get Scarf up and running is with Docker.

### Prerequisites

* [Docker](https://docs.docker.com/get-docker/) installed on your system.

### Build and Run

1.  **Clone the repository (or download the files):**
    ```bash
    git clone [https://github.com/pixelotes/scarf.git](https://github.com/pixelotes/scarf.git)
    cd scarf
    ```

2.  **Build the Docker image:**
    ```bash
    docker build -t scarf .
    ```

3.  **Run the container:**
    ```bash
    docker run -d \
      -p 8080:8080 \
      -v $(pwd)/definitions:/app/definitions \
      -v $(pwd)/data:/app/data \
      -e UI_PASSWORD="your_secure_password" \
      --name scarf \
      scarf
    ```

After running the command, Scarf will be accessible at `http://localhost:8080`.

---

## ⚙️ Configuration

Scarf is configured using environment variables. Here are the most important ones:

| Variable          | Description                                                                 | Default                      |
| ----------------- | --------------------------------------------------------------------------- | ---------------------------- |
| `APP_PORT`        | The port the application will listen on.                                    | `8080`                       |
| `DEFINITIONS_PATH`| Path to the indexer definition files.                                       | `./definitions`              |
| `CACHE_TTL`       | How long to cache search results.                                           | `15m`                        |
| `DB_PATH`         | Path to the SQLite database file for the cache.                             | `./data/indexer-cache.db`    |
| `WEB_UI`          | Enable or disable the web UI.                                               | `true`                       |
| `DEBUG`           | Enable debug logging.                                                       | `false`                      |
| `UI_PASSWORD`     | Password to protect the web UI. **Set this!** | `password`                   |
| `FLEXGET_API_KEY` | The API key for accessing the Torznab feed.                                 | (auto-generated 16 chars)    |
| `JWT_SECRET`      | A secret key for signing session tokens.                                    | (auto-generated 32 chars)    |

---

##  Components

### Web UI

Navigate to the address where you're hosting Scarf (e.g., `http://localhost:8080`). You'll be prompted for the password you set with the `UI_PASSWORD` environment variable.

The web UI has three main sections:

* **Search**: Manually search across a single indexer or all of them at once.
* **Logs**: View live logs from the application, useful for debugging.
* **Status**: Check the status of each indexer, test them individually, and get the Torznab URL for Flexget, Sonarr, Radarr, etc.

### Torznab API

To add Scarf to your media automation software:

1.  Go to the **Status** page in the Scarf web UI.
2.  Find the indexer you want to add (or use the "all" indexer).
3.  Click the "Copy Link" button to get the Torznab URL.
4.  In your media automation software, add a new Torznab indexer and paste the URL.

The URL will look something like this: `http://your-scarf-address:8080/torznab/all?apikey=your_flexget_api_key`

---

## 🧩 Indexer Definitions

Scarf's real power comes from its YAML-based definition files. You can find them in the `definitions` directory. Each file defines how to search a specific torrent site.

### Example Definition (`torrentgalaxy.yml`)

```yaml
key: "torrentgalaxy"
name: "TorrentGalaxy"
description: "TorrentGalaxy is a Public site for MOVIES / TV / GENERAL"
language: "en-US"
schedule: "@every 1h"

search:
  type: "html"
  url: "[https://torrentgalaxy.one/get-posts/](https://torrentgalaxy.one/get-posts/){{if .Query}}keywords:{{.Query}}{{end}}"
  results:
    rows_selector: "div.tgxtablerow"
    download_selector: "a[href^='magnet:?xt=']@href"
    fields:
      title:
        selector: "a[href^='/post-detail/']@title"
      # ... other fields
      details_url:
        selector: "a[href^='/post-detail/']@href"

category_mappings:
  - indexer_cat: "Movies"
    torznab_cat: 2000
  - indexer_cat: "TV"
    torznab_cat: 5000
```

### Adding a New Indexer
1. Create a new .yml file in the definitions directory.
2. Follow the structure of the existing definition files to define how to search the new site.
3. Scarf will automatically detect the new file and load it. You don't even need to restart the container!

For more complex sites, you can use the details_url and download_selector fields to perform a two-step search, where Scarf first finds a details page and then extracts the magnet link from that page.

## Roadmap
- [X] Create a simple web ui
- [X] Add authentication
- [X] Add Docker support
- [X] Create basic torznab-compatible api
- [X] Add support for api-based trackers
- [X] Add support for simple html scraping
- [X] Add support for multi-step html scraping (for links in details page)
- [ ] Add support for direct torrent links in addition to magnets
- [ ] Add specific search modes (tv, movie, etc.)
- [ ] Add multi-domain support for trackers
- [ ] Add support for trackers with user / password authentication
- [ ] Add support for CloudSolvarr
- [ ] Direct support for Jackett tracker definitions

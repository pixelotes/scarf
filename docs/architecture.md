# 🏗️ Scarf Architecture Overview

Scarf is designed to be a lightweight, efficient, and highly extensible meta-indexer. Its architecture is built on modern, simple, and robust technologies.



---

### Core Components

#### 1. Go Backend
The entire application is a single, compiled Go binary. This provides several key advantages:
-   **Performance**: Go is a compiled language known for its excellent performance and efficient concurrency, making it ideal for handling multiple simultaneous searches.
-   **Lightweight**: The application has a very low memory footprint (typically 10-15 MB of RAM) and minimal CPU usage.
-   **Portability**: As a single binary, it has no external runtime dependencies and can be run on any major operating system.

#### 2. Extensible YAML Definitions
The logic for interacting with each tracker is not hardcoded. Instead, it is defined in simple, human-readable YAML files located in the `definitions` directory.
-   **Flexibility**: Users can easily add new trackers or modify existing ones without needing to recompile or restart the application. Scarf automatically detects changes and reloads the definitions.
-   **Power**: The YAML format supports various search types, from simple JSON API calls to complex, multi-step HTML scraping.

#### 3. Caching Layer (SQLite)
To minimize redundant requests to trackers and speed up responses, Scarf implements a sophisticated caching layer.
-   **Persistence**: It uses an embedded SQLite database to persist cache data, ensuring that the cache survives application restarts.
-   **TTL & Eviction**: Caches have a Time-To-Live (TTL) and the system automatically evicts the least recently used items when the cache size limit is reached.
-   **Scheduled Pre-fetching**: A background job periodically fetches the latest releases from trackers to keep the "latest" feed warm, providing instant responses to media managers.

#### 4. Frontend Web UI
The frontend is a simple, self-contained single-page application.
-   **Technology**: It uses vanilla JavaScript and CSS, avoiding the complexity of modern frontend frameworks. This keeps the application small and easy to maintain.
-   **Functionality**: The UI communicates with the backend via a secure JSON API to perform searches, view logs in real-time (via WebSockets), and manage indexer settings.

#### 5. Deployment (Docker)
The primary deployment method is via Docker.
-   **Efficiency**: A multi-stage `Dockerfile` is used to build the Go binary in one stage and then copy it into a minimal `scratch` image. This results in a tiny and secure final container.
-   **Ease of Use**: Users can get the application running with a single `docker run` command, with configuration managed through environment variables.
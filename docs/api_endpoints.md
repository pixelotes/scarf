# 🧣 Scarf API Endpoints

This document outlines the available API endpoints for the Scarf application. The API is divided into two main categories: the **Web UI API** (for managing the application) and the **Torznab API** (for media automation tools).

---

## Web UI API

These endpoints are used by the Scarf frontend to provide an interactive user experience. All endpoints under `/api/v1/` require a valid JWT token for authentication, obtained from the `/login` endpoint.

| Method | Path                                | Description                                                                 |
| :----- | :---------------------------------- | :-------------------------------------------------------------------------- |
| `POST` | `/api/v1/login`                     | Authenticates the user with a password and returns a session JWT.           |
| `GET`  | `/api/v1/indexers`                  | Lists all available indexer definitions and their current configurations.   |
| `GET`  | `/api/v1/search`                    | Performs a search and returns results in JSON format. Supports filtering.   |
| `GET`  | `/api/v1/flexget_key`               | Retrieves the secret API key required for the Torznab endpoints.            |
| `POST` | `/api/v1/indexer/toggle`            | Enables or disables a specific indexer.                                     |
| `POST` | `/api/v1/indexer/config`            | Updates the user-specific configuration for an indexer (e.g., username).    |
| `GET`  | `/api/v1/test_indexer`              | Runs a test search on a specific indexer to check its status.               |
| `GET`  | `/api/v1/stats`                     | Retrieves detailed application statistics (cache, memory, etc.).            |
| `GET`  | `/api/v1/logs`                      | Establishes a WebSocket connection to stream live application logs.         |
| `GET`  | `/health`                           | A public endpoint to check the health status of the application.            |

---

## Torznab API

This is the primary API for integration with media managers like Sonarr and Radarr. It follows the Torznab specification.

| Method | Path                        | Description                                                                 |
| :----- | :-------------------------- | :-------------------------------------------------------------------------- |
| `GET`  | `/torznab/{indexer}/api`    | The main Torznab endpoint. Use `?t=caps` for capabilities or `?t=search` for searches. |
| `GET`  | `/torznab/{indexer}/latest` | Returns a feed of the most recent releases, pre-cached by a background job. |

**Note**: The `{indexer}` placeholder can be the key of a specific indexer (e.g., `bitsearch`) or the special keyword `all` to search across all enabled indexers. All Torznab requests require an `apikey` parameter.
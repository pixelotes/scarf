# 🧐 Scarf API Usage, Filtering, and Sorting

Scarf's search API is designed to be both simple for basic queries and powerful for advanced use cases. This guide explains how to use the various search parameters to refine your results.

---

## Basic Search

A basic search is performed using the `q` parameter.

-   **`q={search_term}`**: The keywords you want to search for.

**Example**: `?q=ubuntu`

---

## Advanced Filtering

You can refine your search results by adding parameters to your API request.

### ✒️ Exact Phrase Filtering ("Double Quotes")

To ensure a specific phrase appears in the search results, enclose it in double quotes within your query string. The application will still send the full query to the indexer but will filter the results client-side to guarantee the phrase is present. This is case-insensitive.

-   **Usage**: `?q={search_term} "{must_contain_phrase}"`
-   **Example**: `?q=Dr Stone "S01E03"` will only return results containing "S01E03".
-   **Multiple Filters**: You can use multiple quoted phrases. `?q=Spice and Wolf "Season 1" "1080p"` will only return results containing both "Season 1" and "1080p".

### 🌱 Minimum Seeders

Filter out results that don't have enough seeders to ensure good download speeds.

-   **Usage**: `&min_seeders={number}`
-   **Example**: `&min_seeders=5` will only return results with 5 or more seeders.

### 💾 Minimum Size

Filter out results that are smaller than a specified size. This is useful for avoiding low-quality releases.

-   **Usage**: `&min_size={size}`
-   **Example**: `&min_size=2GB` will only return results that are 2 Gigabytes or larger.
-   **Valid Units**: `B`, `KB`, `MB`, `GB`, `TB`.

---

## 📊 Sorting Results

You can control the order in which results are returned.

### Default Sorting

If you do not provide any sorting parameters, Scarf will **automatically sort results by seeders in descending order** (`seeders`, `desc`). This prioritizes the most popular and healthy torrents.

### Custom Sorting

To override the default behavior, use the `sort` and `order` parameters.

-   **`sort={field}`**: The field to sort by.
    -   **Valid Fields**: `size`, `seeders`, `leechers`, `publishdate`.
-   **`order={direction}`**: The direction to sort in.
    -   **Valid Directions**: `asc` (ascending), `desc` (descending).

**Example**: To sort by file size from largest to smallest:
`&sort=size&order=desc`

**Example**: To sort by release date from oldest to newest:
`&sort=publishdate&order=asc`
# 🚀 Scarf `curl` Examples

Here are some practical `curl` examples to help you test and interact with the Scarf Torznab API.

**Prerequisites:**
-   Scarf is running at `http://localhost:8080`.
-   Your API key is `your_secret_apikey_here`.

---

### 1. Basic Search (Default Sorting by Seeders)
This search for "ubuntu" will return results sorted by the number of seeders, from highest to lowest.

```bash
curl "http://localhost:8080/torznab/all/api?t=search&q=ubuntu&apikey=your_secret_apikey_here"
```

### 2. Custom Sorting (Newest First)
This search sorts the results by their publication date, showing the newest releases first.

```bash
curl "http://localhost:8080/torznab/all/api?t=search&q=ubuntu&apikey=your_secret_apikey_here&sort=publishdate&order=desc"
```

### 3. Filtering by Minimum Seeders
This search will only show results that have at least 10 seeders.

```bash
curl "http://localhost:8080/torznab/all/api?t=search&q=ubuntu&apikey=your_secret_apikey_here&min_seeders=10"
```

### 4. Filtering by Minimum Size
This search will only show results that are larger than 1 Gigabyte.

```bash
curl "http://localhost:8080/torznab/all/api?t=search&q=ubuntu&apikey=your_secret_apikey_here&min_size=1GB"
```

### 5. Advanced Combined Search
This example combines multiple features into a single powerful query. It searches for "ubuntu", but only shows results:

- Containing the exact phrase "24.04".

- With at least 5 seeders.

- Larger than 200 Megabytes.

- Sorted with the largest files first.

```bash
curl "http://localhost:8080/torznab/all/api?t=search&q=ubuntu%20%2224.04%22&apikey=your_secret_apikey_here&min_seeders=5&min_size=200MB&sort=size&order=desc"
```
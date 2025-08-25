package api

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-indexer/auth"
	"go-indexer/cache"
	"go-indexer/indexer"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

// APIHandler holds all dependencies for all API endpoints.
type APIHandler struct {
	Manager         *indexer.Manager
	Cache           *cache.Cache
	CacheTTL        time.Duration
	FlexgetAPIKey   string
	UIPassword      string
	StartTime       time.Time
	rateLimiters    map[string]*rate.Limiter
	rlMutex         sync.RWMutex
	DefaultAPILimit int // New field
}

// SearchResponse represents the enhanced API response with metadata
type SearchResponse struct {
	Results    []indexer.SearchResult `json:"results"`
	Total      int                    `json:"total"`
	Limit      int                    `json:"limit"`
	Offset     int                    `json:"offset"`
	CacheHit   bool                   `json:"cache_hit"`
	SearchTime string                 `json:"search_time_ms"`
	Indexer    string                 `json:"indexer"`
}

// NewAPIHandler creates a new API handler with initialized rate limiters
func NewAPIHandler(manager *indexer.Manager, cache *cache.Cache, cacheTTL time.Duration, flexgetKey, uiPassword string, defaultLimit int) *APIHandler {
	return &APIHandler{
		Manager:         manager,
		Cache:           cache,
		CacheTTL:        cacheTTL,
		FlexgetAPIKey:   flexgetKey,
		UIPassword:      uiPassword,
		StartTime:       time.Now(),
		rateLimiters:    make(map[string]*rate.Limiter),
		DefaultAPILimit: defaultLimit, // Store the new default limit
	}
}

// getRateLimiter returns a rate limiter for the given indexer
func (h *APIHandler) getRateLimiter(indexerKey string) *rate.Limiter {
	h.rlMutex.RLock()
	limiter, exists := h.rateLimiters[indexerKey]
	h.rlMutex.RUnlock()

	if !exists {
		h.rlMutex.Lock()
		// Double-check after acquiring the lock
		if limiter, exists = h.rateLimiters[indexerKey]; !exists {
			limiter = rate.NewLimiter(rate.Limit(1), 3) // 1 request per second, burst of 3
			h.rateLimiters[indexerKey] = limiter
		}
		h.rlMutex.Unlock()
	}
	return limiter
}

// HealthCheck returns enhanced health status of the application
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	allIndexers := h.Manager.GetAllIndexers()
	healthyIndexers := 0
	totalIndexers := 0
	indexerStatus := make(map[string]interface{})

	// Test a limited number of indexers for performance
	testLimit := 5
	if len(allIndexers) < testLimit {
		testLimit = len(allIndexers)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	count := 0
	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		totalIndexers++

		// Only test a subset for performance
		if count < testLimit {
			err := h.Manager.Test(ctx, key)
			status := map[string]interface{}{
				"name":    def.Name,
				"healthy": err == nil,
				"type":    def.Type,
			}

			if err != nil {
				status["error"] = err.Error()
			} else {
				healthyIndexers++
			}

			indexerStatus[key] = status
			count++
		} else if count == testLimit {
			// For remaining indexers, just assume they're healthy if enabled
			healthyIndexers += (totalIndexers - testLimit)
			break
		}
	}

	// Get cache statistics
	cacheStats := h.Cache.GetStats()

	healthStatus := map[string]interface{}{
		"status":           determineHealthStatus(healthyIndexers, totalIndexers),
		"uptime":           time.Since(h.StartTime).String(),
		"total_indexers":   totalIndexers,
		"healthy_indexers": healthyIndexers,
		"tested_indexers":  testLimit,
		"cache": map[string]interface{}{
			"enabled":   h.Cache != nil,
			"entries":   cacheStats.EntryCount,
			"size_mb":   cacheStats.Size / (1024 * 1024),
			"hit_ratio": cacheStats.HitRatio,
			"hits":      cacheStats.Hits,
			"misses":    cacheStats.Misses,
		},
		"timestamp": time.Now().UTC(),
	}

	// Include detailed indexer status only if requested
	if r.URL.Query().Get("detailed") == "true" {
		healthStatus["indexer_details"] = indexerStatus
	}

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	if healthStatus["status"] == "degraded" {
		statusCode = http.StatusServiceUnavailable
	} else if healthStatus["status"] == "unhealthy" {
		statusCode = http.StatusInternalServerError
	}

	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthStatus)
}

// Login handles UI authentication.
func (h *APIHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if creds.Password != h.UIPassword {
		slog.Warn("Failed login attempt", "remote_addr", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		slog.Error("Failed to generate token", "error", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	slog.Info("Successful login", "remote_addr", r.RemoteAddr)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// IndexerDetail for API response, including a map of categories for the UI.
type IndexerDetail struct {
	Name             string                    `json:"name"`
	Type             string                    `json:"type"`
	Description      string                    `json:"description"`
	Enabled          bool                      `json:"enabled"`
	Settings         []indexer.UserSetting     `json:"settings,omitempty"`
	UserConfig       map[string]string         `json:"user_config"`
	CategoryMappings []indexer.CategoryMapping `json:"category_mappings"`
	Categories       map[int]string            `json:"categories"`
}

// ListIndexers returns a JSON list of available indexers for the UI.
func (h *APIHandler) ListIndexers(w http.ResponseWriter, r *http.Request) {
	indexers := h.Manager.GetAllIndexers()
	response := make(map[string]IndexerDetail)

	for key, def := range indexers {
		cats := make(map[int]string)
		for _, mapping := range def.CategoryMappings {
			if stdCat, ok := indexer.StandardCategories[mapping.TorznabCategory]; ok {
				cats[stdCat.ID] = stdCat.Name
			}
		}
		response[key] = IndexerDetail{
			Name:             def.Name,
			Type:             def.Type,
			Description:      def.Description,
			Enabled:          bool(def.Enabled),
			Settings:         def.Settings,
			UserConfig:       def.UserConfig,
			CategoryMappings: def.CategoryMappings,
			Categories:       cats,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ToggleIndexerPayload is the struct for the toggle request
type ToggleIndexerPayload struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

// UpdateConfigPayload is the struct for the credential update request
type UpdateConfigPayload struct {
	Key    string            `json:"key"`
	Config map[string]string `json:"config"`
}

// UpdateIndexerConfig handles updating the user configuration for an indexer.
func (h *APIHandler) UpdateIndexerConfig(w http.ResponseWriter, r *http.Request) {
	var payload UpdateConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if err := h.Manager.UpdateIndexerUserConfig(payload.Key, payload.Config); err != nil {
		slog.Error("Failed to update indexer config", "key", payload.Key, "error", err)
		http.Error(w, "Failed to update indexer configuration", http.StatusInternalServerError)
		return
	}

	// Explicitly trigger a reload after saving the configuration.
	if err := h.Manager.Reload(); err != nil {
		slog.Error("Failed to reload definitions after config update", "key", payload.Key, "error", err)
	}

	slog.Info("Successfully updated indexer config and triggered reload", "key", payload.Key)
	w.WriteHeader(http.StatusOK)
}

// ToggleIndexer handles enabling or disabling an indexer
func (h *APIHandler) ToggleIndexer(w http.ResponseWriter, r *http.Request) {
	var payload ToggleIndexerPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if err := h.Manager.ToggleIndexerEnabled(payload.Key, payload.Enabled); err != nil {
		slog.Error("Failed to toggle indexer", "key", payload.Key, "error", err)
		http.Error(w, "Failed to update indexer", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// searchAll performs a concurrent search across all indexers with cache support.
func (h *APIHandler) searchAll(query, category string) ([]indexer.SearchResult, error) {
	slog.Info("Starting aggregate search", "query", query, "category", category)
	allIndexers := h.Manager.GetAllIndexers()

	var wg sync.WaitGroup
	resultsChan := make(chan []indexer.SearchResult, len(allIndexers))

	liveQueryKeys := []string{}

	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		cacheKeyHash := sha1.Sum([]byte(fmt.Sprintf("%s:search:%s:%s", key, query, category)))
		cacheKey := fmt.Sprintf("%x", cacheKeyHash)

		if cachedXML, found := h.Cache.Get(cacheKey); found {
			slog.Info("Aggregate search served from cache for indexer", "indexer", def.Name, "query", query)
			var feed RSSFeed
			if xml.Unmarshal(cachedXML, &feed) == nil {
				var cachedResults []indexer.SearchResult
				for _, item := range feed.Channel.Items {
					pubDate, _ := time.Parse(time.RFC1123Z, item.PublishDate)
					// Correctly parse seeders/leechers from cached XML attributes
					cachedResults = append(cachedResults, indexer.SearchResult{
						Title:       item.Title,
						DownloadURL: item.Link,
						Size:        item.Size,
						Seeders:     toInt(findAttr(item.Attrs, "seeders")),
						Leechers:    toInt(findAttr(item.Attrs, "leechers")),
						PublishDate: pubDate,
					})
				}
				if len(cachedResults) > 0 {
					resultsChan <- cachedResults
				}
			}
		} else {
			liveQueryKeys = append(liveQueryKeys, key)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, indexerKey := range liveQueryKeys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			limiter := h.getRateLimiter(key)
			if !limiter.Allow() {
				slog.Warn("Rate limit exceeded during searchAll", "indexer", key)
				return
			}
			slog.Info("Aggregate search (cache miss)", "indexer", key, "query", query)
			results, err := h.Manager.Search(ctx, key, query, category)
			if err != nil {
				if err == context.DeadlineExceeded {
					slog.Warn("Search timed out for indexer", "indexer", key)
				} else {
					slog.Warn("Search failed for indexer during searchAll", "indexer", key, "query", query, "error", err)
				}
				return
			}
			if len(results) > 0 {
				resultsChan <- results
				// --- FIX: Cache the new results for next time ---
				def, _ := h.Manager.GetIndexer(key)
				cacheKeyHash := sha1.Sum([]byte(fmt.Sprintf("%s:search:%s:%s", key, query, category)))
				cacheKey := fmt.Sprintf("%x", cacheKeyHash)
				CacheRSSFeed(h.Cache, cacheKey, h.CacheTTL, def, results)
			}
		}(indexerKey)
	}

	wg.Wait()
	close(resultsChan)

	uniqueResults := make(map[string]indexer.SearchResult)
	for resultSet := range resultsChan {
		for _, result := range resultSet {
			isDuplicate := false
			for existingKey, existingResult := range uniqueResults {
				if similarTitles(result.Title, existingResult.Title) &&
					abs(result.Size-existingResult.Size) < 100*1024*1024 {
					isDuplicate = true
					if result.Seeders > existingResult.Seeders {
						delete(uniqueResults, existingKey)
						break
					} else {
						break
					}
				}
			}
			if !isDuplicate {
				uniqueKey := fmt.Sprintf("%s-%d-%d", result.Title, result.Size, result.Seeders)
				uniqueResults[uniqueKey] = result
			}
		}
	}

	allResults := make([]indexer.SearchResult, 0, len(uniqueResults))
	for _, result := range uniqueResults {
		allResults = append(allResults, result)
	}

	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].PublishDate.After(allResults[j].PublishDate)
	})

	return allResults, nil
}

// WebSearch handles search requests with enhanced caching and pagination
func (h *APIHandler) WebSearch(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	indexerKey := r.URL.Query().Get("indexer")
	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("cat")

	// Parse pagination parameters with new logic
	limitStr := r.URL.Query().Get("perPage")
	if limitStr == "" {
		limitStr = r.URL.Query().Get("limit")
	}
	limit := h.DefaultAPILimit
	if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
		limit = parsed
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	forceFresh := r.URL.Query().Get("fresh") == "true"

	if indexerKey == "" {
		http.Error(w, `{"error": "indexer parameter is required"}`, http.StatusBadRequest)
		return
	}

	cacheKeyHash := sha1.Sum([]byte(fmt.Sprintf("json_search:%s:%s:%s",
		indexerKey, query, category)))
	cacheKey := fmt.Sprintf("%x", cacheKeyHash)

	var results []indexer.SearchResult
	var err error
	var cacheHit bool

	if !forceFresh && indexerKey != "all" {
		if cachedJSON, found := h.Cache.Get(cacheKey); found {
			var cachedResponse SearchResponse
			if json.Unmarshal(cachedJSON, &cachedResponse) == nil {
				slog.Info("Web search request served from cache", "indexer", indexerKey, "query", query, "key", cacheKey)
				cachedResponse.CacheHit = true
				cachedResponse.SearchTime = fmt.Sprintf("%.2f", float64(time.Since(startTime).Nanoseconds())/1e6)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				json.NewEncoder(w).Encode(cachedResponse)
				return
			}
		}
	}

	slog.Info("Web search request (cache miss)", "indexer", indexerKey, "query", query, "category", category, "force_fresh", forceFresh)

	ctx := r.Context()
	if indexerKey == "all" {
		results, err = h.searchAll(query, category)
	} else {
		limiter := h.getRateLimiter(indexerKey)
		if !limiter.Allow() {
			http.Error(w, `{"error": "Rate limit exceeded, please try again later"}`, http.StatusTooManyRequests)
			return
		}
		results, err = h.Manager.Search(ctx, indexerKey, query, category)
	}

	if err != nil {
		slog.Error("Error during web search", "indexer", indexerKey, "query", query, "error", err)
		http.Error(w, `{"error": "Failed to perform search on the selected indexer"}`, http.StatusInternalServerError)
		return
	}

	total := len(results)
	if offset >= total {
		results = []indexer.SearchResult{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		results = results[offset:end]
	}

	response := SearchResponse{
		Results:    results,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		CacheHit:   cacheHit,
		SearchTime: fmt.Sprintf("%.2f", float64(time.Since(startTime).Nanoseconds())/1e6),
		Indexer:    indexerKey,
	}

	if indexerKey != "all" && len(results) > 0 {
		if jsonResponse, err := json.Marshal(response); err == nil {
			h.Cache.Set(cacheKey, jsonResponse, h.CacheTTL/2)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cache", "MISS")
	json.NewEncoder(w).Encode(response)
}

// TestIndexer runs a test search on an indexer.
func (h *APIHandler) TestIndexer(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("indexer")
	limiter := h.getRateLimiter(key)
	if !limiter.Allow() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "Rate limit exceeded, please try again later",
		})
		return
	}

	err := h.Manager.Test(r.Context(), key)
	if err != nil {
		slog.Warn("Indexer test failed", "indexer", key, "error", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	slog.Info("Indexer test successful", "indexer", key)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// GetFlexgetAPIKey returns the API key for Flexget configuration.
func (h *APIHandler) GetFlexgetAPIKey(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"key": h.FlexgetAPIKey})
}

// CacheStatsHandler provides cache statistics
func (h *APIHandler) CacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := h.Cache.GetStats()
	popular := h.Cache.GetPopularKeys(10)

	response := map[string]interface{}{
		"statistics":   stats,
		"popular_keys": popular,
		"cache_ttl":    h.CacheTTL.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CacheManagementHandler provides cache management operations
func (h *APIHandler) CacheManagementHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "DELETE":
		key := r.URL.Query().Get("key")
		if key != "" {
			h.Cache.Delete(key)
			slog.Info("Cache entry deleted", "key", key)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "key": key})
		} else {
			h.Cache.Clear()
			slog.Info("Cache cleared")
			json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MetricsHandler provides Prometheus-style metrics
func (h *APIHandler) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	stats := h.Cache.GetStats()
	allIndexers := h.Manager.GetAllIndexers()

	enabledCount := 0
	for _, def := range allIndexers {
		if def.Enabled {
			enabledCount++
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# HELP scarf_indexers_total Total number of configured indexers\n")
	fmt.Fprintf(w, "# TYPE scarf_indexers_total gauge\n")
	fmt.Fprintf(w, "scarf_indexers_total %d\n", len(allIndexers))

	fmt.Fprintf(w, "# HELP scarf_indexers_enabled Number of enabled indexers\n")
	fmt.Fprintf(w, "# TYPE scarf_indexers_enabled gauge\n")
	fmt.Fprintf(w, "scarf_indexers_enabled %d\n", enabledCount)

	fmt.Fprintf(w, "# HELP scarf_cache_hits_total Total cache hits\n")
	fmt.Fprintf(w, "# TYPE scarf_cache_hits_total counter\n")
	fmt.Fprintf(w, "scarf_cache_hits_total %d\n", stats.Hits)

	fmt.Fprintf(w, "# HELP scarf_cache_misses_total Total cache misses\n")
	fmt.Fprintf(w, "# TYPE scarf_cache_misses_total counter\n")
	fmt.Fprintf(w, "scarf_cache_misses_total %d\n", stats.Misses)

	fmt.Fprintf(w, "# HELP scarf_cache_hit_ratio Cache hit ratio\n")
	fmt.Fprintf(w, "# TYPE scarf_cache_hit_ratio gauge\n")
	fmt.Fprintf(w, "scarf_cache_hit_ratio %.4f\n", stats.HitRatio)

	fmt.Fprintf(w, "# HELP scarf_cache_entries Current cache entries\n")
	fmt.Fprintf(w, "# TYPE scarf_cache_entries gauge\n")
	fmt.Fprintf(w, "scarf_cache_entries %d\n", stats.EntryCount)

	fmt.Fprintf(w, "# HELP scarf_cache_size_bytes Cache size in bytes\n")
	fmt.Fprintf(w, "# TYPE scarf_cache_size_bytes gauge\n")
	fmt.Fprintf(w, "scarf_cache_size_bytes %d\n", stats.Size)

	fmt.Fprintf(w, "# HELP scarf_uptime_seconds Application uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE scarf_uptime_seconds gauge\n")
	fmt.Fprintf(w, "scarf_uptime_seconds %.0f\n", time.Since(h.StartTime).Seconds())
}

// TorznabAPI handles the main Torznab API endpoint with proper routing
func (h *APIHandler) TorznabAPI(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("apikey")
	if apiKey != h.FlexgetAPIKey {
		slog.Warn("Invalid Torznab API key used", "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	indexerKey := chi.URLParam(r, "indexer")
	torznabType := r.URL.Query().Get("t")

	if torznabType == "" {
		http.Error(w, "Bad request: 't' parameter is required.", http.StatusBadRequest)
		return
	}

	switch torznabType {
	case "caps":
		h.handleCaps(w, r, indexerKey)
	case "search", "tv-search", "movie-search":
		h.handleSearch(w, r, indexerKey)
	default:
		http.Error(w, fmt.Sprintf("Unsupported Torznab function: %s", torznabType), http.StatusBadRequest)
	}
}

// handleCaps returns the capabilities of an indexer
func (h *APIHandler) handleCaps(w http.ResponseWriter, r *http.Request, indexerKey string) {
	var caps TorznabCaps

	if indexerKey == "all" {
		slog.Debug("Generating caps for 'all' indexers")

		caps = TorznabCaps{
			XMLName: xml.Name{Local: "caps"},
			Server:  TorznabServer{Title: "All Indexers"},
			Limits:  TorznabLimits{Max: 100, Default: 50},
			Searching: TorznabSearching{
				Search:      TorznabSearchType{Available: "yes", SupportedParams: "q,cat"},
				TvSearch:    TorznabSearchType{Available: "yes", SupportedParams: "q,cat,season,ep"},
				MovieSearch: TorznabSearchType{Available: "yes", SupportedParams: "q,cat,imdbid"},
			},
			Categories: TorznabCategories{Categories: []TorznabParentCategory{}},
		}

		hardcodedCategoryIDs := []int{2000, 2030, 2040, 5000, 5030, 5040}
		parentCategories := make(map[int]TorznabParentCategory)

		for _, catID := range hardcodedCategoryIDs {
			if stdCat, ok := indexer.StandardCategories[catID]; ok {
				parentID := (stdCat.ID / 1000) * 1000
				if parent, ok := indexer.StandardCategories[parentID]; ok {
					if _, exists := parentCategories[parentID]; !exists {
						parentCategories[parentID] = TorznabParentCategory{
							ID:     strconv.Itoa(parent.ID),
							Name:   parent.Name,
							Subcat: []TorznabSubCategory{},
						}
					}
					pCat := parentCategories[parentID]
					pCat.Subcat = append(pCat.Subcat, TorznabSubCategory{
						ID:   strconv.Itoa(stdCat.ID),
						Name: strings.TrimPrefix(stdCat.Name, parent.Name+"/"),
					})
					parentCategories[parentID] = pCat
				}
			}
		}

		for _, pCat := range parentCategories {
			caps.Categories.Categories = append(caps.Categories.Categories, pCat)
		}

	} else {
		def, ok := h.Manager.GetIndexer(indexerKey)
		if !ok {
			slog.Warn("Indexer not found for caps request", "indexer", indexerKey)
			http.NotFound(w, r)
			return
		}

		slog.Debug("Generating caps for indexer", "indexer", indexerKey, "name", def.Name)

		caps = TorznabCaps{
			XMLName: xml.Name{Local: "caps"},
			Server:  TorznabServer{Title: def.Name},
			Limits:  TorznabLimits{Max: 100, Default: 50},
			Searching: TorznabSearching{
				Search:      TorznabSearchType{Available: "yes", SupportedParams: "q,cat"},
				TvSearch:    TorznabSearchType{Available: "yes", SupportedParams: "q,cat,season,ep"},
				MovieSearch: TorznabSearchType{Available: "yes", SupportedParams: "q,cat,imdbid"},
			},
			Categories: TorznabCategories{Categories: []TorznabParentCategory{}},
		}

		parentCategories := make(map[int]TorznabParentCategory)

		if def.CategoryMappings != nil {
			for _, mapping := range def.CategoryMappings {
				if stdCat, ok := indexer.StandardCategories[mapping.TorznabCategory]; ok {
					parentID := (stdCat.ID / 1000) * 1000
					if parent, ok := indexer.StandardCategories[parentID]; ok {
						if _, exists := parentCategories[parentID]; !exists {
							parentCategories[parentID] = TorznabParentCategory{
								ID:     strconv.Itoa(parent.ID),
								Name:   parent.Name,
								Subcat: []TorznabSubCategory{},
							}
						}
						pCat := parentCategories[parentID]
						pCat.Subcat = append(pCat.Subcat, TorznabSubCategory{
							ID:   strconv.Itoa(stdCat.ID),
							Name: strings.TrimPrefix(stdCat.Name, parent.Name+"/"),
						})
						parentCategories[parentID] = pCat
					}
				}
			}
		}

		for _, pCat := range parentCategories {
			caps.Categories.Categories = append(caps.Categories.Categories, pCat)
		}
	}

	output, err := xml.MarshalIndent(caps, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal caps XML", "indexer", indexerKey, "error", err)
		http.Error(w, "Failed to generate caps XML", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(xml.Header + string(output)))
}

// handleSearch performs the actual search and returns RSS
func (h *APIHandler) handleSearch(w http.ResponseWriter, r *http.Request, indexerKey string) {
	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("cat")

	var results []indexer.SearchResult
	var err error
	var def *indexer.Definition

	if indexerKey == "all" {
		slog.Info("Torznab request", "indexer", "all", "query", query, "category", category)
		results, err = h.searchAll(query, category)
		if err != nil {
			slog.Error("Torznab search failed for all indexers", "query", query, "error", err)
			http.Error(w, "Failed to search indexers.", http.StatusInternalServerError)
			return
		}
		def = &indexer.Definition{
			Name:        "All Indexers",
			Description: "Aggregated search across all enabled indexers",
			Language:    "en-US",
		}
	} else {
		var ok bool
		def, ok = h.Manager.GetIndexer(indexerKey)
		if !ok {
			http.NotFound(w, r)
			return
		}

		limiter := h.getRateLimiter(indexerKey)
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		cacheKeyHash := sha1.Sum([]byte(fmt.Sprintf("%s:search:%s:%s", indexerKey, query, category)))
		cacheKey := fmt.Sprintf("%x", cacheKeyHash)

		if cachedXML, found := h.Cache.Get(cacheKey); found {
			slog.Info("Torznab request served from cache", "indexer", indexerKey, "query", query, "key", cacheKey)
			var feed RSSFeed
			if xml.Unmarshal(cachedXML, &feed) == nil {
				// Convert cached XML items back to SearchResult structs to allow for pagination
				for _, item := range feed.Channel.Items {
					pubDate, _ := time.Parse(time.RFC1123Z, item.PublishDate)
					results = append(results, indexer.SearchResult{
						Title:       item.Title,
						DownloadURL: item.Link,
						Size:        item.Size,
						Seeders:     toInt(findAttr(item.Attrs, "seeders")),
						Leechers:    toInt(findAttr(item.Attrs, "leechers")),
						PublishDate: pubDate,
					})
				}
			}
		} else {
			slog.Info("Torznab request (cache miss)", "indexer", indexerKey, "query", query, "category", category)
			results, err = h.Manager.Search(r.Context(), indexerKey, query, category)
			if err != nil {
				slog.Error("Torznab search failed", "indexer", indexerKey, "query", query, "error", err)
				http.Error(w, "Failed to search indexer.", http.StatusInternalServerError)
				return
			}
			// Cache the full, unpaginated results for future requests
			defer func() {
				if indexerKey != "all" {
					CacheRSSFeed(h.Cache, cacheKey, h.CacheTTL, def, results)
				}
			}()
		}
	}

	// --- PAGINATION LOGIC (Applies to both live and cached results) ---
	limitStr := r.URL.Query().Get("limit")
	limit := h.DefaultAPILimit
	if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
		limit = parsed
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
		offset = parsed
	}

	total := len(results)
	if offset >= total {
		results = []indexer.SearchResult{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		results = results[offset:end]
	}

	// Generate RSS feed for the correctly paginated results
	feed := NewRSSFeed(def)
	for _, result := range results {
		item := Item{
			Title:       result.Title,
			Link:        result.DownloadURL,
			PublishDate: result.PublishDate.Format(time.RFC1123Z),
			Size:        result.Size,
			Enclosure: Enclosure{
				URL:    result.DownloadURL,
				Length: result.Size,
				Type:   "application/x-bittorrent",
			},
			Attrs: []TorznabAttr{
				{Name: "seeders", Value: strconv.Itoa(result.Seeders)},
				{Name: "leechers", Value: strconv.Itoa(result.Leechers)},
				{Name: "size", Value: strconv.FormatInt(result.Size, 10)},
			},
		}
		feed.Channel.Items = append(feed.Channel.Items, item)
	}

	output, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		http.Error(w, "Failed to generate XML feed.", http.StatusInternalServerError)
		return
	}

	finalOutput := []byte(xml.Header + string(output))

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write(finalOutput)
}

// Legacy TorznabSearch for backward compatibility (if needed)
func (h *APIHandler) TorznabSearch(w http.ResponseWriter, r *http.Request) {
	h.TorznabAPI(w, r)
}

// Helper functions
func determineHealthStatus(healthy, total int) string {
	if total == 0 {
		return "no_indexers"
	}

	ratio := float64(healthy) / float64(total)
	switch {
	case ratio >= 0.8:
		return "healthy"
	case ratio >= 0.3:
		return "degraded"
	default:
		return "unhealthy"
	}
}

func similarTitles(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == b {
		return true
	}
	commonWords := []string{"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
	for _, word := range commonWords {
		a = strings.ReplaceAll(a, " "+word+" ", " ")
		b = strings.ReplaceAll(b, " "+word+" ", " ")
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func findAttr(attrs []TorznabAttr, name string) string {
	for _, attr := range attrs {
		if attr.Name == name {
			return attr.Value
		}
	}
	return "0"
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

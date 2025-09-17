package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"runtime"
	"slices"
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
	Manager               *indexer.Manager
	Cache                 *cache.Cache
	CacheTTL              time.Duration
	LatestCacheTTL        time.Duration
	FlexgetAPIKey         string
	UIPassword            string
	StartTime             time.Time
	rateLimiters          map[string]*rate.Limiter
	rlMutex               sync.RWMutex
	DefaultAPILimit       int
	MaxConcurrentSearches int
	indexerHits           map[string]int64
	recentSearches        []string
	statsMutex            sync.Mutex
}

// Represents the stats object
type AppStats struct {
	Cache          *cache.CacheStats `json:"cache"`
	DB             *cache.DBStats    `json:"db"`
	IndexerHits    map[string]int64  `json:"indexer_hits"`
	TopFailures    map[string]int    `json:"top_failures"`
	RecentSearches []string          `json:"recent_searches"`
	Runtime        struct {
		Alloc      uint64 `json:"alloc_mb"`
		TotalAlloc uint64 `json:"total_alloc_mb"`
		Sys        uint64 `json:"sys_mb"`
		NumGC      uint32 `json:"num_gc"`
	} `json:"runtime"`
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

// parseQueryAndFilters extracts terms in double quotes for filtering and returns a clean query.
func parseQueryAndFilters(query string) (string, []string) {
	re := regexp.MustCompile(`"([^"]+)"`)
	filters := []string{}
	matches := re.FindAllStringSubmatch(query, -1)
	for _, match := range matches {
		if len(match) > 1 {
			filters = append(filters, strings.ToLower(match[1]))
		}
	}
	// The clean query sent to the indexer should contain the full string
	cleanQuery := re.ReplaceAllString(query, "$1")
	cleanQuery = strings.Join(strings.Fields(cleanQuery), " ") // Remove extra spaces
	return cleanQuery, filters
}

func (h *APIHandler) recordSearch(query string) {
	if query == "" {
		return
	}
	h.statsMutex.Lock()
	defer h.statsMutex.Unlock()
	// Avoid adding duplicate consecutive searches
	if len(h.recentSearches) > 0 && h.recentSearches[len(h.recentSearches)-1] == query {
		return
	}
	h.recentSearches = append(h.recentSearches, query)
	if len(h.recentSearches) > 10 {
		h.recentSearches = h.recentSearches[1:]
	}
}

// New handler to provide application-wide stats
func (h *APIHandler) AppStatsHandler(w http.ResponseWriter, r *http.Request) {
	h.statsMutex.Lock()
	defer h.statsMutex.Unlock()

	stats := AppStats{
		IndexerHits:    maps.Clone(h.indexerHits), // Use a copy
		TopFailures:    h.Manager.GetFailureStats(),
		RecentSearches: slices.Clone(h.recentSearches), // Use a copy
	}

	if h.Cache != nil {
		cacheStats := h.Cache.GetStats()
		stats.Cache = &cacheStats
		dbStats, err := h.Cache.GetDBStats()
		if err == nil {
			stats.DB = &dbStats
		}
	}

	// Get memory stats from Go runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats.Runtime.Alloc = m.Alloc / 1024 / 1024
	stats.Runtime.TotalAlloc = m.TotalAlloc / 1024 / 1024
	stats.Runtime.Sys = m.Sys / 1024 / 1024
	stats.Runtime.NumGC = m.NumGC

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// NewAPIHandler creates a new API handler with initialized rate limiters
func NewAPIHandler(manager *indexer.Manager, cache *cache.Cache, cacheTTL, latestCacheTTL time.Duration, flexgetKey, uiPassword string, defaultLimit, maxConcurrent int) *APIHandler {
	return &APIHandler{
		Manager:               manager,
		Cache:                 cache,
		CacheTTL:              cacheTTL,
		LatestCacheTTL:        latestCacheTTL,
		FlexgetAPIKey:         flexgetKey,
		UIPassword:            uiPassword,
		StartTime:             time.Now(),
		rateLimiters:          make(map[string]*rate.Limiter),
		DefaultAPILimit:       defaultLimit,
		MaxConcurrentSearches: maxConcurrent,
		indexerHits:           make(map[string]int64),
		recentSearches:        make([]string, 0, 10),
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

	var cacheStatus map[string]interface{}
	if h.Cache != nil {
		cacheStats := h.Cache.GetStats()
		cacheStatus = map[string]interface{}{
			"enabled":   true,
			"entries":   cacheStats.EntryCount,
			"size_mb":   cacheStats.Size / (1024 * 1024),
			"hit_ratio": cacheStats.HitRatio,
			"hits":      cacheStats.Hits,
			"misses":    cacheStats.Misses,
		}
	} else {
		cacheStatus = map[string]interface{}{"enabled": false}
	}

	healthStatus := map[string]interface{}{
		"status":           determineHealthStatus(healthyIndexers, totalIndexers),
		"uptime":           time.Since(h.StartTime).String(),
		"total_indexers":   totalIndexers,
		"healthy_indexers": healthyIndexers,
		"tested_indexers":  testLimit,
		"cache":            cacheStatus,
		"timestamp":        time.Now().UTC(),
	}

	// Include detailed indexer status only if requested
	if r.URL.Query().Get("detailed") == "true" {
		healthStatus["indexer_details"] = indexerStatus
	}

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	switch healthStatus["status"] {
	case "degraded":
		statusCode = http.StatusServiceUnavailable
	case "unhealthy":
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

// searchAll performs a concurrent search across all indexers with unified cache support
func (h *APIHandler) searchAll(params indexer.SearchParams) ([]indexer.SearchResult, error) {
	slog.Info("Starting aggregate search", "query", params.Query, "category", params.Category)
	allIndexers := h.Manager.GetAllIndexers()
	var cacheMisses []string
	var allResults []indexer.SearchResult
	var resultsMutex sync.Mutex

	// Step 1: Sequentially check the cache for all enabled indexers.
	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		if h.Cache != nil {
			if cachedResults, found := GetCachedSearchResults(h.Cache, key, params.Query, params.Category); found {
				slog.Info("Aggregate search served from cache", "indexer", key, "query", params.Query)
				allResults = append(allResults, cachedResults...)
			} else {
				cacheMisses = append(cacheMisses, key)
			}
		} else {
			cacheMisses = append(cacheMisses, key)
		}
	}

	// Step 2: Concurrently search for all the cache misses.
	if len(cacheMisses) > 0 {
		var wg sync.WaitGroup
		workerJobs := make(chan string, len(cacheMisses))

		for i := 0; i < h.MaxConcurrentSearches; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for indexerKey := range workerJobs {
					slog.Info("Aggregate search (cache miss)", "indexer", indexerKey, "query", params.Query)
					limiter := h.getRateLimiter(indexerKey)
					if !limiter.Allow() {
						slog.Warn("Rate limit exceeded", "indexer", indexerKey)
						continue
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					liveResults, err := h.Manager.Search(ctx, indexerKey, params)
					cancel()

					if err != nil {
						slog.Warn("Search failed for indexer", "indexer", indexerKey, "query", params.Query, "error", err)
						continue
					}

					if len(liveResults) > 0 {
						if h.Cache != nil {
							CacheSearchResults(h.Cache, indexerKey, params.Query, params.Category, liveResults, h.CacheTTL)
						}
						resultsMutex.Lock()
						allResults = append(allResults, liveResults...)
						resultsMutex.Unlock()
					}
				}
			}()
		}

		for _, key := range cacheMisses {
			workerJobs <- key
		}
		close(workerJobs)

		wg.Wait()
	}

	// Step 3: De-duplicate and sort the final combined results.
	uniqueResults := h.deduplicateResults(allResults)
	sort.Slice(uniqueResults, func(i, j int) bool {
		return uniqueResults[i].PublishDate.After(uniqueResults[j].PublishDate)
	})

	return uniqueResults, nil
}

// deduplicateResults removes duplicate search results
func (h *APIHandler) deduplicateResults(results []indexer.SearchResult) []indexer.SearchResult {
	uniqueResults := make(map[string]indexer.SearchResult)

	for _, result := range results {
		isDuplicate := false
		for existingKey, existingResult := range uniqueResults {
			if similarTitles(result.Title, existingResult.Title) &&
				abs(result.Size-existingResult.Size) < 100*1024*1024 {
				isDuplicate = true
				// Keep the result with better seeders
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

	finalResults := make([]indexer.SearchResult, 0, len(uniqueResults))
	for _, result := range uniqueResults {
		finalResults = append(finalResults, result)
	}

	return finalResults
}

// WebSearch handles search requests with unified caching and pagination
func (h *APIHandler) WebSearch(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	originalQuery := r.URL.Query().Get("q")
	cleanQuery, filters := parseQueryAndFilters(originalQuery)

	searchParams := indexer.SearchParams{
		Query:    cleanQuery,
		Category: r.URL.Query().Get("cat"),
		IMDBID:   r.URL.Query().Get("imdbid"),
	}
	if s, err := strconv.Atoi(r.URL.Query().Get("season")); err == nil {
		searchParams.Season = s
	}
	if e, err := strconv.Atoi(r.URL.Query().Get("ep")); err == nil {
		searchParams.Episode = e
	}

	indexerKey := r.URL.Query().Get("indexer")

	// Add this line to record the search
	h.recordSearch(searchParams.Query)

	// Parse pagination parameters
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

	if indexerKey == "" {
		http.Error(w, `{"error": "indexer parameter is required"}`, http.StatusBadRequest)
		return
	}

	var results []indexer.SearchResult
	var err error
	var cacheHit bool

	if indexerKey == "all" {
		results, err = h.searchAll(searchParams)
		cacheHit = false // We report MISS on the aggregate even if sub-queries hit cache.
	} else {
		// This logic is for individual indexer searches
		if h.Cache != nil {
			if cachedResults, found := GetCachedSearchResults(h.Cache, indexerKey, searchParams.Query, searchParams.Category); found {
				slog.Info("Web search request served from cache", "indexer", indexerKey, "query", searchParams.Query)
				results = cachedResults
				cacheHit = true
				// Add this to record the hit
				h.statsMutex.Lock()
				h.indexerHits[indexerKey]++
				h.statsMutex.Unlock()
			}
		}
		if results == nil { // Cache miss
			slog.Info("Web search request (cache miss)", "indexer", indexerKey, "query", searchParams.Query, "category", searchParams.Category)
			liveResults, searchErr := h.Manager.Search(r.Context(), indexerKey, searchParams)
			err = searchErr
			if err == nil && len(liveResults) > 0 && h.Cache != nil {
				CacheSearchResults(h.Cache, indexerKey, searchParams.Query, searchParams.Category, liveResults, h.CacheTTL)
			}
			results = liveResults
		}
	}

	if err != nil {
		slog.Error("Error during web search", "indexer", indexerKey, "query", searchParams.Query, "error", err)
		http.Error(w, `{"error": "Failed to perform search on the selected indexer"}`, http.StatusInternalServerError)
		return
	}

	// Apply server-side filtering and sorting
	results = applyQueryFilters(r, results)
	applyQuerySorting(r, results)

	if len(filters) > 0 {
		var filteredResults []indexer.SearchResult
		for _, result := range results {
			titleLower := strings.ToLower(result.Title)
			matchesAll := true
			for _, filter := range filters {
				if !strings.Contains(titleLower, filter) {
					matchesAll = false
					break
				}
			}
			if matchesAll {
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults
	}

	// Apply pagination
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

	w.Header().Set("Content-Type", "application/json")
	if cacheHit {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	json.NewEncoder(w).Encode(response)
}

// TestIndexer runs a test search on an indexer.
func (h *APIHandler) TestIndexer(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("indexer")

	// The "all" indexer is a special case
	if key == "all" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}

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
	if h.Cache == nil {
		http.Error(w, `{"error": "cache is disabled"}`, http.StatusServiceUnavailable)
		return
	}
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
	if h.Cache == nil {
		http.Error(w, "Method not allowed when cache is disabled", http.StatusMethodNotAllowed)
		return
	}

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

	if h.Cache != nil {
		stats := h.Cache.GetStats()
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
	}

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
	case "search", "tv-search", "tvsearch", "movie-search", "moviesearch", "book-search", "booksearch", "music-search", "musicsearch":
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
		// "all" endpoint only supports basic search for now
		caps = TorznabCaps{
			XMLName: xml.Name{Local: "caps"},
			Server:  TorznabServer{Title: "All Indexers"},
			Limits:  TorznabLimits{Max: 100, Default: 50},
			Searching: TorznabSearching{
				Search:      TorznabSearchType{Available: "yes", SupportedParams: "q,cat"},
				TvSearch:    TorznabSearchType{Available: "no"},
				MovieSearch: TorznabSearchType{Available: "no"},
			},
			Categories: TorznabCategories{Categories: []TorznabParentCategory{}},
		}
	} else {
		def, ok := h.Manager.GetIndexer(indexerKey)
		if !ok {
			slog.Warn("Indexer not found for caps request", "indexer", indexerKey)
			http.NotFound(w, r)
			return
		}

		slog.Debug("Generating caps for indexer", "indexer", indexerKey, "name", def.Name)

		// Dynamically build searching capabilities
		searching := TorznabSearching{
			Search:      TorznabSearchType{Available: "no"},
			TvSearch:    TorznabSearchType{Available: "no"},
			MovieSearch: TorznabSearchType{Available: "no"},
		}
		for mode, params := range def.Search.Modes {
			supportedParams := strings.Join(params, ",")
			switch mode {
			case "search":
				searching.Search = TorznabSearchType{Available: "yes", SupportedParams: supportedParams}
			case "tv-search", "tvsearch":
				searching.TvSearch = TorznabSearchType{Available: "yes", SupportedParams: supportedParams}
			case "movie-search", "moviesearch":
				searching.MovieSearch = TorznabSearchType{Available: "yes", SupportedParams: supportedParams}
			}
		}

		caps = TorznabCaps{
			XMLName:    xml.Name{Local: "caps"},
			Server:     TorznabServer{Title: def.Name},
			Limits:     TorznabLimits{Max: 100, Default: 50},
			Searching:  searching,
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

// handleSearch performs the actual search and returns RSS (updated for unified cache)
func (h *APIHandler) handleSearch(w http.ResponseWriter, r *http.Request, indexerKey string) {
	originalQuery := r.URL.Query().Get("q")
	cleanQuery, filters := parseQueryAndFilters(originalQuery)

	searchParams := indexer.SearchParams{
		Query:    cleanQuery,
		Category: r.URL.Query().Get("cat"),
		IMDBID:   r.URL.Query().Get("imdbid"),
		TVDBID:   r.URL.Query().Get("tvdbid"),
		RID:      r.URL.Query().Get("rid"),
		GUID:     r.URL.Query().Get("guid"),
	}
	if s, err := strconv.Atoi(r.URL.Query().Get("season")); err == nil {
		searchParams.Season = s
	}
	if e, err := strconv.Atoi(r.URL.Query().Get("ep")); err == nil {
		searchParams.Episode = e
	}

	var results []indexer.SearchResult
	var err error
	var def *indexer.Definition

	if indexerKey == "all" {
		slog.Info("Torznab request", "indexer", "all", "query", searchParams.Query, "category", searchParams.Category)
		results, err = h.searchAll(searchParams)
		if err != nil {
			slog.Error("Torznab search failed for all indexers", "query", searchParams.Query, "error", err)
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

		if h.Cache != nil {
			// Check if we have cached RSS XML first
			if cachedXML, found := GetCachedRSSFeed(h.Cache, indexerKey, searchParams.Query, searchParams.Category); found {
				slog.Info("Torznab request served from RSS cache", "indexer", indexerKey, "query", searchParams.Query)
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.Header().Set("X-Cache", "HIT")
				w.Write(cachedXML)
				return
			}

			// Check unified cache for search results
			if cachedResults, found := GetCachedSearchResults(h.Cache, indexerKey, searchParams.Query, searchParams.Category); found {
				slog.Info("Torznab request served from unified cache", "indexer", indexerKey, "query", searchParams.Query)
				results = cachedResults
			}
		}

		if results == nil {
			slog.Info("Torznab request (cache miss)", "indexer", indexerKey, "query", searchParams.Query, "category", searchParams.Category)
			results, err = h.Manager.Search(r.Context(), indexerKey, searchParams)
			if err != nil {
				slog.Error("Torznab search failed", "indexer", indexerKey, "query", searchParams.Query, "error", err)
				http.Error(w, "Failed to search indexer.", http.StatusInternalServerError)
				return
			}
			// Cache the results
			if len(results) > 0 {
				if h.Cache != nil {
					CacheSearchResults(h.Cache, indexerKey, searchParams.Query, searchParams.Category, results, h.CacheTTL)
				}
			}
		}
	}

	// Apply server-side filtering and sorting
	results = applyQueryFilters(r, results)
	applyQuerySorting(r, results)

	if len(filters) > 0 {
		var filteredResults []indexer.SearchResult
		for _, result := range results {
			titleLower := strings.ToLower(result.Title)
			matchesAll := true
			for _, filter := range filters {
				if !strings.Contains(titleLower, filter) {
					matchesAll = false
					break
				}
			}
			if matchesAll {
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults
	}

	// Apply pagination to Torznab results
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

	// Generate RSS feed for the paginated results
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
	w.Header().Set("X-Cache", "MISS")
	w.Write(finalOutput)
}

// Legacy TorznabSearch for backward compatibility (if needed)
func (h *APIHandler) TorznabSearch(w http.ResponseWriter, r *http.Request) {
	h.TorznabAPI(w, r)
}

// TorznabLatest returns the pre-cached feed of latest releases from a scheduled job.
func (h *APIHandler) TorznabLatest(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("apikey")
	if apiKey != h.FlexgetAPIKey {
		slog.Warn("Invalid Torznab API key used for /latest endpoint", "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	indexerKey := chi.URLParam(r, "indexer")
	def, ok := h.Manager.GetIndexer(indexerKey)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Create an empty feed structure to return in case of cache miss
	feed := NewRSSFeed(def)

	if h.Cache != nil {
		cacheKey := GenerateLatestCacheKey(indexerKey)

		if cachedData, found := h.Cache.Get(cacheKey); found {
			var cachedResult CachedSearchResult
			if err := json.Unmarshal(cachedData, &cachedResult); err == nil {
				// --- START Log Enhancement ---
				slog.Info("Torznab latest request",
					"indexer", indexerKey,
					"cache_status", "HIT",
					"cache_updated_at", cachedResult.CachedAt.Format(time.RFC3339),
				)
				// --- END Log Enhancement ---

				// Populate the feed with cached results
				for _, result := range cachedResult.Results {
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
				w.Header().Set("X-Cache", "HIT")
			} else {
				slog.Warn("Torznab latest request: Failed to parse cached data", "indexer", indexerKey) // More specific log
				w.Header().Set("X-Cache", "MISS")
			}
		} else {
			// --- Log Enhancement ---
			slog.Info("Torznab latest request", "indexer", indexerKey, "cache_status", "MISS")
			// --- END Log Enhancement ---
			w.Header().Set("X-Cache", "MISS")
		}
	} else {
		slog.Info("Torznab latest request", "indexer", indexerKey, "cache_status", "DISABLED")
		w.Header().Set("X-Cache", "SKIP")
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

// --- START: New Filtering and Sorting Logic ---

// applyQueryFilters filters results based on query parameters like min_seeders and min_size.
func applyQueryFilters(r *http.Request, results []indexer.SearchResult) []indexer.SearchResult {
	q := r.URL.Query()
	var filteredResults []indexer.SearchResult

	minSeeders, _ := strconv.Atoi(q.Get("min_seeders"))
	minSize, _ := parseSize(q.Get("min_size"))

	if minSeeders == 0 && minSize == 0 {
		return results // No filters to apply
	}

	for _, result := range results {
		if result.Seeders < minSeeders {
			continue
		}
		if result.Size < minSize {
			continue
		}
		filteredResults = append(filteredResults, result)
	}
	return filteredResults
}

// applyQuerySorting sorts results based on query parameters, defaulting to seeders desc.
func applyQuerySorting(r *http.Request, results []indexer.SearchResult) {
	q := r.URL.Query()
	sortBy := q.Get("sort")
	orderBy := strings.ToLower(q.Get("order"))

	// Default to seeders descending
	if sortBy == "" {
		sortBy = "seeders"
		orderBy = "desc"
	}

	sort.SliceStable(results, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "size":
			less = results[i].Size < results[j].Size
		case "seeders":
			less = results[i].Seeders < results[j].Seeders
		case "leechers":
			less = results[i].Leechers < results[j].Leechers
		case "publishdate":
			less = results[i].PublishDate.Before(results[j].PublishDate)
		default:
			return false // No change in order
		}
		if orderBy == "desc" {
			return !less
		}
		return less
	})
}

// parseSize converts a human-readable size string (e.g., "1.5GB") to bytes.
func parseSize(s string) (int64, error) {
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`^(\d+(\.\d+)?)\s*(B|KB|MB|GB|TB)$`)
	matches := re.FindStringSubmatch(s)
	if len(matches) != 4 {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	size, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, err
	}

	unit := matches[3]
	var multiplier float64 = 1
	switch unit {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	case "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return int64(size * multiplier), nil
}

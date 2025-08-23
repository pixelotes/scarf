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
	Manager       *indexer.Manager
	Cache         *cache.Cache
	CacheTTL      time.Duration
	FlexgetAPIKey string
	UIPassword    string
	StartTime     time.Time
	rateLimiters  map[string]*rate.Limiter
	rlMutex       sync.RWMutex
}

// NewAPIHandler creates a new API handler with initialized rate limiters
func NewAPIHandler(manager *indexer.Manager, cache *cache.Cache, cacheTTL time.Duration, flexgetKey, uiPassword string) *APIHandler {
	return &APIHandler{
		Manager:       manager,
		Cache:         cache,
		CacheTTL:      cacheTTL,
		FlexgetAPIKey: flexgetKey,
		UIPassword:    uiPassword,
		StartTime:     time.Now(),
		rateLimiters:  make(map[string]*rate.Limiter),
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

// HealthCheck returns the health status of the application
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	allIndexers := h.Manager.GetAllIndexers()
	healthyIndexers := 0
	totalIndexers := 0

	for _, def := range allIndexers {
		if def.Enabled {
			totalIndexers++
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second) // Add a timeout for health checks
	defer cancel()

	count := 0
	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		if count >= 3 { // Limit to testing 3 indexers for speed
			break
		}
		if err := h.Manager.Test(ctx, key); err == nil {
			healthyIndexers++
		}
		count++
	}

	status := map[string]interface{}{
		"status":           "ok",
		"uptime":           time.Since(h.StartTime).String(),
		"total_indexers":   totalIndexers,
		"healthy_indexers": healthyIndexers,
		"cache_enabled":    h.Cache != nil,
		"timestamp":        time.Now().UTC(),
	}

	if healthyIndexers == 0 && totalIndexers > 0 {
		status["status"] = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
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
	Settings         []indexer.UserSetting     `json:"settings,omitempty"` // NEW: For dynamic forms
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
			Enabled:          bool(def.Enabled), // Corrected this line
			Settings:         def.Settings,      // Pass the form definition to the UI
			UserConfig:       def.UserConfig,    // Pass the current values to the UI
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

// searchAll performs a concurrent search across all indexers.
func (h *APIHandler) searchAll(query, category string) ([]indexer.SearchResult, error) {
	slog.Info("Starting aggregate search", "query", query, "category", category)
	allIndexers := h.Manager.GetAllIndexers()
	var wg sync.WaitGroup
	resultsChan := make(chan []indexer.SearchResult, len(allIndexers))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		wg.Add(1)
		go func(indexerKey string) {
			defer wg.Done()
			limiter := h.getRateLimiter(indexerKey)
			if !limiter.Allow() {
				slog.Warn("Rate limit exceeded during searchAll", "indexer", indexerKey)
				return
			}
			results, err := h.Manager.Search(ctx, indexerKey, query, category)
			if err != nil {
				if err == context.DeadlineExceeded {
					slog.Warn("Search timed out for indexer", "indexer", indexerKey)
				} else {
					slog.Warn("Search failed for indexer during searchAll", "indexer", indexerKey, "query", query, "error", err)
				}
				return
			}
			if len(results) > 0 {
				resultsChan <- results
			}
		}(key)
	}

	wg.Wait()
	close(resultsChan)

	uniqueResults := make(map[string]indexer.SearchResult)
	for resultSet := range resultsChan {
		for _, result := range resultSet {
			uniqueKey := fmt.Sprintf("%s-%d", result.Title, result.Size)
			if _, exists := uniqueResults[uniqueKey]; !exists {
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

// WebSearch now handles the "all" indexer case.
func (h *APIHandler) WebSearch(w http.ResponseWriter, r *http.Request) {
	indexerKey := r.URL.Query().Get("indexer")
	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("cat")

	slog.Info("Received web search request", "indexer", indexerKey, "query", query, "category", category)

	if indexerKey == "" {
		http.Error(w, `{"error": "indexer parameter is required"}`, http.StatusBadRequest)
		return
	}

	var results []indexer.SearchResult
	var err error

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
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
		// Handle the special "all" case with hardcoded categories
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

		// Hardcoded categories as requested: 2000, 2030, 2040, 5000, 5030, 5040
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
		// Handle individual indexer caps
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

	slog.Info("Received Torznab search request", "indexer", indexerKey, "query", query, "category", category)

	var results []indexer.SearchResult
	var err error
	var def *indexer.Definition

	if indexerKey == "all" {
		// Handle the special "all" case
		slog.Debug("Performing search across all indexers", "query", query, "category", category)
		results, err = h.searchAll(query, category)
		if err != nil {
			slog.Error("Torznab search failed for all indexers", "query", query, "error", err)
			http.Error(w, "Failed to search indexers.", http.StatusInternalServerError)
			return
		}
		// Create a fake definition for RSS generation
		def = &indexer.Definition{
			Name:        "All Indexers",
			Description: "Aggregated search across all enabled indexers",
			Language:    "en-US",
		}
	} else {
		// Handle individual indexer search
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
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.Header().Set("X-Cache", "HIT")
			w.Write(cachedXML)
			return
		}

		results, err = h.Manager.Search(r.Context(), indexerKey, query, category)
		if err != nil {
			slog.Error("Torznab search failed", "indexer", indexerKey, "query", query, "error", err)
			http.Error(w, "Failed to search indexer.", http.StatusInternalServerError)
			return
		}

		// Cache the results for individual indexers (but not for "all")
		defer func() {
			if indexerKey != "all" {
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

				if output, err := xml.MarshalIndent(feed, "", "  "); err == nil {
					finalOutput := []byte(xml.Header + string(output))
					h.Cache.Set(cacheKey, finalOutput, h.CacheTTL)
				}
			}
		}()
	}

	// Generate RSS feed for the results (works for both "all" and individual indexers)
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
	if indexerKey == "all" {
		w.Header().Set("X-Cache", "MISS") // Don't cache "all" results
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	w.Write(finalOutput)
}

// Legacy TorznabSearch for backward compatibility (if needed)
func (h *APIHandler) TorznabSearch(w http.ResponseWriter, r *http.Request) {
	h.TorznabAPI(w, r)
}

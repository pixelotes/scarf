package api

import (
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
		if limiter, exists = h.rateLimiters[indexerKey]; !exists {
			limiter = rate.NewLimiter(rate.Limit(1), 3)
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

	count := 0
	for key, def := range allIndexers {
		if !def.Enabled {
			continue
		}
		if count >= 3 {
			break
		}
		if err := h.Manager.Test(key); err == nil {
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
			Enabled:          def.Enabled,
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
			results, err := h.Manager.Search(indexerKey, query, category)
			if err != nil {
				slog.Warn("Search failed for indexer during searchAll", "indexer", indexerKey, "query", query, "error", err)
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
			if _, exists := uniqueResults[result.DownloadURL]; !exists {
				uniqueResults[result.DownloadURL] = result
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

	if indexerKey == "all" {
		results, err = h.searchAll(query, category)
	} else {
		limiter := h.getRateLimiter(indexerKey)
		if !limiter.Allow() {
			http.Error(w, `{"error": "Rate limit exceeded, please try again later"}`, http.StatusTooManyRequests)
			return
		}
		results, err = h.Manager.Search(indexerKey, query, category)
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

	err := h.Manager.Test(key)
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
	case "search":
		h.handleSearch(w, r, indexerKey)
	default:
		http.Error(w, fmt.Sprintf("Unsupported Torznab function: %s", torznabType), http.StatusBadRequest)
	}
}

// handleCaps returns the capabilities of an indexer
func (h *APIHandler) handleCaps(w http.ResponseWriter, r *http.Request, indexerKey string) {
	def, ok := h.Manager.GetIndexer(indexerKey)
	if !ok {
		slog.Warn("Indexer not found for caps request", "indexer", indexerKey)
		http.NotFound(w, r)
		return
	}

	slog.Debug("Generating caps for indexer", "indexer", indexerKey, "name", def.Name)

	caps := TorznabCaps{
		XMLName: xml.Name{Local: "caps"},
		Server: TorznabServer{
			Title: def.Name,
		},
		Limits: TorznabLimits{
			Max:     100,
			Default: 50,
		},
		Searching: TorznabSearching{
			Search: TorznabSearchType{
				Available:       "yes",
				SupportedParams: "q,cat",
			},
			TvSearch: TorznabSearchType{
				Available:       "yes",
				SupportedParams: "q,cat",
			},
			MovieSearch: TorznabSearchType{
				Available:       "yes",
				SupportedParams: "q,cat",
			},
		},
		Categories: TorznabCategories{
			Categories: []TorznabParentCategory{},
		},
	}

	// Group subcategories under their parents
	parentCategories := make(map[int]TorznabParentCategory)

	// Add defensive check for nil CategoryMappings
	if def.CategoryMappings != nil {
		for _, mapping := range def.CategoryMappings {
			if stdCat, ok := indexer.StandardCategories[mapping.TorznabCategory]; ok {
				parentID := (stdCat.ID / 1000) * 1000
				if parent, ok := indexer.StandardCategories[parentID]; ok {
					if _, exists := parentCategories[parentID]; !exists {
						parentCategories[parentID] = TorznabParentCategory{
							ID:     strconv.Itoa(parent.ID),
							Name:   parent.Name,
							Subcat: []TorznabSubCategory{}, // Initialize slice
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

	// Convert map to slice
	for _, pCat := range parentCategories {
		caps.Categories.Categories = append(caps.Categories.Categories, pCat)
	}

	slog.Debug("Generated caps structure", "indexer", indexerKey, "parent_categories", len(parentCategories))

	output, err := xml.MarshalIndent(caps, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal caps XML", "indexer", indexerKey, "error", err, "caps_structure", fmt.Sprintf("%+v", caps))
		http.Error(w, "Failed to generate caps XML", http.StatusInternalServerError)
		return
	}

	slog.Debug("Successfully generated caps XML", "indexer", indexerKey, "xml_length", len(output))

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(xml.Header + string(output)))
}

// handleSearch performs the actual search and returns RSS
func (h *APIHandler) handleSearch(w http.ResponseWriter, r *http.Request, indexerKey string) {
	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("cat")

	slog.Info("Received Torznab search request", "indexer", indexerKey, "query", query, "category", category)

	def, ok := h.Manager.GetIndexer(indexerKey)
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

	results, err := h.Manager.Search(indexerKey, query, category)
	if err != nil {
		slog.Error("Torznab search failed", "indexer", indexerKey, "query", query, "error", err)
		http.Error(w, "Failed to search indexer.", http.StatusInternalServerError)
		return
	}

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
	h.Cache.Set(cacheKey, finalOutput, h.CacheTTL)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("X-Cache", "MISS")
	w.Write(finalOutput)
}

// Legacy TorznabSearch for backward compatibility (if needed)
func (h *APIHandler) TorznabSearch(w http.ResponseWriter, r *http.Request) {
	h.TorznabAPI(w, r)
}

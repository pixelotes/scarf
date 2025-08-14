package api

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
	"sort"
	"sync"

	"go-indexer/auth"
	"go-indexer/cache"
	"go-indexer/indexer"

	"github.com/go-chi/chi/v5"
)

// APIHandler holds all dependencies for all API endpoints.
type APIHandler struct {
	Manager       *indexer.Manager
	Cache         *cache.Cache
	CacheTTL      time.Duration
	FlexgetAPIKey string
	UIPassword    string
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// ListIndexers returns a JSON list of available indexers for the UI.
func (h *APIHandler) ListIndexers(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(h.Manager.Indexers)
}

// searchAll performs a concurrent search across all indexers.
func (h *APIHandler) searchAll(query, category string) ([]indexer.SearchResult, error) {
	var wg sync.WaitGroup
	resultsChan := make(chan []indexer.SearchResult, len(h.Manager.Indexers))
	
	for key := range h.Manager.Indexers {
		wg.Add(1)
		go func(indexerKey string) {
			defer wg.Done()
			// We can ignore errors from individual indexers in an aggregate search
			results, err := h.Manager.Search(indexerKey, query, category)
			if err == nil && len(results) > 0 {
				resultsChan <- results
			}
		}(key)
	}

	wg.Wait()
	close(resultsChan)

	// De-duplicate results using the download URL as a unique key
	uniqueResults := make(map[string]indexer.SearchResult)
	for resultSet := range resultsChan {
		for _, result := range resultSet {
			if _, exists := uniqueResults[result.DownloadURL]; !exists {
				uniqueResults[result.DownloadURL] = result
			}
		}
	}

	// Convert map back to slice
	allResults := make([]indexer.SearchResult, 0, len(uniqueResults))
	for _, result := range uniqueResults {
		allResults = append(allResults, result)
	}
	
	// Sort results by publish date, newest first
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

	if indexerKey == "" {
		http.Error(w, `{"error": "indexer parameter is required"}`, http.StatusBadRequest)
		return
	}
	
	var results []indexer.SearchResult
	var err error

	if indexerKey == "all" {
		results, err = h.searchAll(query, category)
	} else {
		results, err = h.Manager.Search(indexerKey, query, category)
	}

	if err != nil {
		log.Printf("Error during web search on '%s': %v", indexerKey, err)
		http.Error(w, `{"error": "Failed to perform search on the selected indexer"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// TestIndexer runs a test search on an indexer.
func (h *APIHandler) TestIndexer(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("indexer")
	err := h.Manager.Test(key)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// GetFlexgetAPIKey returns the API key for Flexget configuration.
func (h *APIHandler) GetFlexgetAPIKey(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"key": h.FlexgetAPIKey})
}

// TorznabSearch handles Torznab/RSS feed requests.
func (h *APIHandler) TorznabSearch(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("apikey")
	if apiKey != h.FlexgetAPIKey {
		http.Error(w, "Invalid API Key", http.StatusUnauthorized)
		return
	}

	indexerKey := chi.URLParam(r, "indexer")
	query := r.URL.Query().Get("q")
	torznabType := r.URL.Query().Get("t")
	category := r.URL.Query().Get("cat")

	if torznabType == "" {
		http.Error(w, "Bad request: 't' parameter is required.", http.StatusBadRequest)
		return
	}

	def, ok := h.Manager.Indexers[indexerKey]
	if !ok {
		// Also handle "all" as a special case if needed in the future
		http.NotFound(w, r)
		return
	}

	cacheKeyHash := sha1.Sum([]byte(fmt.Sprintf("%s:%s:%s:%s", indexerKey, torznabType, query, category)))
	cacheKey := fmt.Sprintf("%x", cacheKeyHash)

	if cachedXML, found := h.Cache.Get(cacheKey); found {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("X-Cache", "HIT")
		w.Write(cachedXML)
		return
	}

	results, err := h.Manager.Search(indexerKey, query, category)
	if err != nil {
		log.Printf("Error searching indexer '%s' for '%s': %v", indexerKey, query, err)
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
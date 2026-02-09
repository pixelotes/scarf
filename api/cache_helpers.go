package api

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"go-indexer/cache"
	"go-indexer/indexer"
)

// GenerateCacheKey generates a standardized cache key for search results.
// It includes all search parameters to prevent cache collisions between different searches.
func GenerateCacheKey(indexerKey string, params indexer.SearchParams) string {
	// Include ALL search parameters to prevent collisions
	// For example: same query but different season/episode should have different cache keys
	keyStr := fmt.Sprintf("search:%s:%s:%s:%s:%d:%d",
		indexerKey,
		params.Query,
		params.Category,
		params.IMDBID,
		params.Season,
		params.Episode,
	)
	hash := sha1.Sum([]byte(keyStr))
	return fmt.Sprintf("%x", hash)
}

// GenerateLatestCacheKey generates a standardized cache key for scheduled job results.
func GenerateLatestCacheKey(indexerKey string) string {
	keyStr := fmt.Sprintf("latest:%s", indexerKey)
	hash := sha1.Sum([]byte(keyStr))
	return fmt.Sprintf("%x", hash)
}

// CachedSearchResult represents the standardized cached search data
type CachedSearchResult struct {
	Results    []indexer.SearchResult `json:"results"`
	CachedAt   time.Time              `json:"cached_at"`
	IndexerKey string                 `json:"indexer_key"`
	Query      string                 `json:"query"`
	Category   string                 `json:"category"`
	IMDBID     string                 `json:"imdbid,omitempty"`
	Season     int                    `json:"season,omitempty"`
	Episode    int                    `json:"episode,omitempty"`
}

// CacheSearchResults stores search results in a unified format with all search parameters.
func CacheSearchResults(c *cache.Cache, indexerKey string, params indexer.SearchParams, results []indexer.SearchResult, ttl time.Duration) {
	if len(results) == 0 {
		return // Don't cache empty results
	}

	cacheKey := GenerateCacheKey(indexerKey, params)
	cachedResult := CachedSearchResult{
		Results:    results,
		CachedAt:   time.Now(),
		IndexerKey: indexerKey,
		Query:      params.Query,
		Category:   params.Category,
		IMDBID:     params.IMDBID,
		Season:     params.Season,
		Episode:    params.Episode,
	}

	if jsonData, err := json.Marshal(cachedResult); err == nil {
		c.Set(cacheKey, jsonData, ttl)
	}
}

// GetCachedSearchResults retrieves cached search results using full search parameters.
func GetCachedSearchResults(c *cache.Cache, indexerKey string, params indexer.SearchParams) ([]indexer.SearchResult, bool) {
	cacheKey := GenerateCacheKey(indexerKey, params)

	if cachedData, found := c.Get(cacheKey); found {
		var cachedResult CachedSearchResult
		if err := json.Unmarshal(cachedData, &cachedResult); err == nil {
			return cachedResult.Results, true
		}
	}
	return nil, false
}

// CacheRSSFeed generates and caches an XML feed from search results (updated to use unified cache)
func CacheRSSFeed(c *cache.Cache, indexerKey string, params indexer.SearchParams, ttl time.Duration, def *indexer.Definition, results []indexer.SearchResult) {
	// First cache the raw results using unified structure
	CacheSearchResults(c, indexerKey, params, results, ttl)

	// Then cache the RSS XML format for direct Torznab responses
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
		return
	}

	// Cache RSS XML with a different key suffix
	rssKey := GenerateCacheKey(indexerKey, params) + ":rss"
	finalOutput := []byte(xml.Header + string(output))
	c.Set(rssKey, finalOutput, ttl)
}

// GetCachedRSSFeed retrieves cached RSS feed using full search parameters.
func GetCachedRSSFeed(c *cache.Cache, indexerKey string, params indexer.SearchParams) ([]byte, bool) {
	rssKey := GenerateCacheKey(indexerKey, params) + ":rss"
	return c.Get(rssKey)
}

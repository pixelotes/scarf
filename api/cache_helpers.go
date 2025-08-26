// api/cache_helpers.go - Unified cache structure

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

// CacheKey generates a standardized cache key for search results
func GenerateCacheKey(indexerKey, query, category string) string {
	// Always use the same key format regardless of search type
	keyStr := fmt.Sprintf("search:%s:%s:%s", indexerKey, query, category)
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
}

// CacheSearchResults stores search results in a unified format
func CacheSearchResults(c *cache.Cache, indexerKey, query, category string, results []indexer.SearchResult, ttl time.Duration) {
	if len(results) == 0 {
		return // Don't cache empty results
	}

	cacheKey := GenerateCacheKey(indexerKey, query, category)
	cachedResult := CachedSearchResult{
		Results:    results,
		CachedAt:   time.Now(),
		IndexerKey: indexerKey,
		Query:      query,
		Category:   category,
	}

	if jsonData, err := json.Marshal(cachedResult); err == nil {
		c.Set(cacheKey, jsonData, ttl)
	}
}

// GetCachedSearchResults retrieves cached search results
func GetCachedSearchResults(c *cache.Cache, indexerKey, query, category string) ([]indexer.SearchResult, bool) {
	cacheKey := GenerateCacheKey(indexerKey, query, category)

	if cachedData, found := c.Get(cacheKey); found {
		var cachedResult CachedSearchResult
		if err := json.Unmarshal(cachedData, &cachedResult); err == nil {
			return cachedResult.Results, true
		}
	}
	return nil, false
}

// CacheRSSFeed generates and caches an XML feed from search results (updated to use unified cache)
func CacheRSSFeed(c *cache.Cache, indexerKey, query, category string, ttl time.Duration, def *indexer.Definition, results []indexer.SearchResult) {
	// First cache the raw results using unified structure
	CacheSearchResults(c, indexerKey, query, category, results, ttl)

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
	rssKey := GenerateCacheKey(indexerKey, query, category) + ":rss"
	finalOutput := []byte(xml.Header + string(output))
	c.Set(rssKey, finalOutput, ttl)
}

// GetCachedRSSFeed retrieves cached RSS feed
func GetCachedRSSFeed(c *cache.Cache, indexerKey, query, category string) ([]byte, bool) {
	rssKey := GenerateCacheKey(indexerKey, query, category) + ":rss"
	return c.Get(rssKey)
}

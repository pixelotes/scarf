package api

import (
	"encoding/xml"
	"time"
	"go-indexer/cache"
	"go-indexer/indexer"
	"strconv"
)

// CacheRSSFeed generates and caches an XML feed from search results
func CacheRSSFeed(c *cache.Cache, key string, ttl time.Duration, def *indexer.Definition, results []indexer.SearchResult) {
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
		return // Cannot cache if marshalling fails
	}

	finalOutput := []byte(xml.Header + string(output))
	c.Set(key, finalOutput, ttl)
}
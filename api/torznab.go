package api

import (
	"encoding/xml"
	"go-indexer/indexer" // FIX: Added the missing import
)

// Torznab specific attribute
type TorznabAttr struct {
	XMLName xml.Name `xml:"torznab:attr"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}

// Enclosure is used for the torrent link
type Enclosure struct {
	XMLName xml.Name `xml:"enclosure"`
	URL     string   `xml:"url,attr"`
	Length  int64    `xml:"length,attr"`
	Type    string   `xml:"type,attr"`
}

// Item represents a single release in the feed
type Item struct {
	XMLName     xml.Name      `xml:"item"`
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	PublishDate string        `xml:"pubDate"`
	Size        int64         `xml:"size"`
	Enclosure   Enclosure     `xml:"enclosure"`
	Attrs       []TorznabAttr `xml:"torznab:attr"`
}

// Channel contains the list of items
type Channel struct {
	XMLName     xml.Name `xml:"channel"`
	Title       string   `xml:"title"`
	Description string   `xml:"description"`
	Language    string   `xml:"language"`
	Items       []Item   `xml:"item"`
}

// RSSFeed is the root element of the Torznab response
type RSSFeed struct {
	XMLName    xml.Name `xml:"rss"`
	Version    string   `xml:"version,attr"`
	XMLNS      string   `xml:"xmlns:torznab,attr"`
	Channel    Channel  `xml:"channel"`
}

// NewRSSFeed creates a new feed structure
func NewRSSFeed(def *indexer.Definition) *RSSFeed {
	return &RSSFeed{
		Version: "2.0",
		XMLNS:   "http://torznab.com/schemas/2012/xmlns",
		Channel: Channel{
			Title:       def.Name,
			Description: def.Description,
			Language:    def.Language,
			Items:       []Item{},
		},
	}
}
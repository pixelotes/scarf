package api

import (
	"encoding/xml"
	"go-indexer/indexer"
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
	XMLName xml.Name `xml:"rss"`
	Version string   `xml:"version,attr"`
	XMLNS   string   `xml:"xmlns:torznab,attr"`
	Channel Channel  `xml:"channel"`
}

// --- START: Fixed Torznab Capabilities Structures ---

type TorznabServer struct {
	XMLName xml.Name `xml:"server"`
	Title   string   `xml:"title,attr"`
}

type TorznabLimits struct {
	XMLName xml.Name `xml:"limits"`
	Max     int      `xml:"max,attr"`
	Default int      `xml:"default,attr"`
}

// Fixed: Remove XMLName from TorznabSearchType to avoid conflicts
type TorznabSearchType struct {
	Available       string `xml:"available,attr"`
	SupportedParams string `xml:"supportedParams,attr"`
}

type TorznabSearching struct {
	XMLName     xml.Name          `xml:"searching"`
	Search      TorznabSearchType `xml:"search"`
	TvSearch    TorznabSearchType `xml:"tv-search"`
	MovieSearch TorznabSearchType `xml:"movie-search"`
}

// TorznabSubCategory represents a <subcat> element.
type TorznabSubCategory struct {
	XMLName xml.Name `xml:"subcat"`
	ID      string   `xml:"id,attr"`
	Name    string   `xml:"name,attr"`
}

// TorznabParentCategory represents a <category> element which can contain subcategories.
type TorznabParentCategory struct {
	XMLName xml.Name             `xml:"category"`
	ID      string               `xml:"id,attr"`
	Name    string               `xml:"name,attr"`
	Subcat  []TorznabSubCategory `xml:"subcat,omitempty"`
}

// TorznabCategories is the root <categories> element.
type TorznabCategories struct {
	XMLName    xml.Name                `xml:"categories"`
	Categories []TorznabParentCategory `xml:"category"`
}

type TorznabCaps struct {
	XMLName    xml.Name          `xml:"caps"`
	Server     TorznabServer     `xml:"server"`
	Limits     TorznabLimits     `xml:"limits"`
	Searching  TorznabSearching  `xml:"searching"`
	Categories TorznabCategories `xml:"categories"`
}

// --- END: Fixed Torznab Capabilities Structures ---

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

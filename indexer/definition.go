package indexer

import (
	"go-indexer/indexer/cardigann"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Bool is a custom boolean type to handle unmarshaling from string or bool.
type Bool bool

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (b *Bool) UnmarshalYAML(value *yaml.Node) error {
	var val bool
	var err error

	// Try to unmarshal as a boolean first
	if err = value.Decode(&val); err == nil {
		*b = Bool(val)
		return nil
	}

	// If that fails, try to unmarshal as a string and parse it
	var s string
	if err = value.Decode(&s); err == nil {
		parsedBool, parseErr := strconv.ParseBool(s)
		if parseErr == nil {
			*b = Bool(parsedBool)
			return nil
		}
		return parseErr
	}

	return err
}

// UserSetting defines a single configurable field for the UI settings modal.
type UserSetting struct {
	Name    string            `yaml:"name" json:"name"`
	Type    string            `yaml:"type" json:"type"`
	Label   string            `yaml:"label" json:"label"`
	Default string            `yaml:"default" json:"default"`
	Options map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// Definition represents a single tracker's configuration
type Definition struct {
	Key              string            `yaml:"key" json:"-"`
	Name             string            `yaml:"name" json:"name"`
	Type             string            `yaml:"type" json:"type"`
	Enabled          Bool              `yaml:"enabled" json:"enabled"`
	Description      string            `yaml:"description" json:"-"`
	Language         string            `yaml:"language" json:"-"`
	Schedule         string            `yaml:"schedule" json:"-"`
	RateLimit        time.Duration     `yaml:"rate_limit,omitempty" json:"-"`
	Settings         []UserSetting     `yaml:"settings" json:"settings,omitempty"` // Defines the settings form
	UserConfig       map[string]string `yaml:"-" json:"user_config"`               // the user's saved values
	Source           string            `yaml:"-" json:"source"`                    // SourceLocal or SourceUpstream
	CategoryMappings []CategoryMapping `yaml:"category_mappings" json:"category_mappings"`
	// Modes lists the supported Torznab search modes and their parameters.
	Modes map[string][]string `yaml:"-" json:"-"`

	// Cardigann is the parsed definition; searches run through its engine.
	Cardigann *cardigann.Definition `yaml:"-" json:"-"`
}

// CategoryMapping maps an indexer's specific category ID to a standard Torznab category.
type CategoryMapping struct {
	IndexerCategory string `yaml:"indexer_cat" json:"indexer_cat"`
	TorznabCategory int    `yaml:"torznab_cat" json:"torznab_cat"`
}

// SearchResult holds data parsed from a tracker
type SearchResult struct {
	Title       string    `json:"Title"`
	DownloadURL string    `json:"DownloadURL"`
	Size        int64     `json:"Size"`
	Seeders     int       `json:"Seeders"`
	Leechers    int       `json:"Leechers"`
	PublishDate time.Time `json:"PublishDate"`
	Indexer     string    `json:"Indexer"`
	// IndexerKey and Proxied mark results whose link must go through the
	// download proxy (private trackers, download blocks).
	IndexerKey string `json:"IndexerKey,omitempty"`
	Proxied    bool   `json:"Proxied,omitempty"`
}

// Where a definition was loaded from.
const (
	SourceLocal    = "local"    // the definitions directory
	SourceUpstream = "upstream" // the downloaded upstream catalog
)

// SearchParams holds all possible search parameters from Torznab requests
type SearchParams struct {
	Query    string
	Category string
	IMDBID   string
	TVDBID   string
	RID      string
	Season   int
	Episode  int
	GUID     string
}

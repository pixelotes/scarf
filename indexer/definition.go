package indexer

import (
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

// Selector defines how to extract a piece of data, with an optional removal instruction.
type Selector struct {
	Selector string `yaml:"selector"`
	Remove   string `yaml:"remove,omitempty"`
}

// LoginDefinition describes how to authenticate with a tracker
type LoginDefinition struct {
	URL          string            `yaml:"url"`
	Method       string            `yaml:"method"`
	Body         map[string]string `yaml:"body"`
	SuccessCheck struct {
		Contains string `yaml:"contains"`
	} `yaml:"success_check"`
}

// FieldDefinition defines the selectors for each piece of data.
type FieldDefinition struct {
	Title       Selector `yaml:"title"`
	DownloadURL Selector `yaml:"download_url"`
	DetailsURL  Selector `yaml:"details_url"`
	Size        Selector `yaml:"size"`
	Seeders     Selector `yaml:"seeders"`
	Leechers    Selector `yaml:"leechers"`
	PublishDate Selector `yaml:"publish_date"`
}

// SearchDefinition defines how to query a tracker's API
type SearchDefinition struct {
	Type        string            `yaml:"type"`
	URLs        []string          `yaml:"urls"`
	Method      string            `yaml:"method"`
	Body        string            `yaml:"body"`
	ContentType string            `yaml:"content_type"`
	Params      map[string]string `yaml:"params"`
	Results     struct {
		Path             string          `yaml:"path"`
		SubPath          string          `yaml:"sub_path"`
		RowsSelector     string          `yaml:"rows_selector"`
		DownloadSelector string          `yaml:"download_selector"`
		Fields           FieldDefinition `yaml:"fields"`
	} `yaml:"results"`
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
	Settings         []UserSetting     `yaml:"settings" json:"settings,omitempty"` // Defines the settings form
	UserConfig       map[string]string `yaml:"-" json:"user_config"`               // Holds the user's saved values
	Login            LoginDefinition   `yaml:"login" json:"-"`
	Search           SearchDefinition  `yaml:"search" json:"-"`
	Categories       map[string]string `yaml:"categories" json:"-"`
	CategoryMappings []CategoryMapping `yaml:"category_mappings" json:"category_mappings"`
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
}

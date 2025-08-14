package indexer

import "time"

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
	Title       string `yaml:"title"`
	DownloadURL string `yaml:"download_url"`
	Size        string `yaml:"size"`
	Seeders     string `yaml:"seeders"`
	Leechers    string `yaml:"leechers"`
	PublishDate string `yaml:"publish_date"`
}

// SearchDefinition defines how to query a tracker's API
type SearchDefinition struct {
	Type        string            `yaml:"type"`
	URL         string            `yaml:"url"`
	Method      string            `yaml:"method"`
	Body        string            `yaml:"body"`
	ContentType string            `yaml:"content_type"` // NEW: To specify POST data format
	Params      map[string]string `yaml:"params"`
	Results     struct {
		Path         string          `yaml:"path"`
		SubPath      string          `yaml:"sub_path"`
		RowsSelector string          `yaml:"rows_selector"`
		Fields       FieldDefinition `yaml:"fields"`
	} `yaml:"results"`
}

// Definition represents a single tracker's configuration
type Definition struct {
	Key         string            `yaml:"key" json:"-"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"-"`
	Language    string            `yaml:"language" json:"-"`
	Schedule    string            `yaml:"schedule" json:"-"`
	UserConfig  map[string]string `yaml:"user_config" json:"-"`
	Login       LoginDefinition   `yaml:"login" json:"-"`
	Search      SearchDefinition  `yaml:"search" json:"-"`
	Categories  map[string]string `yaml:"categories" json:"categories"`
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
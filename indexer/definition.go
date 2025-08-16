package indexer

import "time"

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
	URLs        []string          `yaml:"urls"` // Cambiado de 'url' a 'urls' y de string a []string
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

// Definition represents a single tracker's configuration
type Definition struct {
	Key              string            `yaml:"key" json:"-"`
	Name             string            `yaml:"name" json:"name"`
	Description      string            `yaml:"description" json:"-"`
	Language         string            `yaml:"language" json:"-"`
	Schedule         string            `yaml:"schedule" json:"-"`
	UserConfig       map[string]string `yaml:"user_config" json:"-"`
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

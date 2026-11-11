// Package cardigann loads and runs indexer definitions written in the
// Cardigann format used by Jackett and Prowlarr.
//
// This is the phase 1 prototype described in docs/cardigann_migration_plan.md:
// HTML search for public indexers. Login, JSON responses and the download
// block are rejected at load time so a definition never half-works.
package cardigann

import (
	"fmt"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// Definition is a parsed Cardigann definition. Only the parts the prototype
// executes are modelled; unknown keys are ignored.
type Definition struct {
	ID           string    `yaml:"id"`
	Name         string    `yaml:"name"`
	Description  string    `yaml:"description"`
	Language     string    `yaml:"language"`
	Type         string    `yaml:"type"`
	Encoding     string    `yaml:"encoding"`
	RequestDelay float64   `yaml:"requestDelay"`
	Links        []string  `yaml:"links"`
	Caps         Caps      `yaml:"caps"`
	Settings     []Setting `yaml:"settings"`
	Login        *Login    `yaml:"login"`
	Download     *Download `yaml:"download"`
	Search       Search    `yaml:"search"`

	activeLink atomic.Int32 // index of the link that last worked
}

// Caps holds the indexer's category mappings and search modes.
type Caps struct {
	CategoryMappings []CategoryMapping   `yaml:"categorymappings"`
	Modes            map[string][]string `yaml:"modes"`
}

// CategoryMapping maps a site category ID to a Torznab category name such as "TV/Anime".
type CategoryMapping struct {
	ID   string `yaml:"id"`
	Cat  string `yaml:"cat"`
	Desc string `yaml:"desc"`
}

// Setting is one user-configurable value.
type Setting struct {
	Name    string            `yaml:"name"`
	Type    string            `yaml:"type"`
	Label   string            `yaml:"label"`
	Default string            `yaml:"default"`
	Options map[string]string `yaml:"options"`
}

// Search describes how to query the site and parse its results.
type Search struct {
	Paths           []Path            `yaml:"paths"`
	Path            string            `yaml:"path"` // older single-path form
	Inputs          map[string]string `yaml:"inputs"`
	Headers         map[string]any    `yaml:"headers"`
	KeywordsFilters []Filter          `yaml:"keywordsfilters"`
	Rows            Rows              `yaml:"rows"`
	Fields          Fields            `yaml:"fields"`
}

// Path is one request made for a search.
type Path struct {
	Path          string            `yaml:"path"`
	Method        string            `yaml:"method"`
	Inputs        map[string]string `yaml:"inputs"`
	InheritInputs *bool             `yaml:"inheritinputs"`
	Categories    []string          `yaml:"categories"`
	Response      struct {
		Type             string  `yaml:"type"`
		NoResultsMessage *string `yaml:"noResultsMessage"`
	} `yaml:"response"`
}

// Rows selects the result rows.
type Rows struct {
	Selector    string   `yaml:"selector"`
	After       int      `yaml:"after"`
	Remove      string   `yaml:"remove"`
	Filters     []Filter `yaml:"filters"`
	DateHeaders *Field   `yaml:"dateheaders"`
	// JSON only
	Attribute string `yaml:"attribute"`
	Multiple  bool   `yaml:"multiple"`
	Count     struct {
		Selector string `yaml:"selector"`
	} `yaml:"count"`
}

// Field extracts one value from a row.
type Field struct {
	Name      string
	Selector  string            `yaml:"selector"`
	Attribute string            `yaml:"attribute"`
	Remove    string            `yaml:"remove"`
	Text      *string           `yaml:"text"`
	Optional  bool              `yaml:"optional"`
	Default   *string           `yaml:"default"`
	Case      map[string]string `yaml:"case"`
	Filters   []Filter          `yaml:"filters"`
}

// Fields keeps the YAML order: later fields may read earlier ones via .Result.
type Fields []Field

// UnmarshalYAML decodes the fields mapping in document order.
func (f *Fields) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("fields: expected a mapping")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		var fld Field
		if err := n.Content[i+1].Decode(&fld); err != nil {
			return fmt.Errorf("field %q: %w", n.Content[i].Value, err)
		}
		fld.Name = n.Content[i].Value
		*f = append(*f, fld)
	}
	return nil
}

// Filter is a named transformation with arguments.
type Filter struct {
	Name string
	Args []string
}

// UnmarshalYAML accepts args as a scalar or a list of scalars.
func (f *Filter) UnmarshalYAML(n *yaml.Node) error {
	var raw struct {
		Name string    `yaml:"name"`
		Args yaml.Node `yaml:"args"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	f.Name = raw.Name
	switch raw.Args.Kind {
	case 0:
	case yaml.ScalarNode:
		f.Args = []string{raw.Args.Value}
	case yaml.SequenceNode:
		for _, a := range raw.Args.Content {
			f.Args = append(f.Args, a.Value)
		}
	default:
		return fmt.Errorf("filter %q: unsupported args", raw.Name)
	}
	return nil
}

// Parse decodes and validates a definition. It returns an error when the
// definition needs a feature the prototype does not run yet.
func Parse(data []byte) (*Definition, error) {
	var d Definition
	if err := Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("could not parse yaml: %w", err)
	}
	if d.ID == "" || len(d.Links) == 0 {
		return nil, fmt.Errorf("not a Cardigann definition: id and links are required")
	}
	if d.Search.Path != "" && len(d.Search.Paths) == 0 {
		d.Search.Paths = []Path{{Path: d.Search.Path}}
	}
	if err := d.checkSupported(); err != nil {
		return nil, fmt.Errorf("%s: %w", d.ID, err)
	}
	return &d, nil
}

// Unmarshal decodes YAML, accepting the "\/" escape that YAML 1.2 (and
// Jackett/Prowlarr's parser) allow in double-quoted strings but go-yaml does not.
func Unmarshal(data []byte, v any) error {
	err := yaml.Unmarshal(data, v)
	if err != nil && strings.Contains(err.Error(), "unknown escape") {
		err = yaml.Unmarshal(dropSlashEscapes(data), v)
	}
	return err
}

// dropSlashEscapes turns "\/" into "/" where the backslash is not itself escaped.
func dropSlashEscapes(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '\\' && i+1 < len(data) {
			if data[i+1] == '/' {
				out = append(out, '/')
			} else {
				out = append(out, data[i], data[i+1])
			}
			i++
			continue
		}
		out = append(out, data[i])
	}
	return out
}

// IsCardigann reports whether data looks like a Cardigann definition rather
// than Scarf's own format: Cardigann has top-level "id" and "links", Scarf has "key".
func IsCardigann(data []byte) bool {
	var probe struct {
		ID    string   `yaml:"id"`
		Key   string   `yaml:"key"`
		Links []string `yaml:"links"`
	}
	if err := Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Key == "" && probe.ID != "" && len(probe.Links) > 0
}

func (d *Definition) checkSupported() error {
	var missing []string
	if d.Login != nil {
		if d.Login.Captcha.Kind != 0 {
			missing = append(missing, "login captcha")
		}
		switch strings.ToLower(d.Login.Method) {
		case "", "post", "get", "form", "cookie":
		default:
			missing = append(missing, "login method "+d.Login.Method)
		}
	}
	for _, f := range d.Search.Rows.Filters {
		if f.Name != "andmatch" {
			missing = append(missing, "rows filter "+f.Name)
		}
	}
	if len(d.Search.Paths) == 0 {
		missing = append(missing, "search.paths (none defined)")
	}
	for _, p := range d.Search.Paths {
		if t := p.Response.Type; t != "" && t != "html" && t != "json" && t != "xml" {
			missing = append(missing, "response type "+t)
			break
		}
	}
	unknown := map[string]bool{}
	check := func(fs []Filter) {
		for _, f := range fs {
			if _, ok := filters[f.Name]; !ok {
				unknown[f.Name] = true
			}
		}
	}
	check(d.Search.KeywordsFilters)
	for _, f := range d.Search.Fields {
		check(f.Filters)
	}
	if dh := d.Search.Rows.DateHeaders; dh != nil {
		check(dh.Filters)
	}
	if d.Download != nil {
		for _, f := range d.Download.Selectors {
			check(f.Filters)
		}
		if ih := d.Download.Infohash; ih != nil {
			check(ih.Hash.Filters)
			check(ih.Title.Filters)
		}
	}
	if d.Login != nil {
		for _, f := range d.Login.SelectorInputs {
			check(f.Filters)
		}
		for _, e := range d.Login.Error {
			if e.Message != nil {
				check(e.Message.Filters)
			}
		}
	}
	for name := range unknown {
		missing = append(missing, "filter "+name)
	}
	if len(missing) > 0 {
		return fmt.Errorf("unsupported in this Scarf version: %s", strings.Join(missing, ", "))
	}
	return nil
}

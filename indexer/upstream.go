package indexer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go-indexer/indexer/cardigann"
)

// UpstreamSchema is the Cardigann schema version Scarf runs. Only definitions
// from this directory of the upstream repository are used.
const UpstreamSchema = "v11"

// DefaultUpstreamURL is Prowlarr's definitions repository as a tarball.
const DefaultUpstreamURL = "https://github.com/Prowlarr/Indexers/archive/refs/heads/master.tar.gz"

const (
	maxUpstreamArchive = 200 << 20 // compressed download
	maxUpstreamFile    = 1 << 20   // one definition
	maxUpstreamFiles   = 5000
)

var upstreamName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.yml$`)

// ErrUpstreamDisabled is returned when no upstream directory is configured.
var ErrUpstreamDisabled = errors.New("upstream catalog is disabled")

// CatalogEntry describes one upstream definition.
type CatalogEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Language    string `json:"language"`
	Type        string `json:"type"`
	Supported   bool   `json:"supported"`
	Reason      string `json:"reason,omitempty"` // why it is not supported
	Enabled     bool   `json:"enabled"`
	Local       bool   `json:"local"` // a local definition with this key takes precedence
}

// Catalog is the upstream catalog with its update time.
type Catalog struct {
	UpdatedAt time.Time      `json:"updated_at"`
	Entries   []CatalogEntry `json:"entries"`
}

// upstreamFile returns the path of the upstream definition for key, or "".
func (m *Manager) upstreamFile(key string) string {
	if m.upstreamDir == "" || !upstreamName.MatchString(key+".yml") {
		return ""
	}
	p := filepath.Join(m.upstreamDir, key+".yml")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// SyncUpstream downloads the upstream tarball and replaces the catalog with
// its definitions. Enabled upstream indexers are reloaded from the new files.
// It returns the number of definitions.
func (m *Manager) SyncUpstream(ctx context.Context) (int, error) {
	if m.upstreamDir == "" {
		return 0, ErrUpstreamDisabled
	}
	m.upstreamMu.Lock()
	defer m.upstreamMu.Unlock()

	url := m.upstreamURL
	if url == "" {
		url = DefaultUpstreamURL
	}
	slog.Info("Downloading upstream definitions", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download: status %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(m.upstreamDir), 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(m.upstreamDir), ".upstream-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	n, err := extractDefinitions(io.LimitReader(resp.Body, maxUpstreamArchive), tmp)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("no definitions/%s/*.yml found in the archive", UpstreamSchema)
	}

	// Swap the directories. No previous version is kept.
	old := m.upstreamDir + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(m.upstreamDir); err == nil {
		if err := os.Rename(m.upstreamDir, old); err != nil {
			return 0, err
		}
	}
	if err := os.Rename(tmp, m.upstreamDir); err != nil {
		os.Rename(old, m.upstreamDir)
		return 0, err
	}
	os.RemoveAll(old)

	m.mu.Lock()
	m.catalog = nil
	m.mu.Unlock()
	slog.Info("Upstream definitions updated", "count", n)
	if err := m.Reload(); err != nil {
		return n, err
	}
	return n, nil
}

// extractDefinitions writes the definitions/<schema>/*.yml entries of a
// gzipped tarball into dir, flattening paths and rejecting anything else.
func extractDefinitions(r io.Reader, dir string) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, fmt.Errorf("reading archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// Entries look like "Indexers-master/definitions/v11/nyaasi.yml".
		dirPart, name := path.Split(h.Name)
		if !strings.HasSuffix(dirPart, "definitions/"+UpstreamSchema+"/") || !upstreamName.MatchString(name) {
			continue
		}
		if h.Size > maxUpstreamFile {
			slog.Warn("Skipping oversized upstream definition", "file", name, "size", h.Size)
			continue
		}
		if n >= maxUpstreamFiles {
			return n, fmt.Errorf("archive has more than %d definitions", maxUpstreamFiles)
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return n, err
		}
		_, err = io.Copy(f, io.LimitReader(tr, maxUpstreamFile))
		f.Close()
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// UpstreamCatalog lists the downloaded upstream definitions. The list is
// built once per sync; definitions are parsed to report whether Scarf can
// run them, then discarded.
func (m *Manager) UpstreamCatalog() (Catalog, error) {
	if m.upstreamDir == "" {
		return Catalog{}, ErrUpstreamDisabled
	}
	var cat Catalog
	if info, err := os.Stat(m.upstreamDir); err == nil {
		cat.UpdatedAt = info.ModTime()
	} else {
		return cat, nil // not downloaded yet
	}

	m.mu.RLock()
	entries := m.catalog
	m.mu.RUnlock()
	if entries == nil {
		files, err := filepath.Glob(filepath.Join(m.upstreamDir, "*.yml"))
		if err != nil {
			return cat, err
		}
		entries = make([]CatalogEntry, 0, len(files))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			e := CatalogEntry{ID: strings.TrimSuffix(filepath.Base(f), ".yml")}
			var meta struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
				Language    string `yaml:"language"`
				Type        string `yaml:"type"`
			}
			if err := cardigann.Unmarshal(data, &meta); err != nil {
				e.Reason = err.Error()
			} else {
				e.Name, e.Description, e.Language, e.Type = meta.Name, meta.Description, meta.Language, meta.Type
				if _, err := cardigann.Parse(data); err != nil {
					e.Reason = strings.TrimPrefix(err.Error(), e.ID+": ")
				} else {
					e.Supported = true
				}
			}
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool { return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name) })
		m.mu.Lock()
		m.catalog = entries
		m.mu.Unlock()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	cat.Entries = make([]CatalogEntry, len(entries))
	for i, e := range entries {
		if def, ok := m.Indexers[e.ID]; ok {
			e.Enabled = bool(def.Enabled)
			e.Local = def.Source == SourceLocal
		}
		cat.Entries[i] = e
	}
	return cat, nil
}

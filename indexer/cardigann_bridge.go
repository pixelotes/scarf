package indexer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go-indexer/indexer/cardigann"

	"gopkg.in/yaml.v3"
)

// loadCardigann builds a Scarf Definition from a Cardigann (Jackett/Prowlarr)
// definition. Scarf-only state that the Cardigann format has no place for
// (the enabled flag) is read from extra top-level keys, which Jackett ignores.
func loadCardigann(data []byte) (*Definition, error) {
	cd, err := cardigann.Parse(data)
	if err != nil {
		return nil, err
	}
	var extra struct {
		Enabled Bool `yaml:"enabled"`
	}
	_ = yaml.Unmarshal(data, &extra)

	def := &Definition{
		Key:         cd.ID,
		Name:        cd.Name,
		Type:        cd.Type,
		Enabled:     extra.Enabled,
		Description: cd.Description,
		Language:    cd.Language,
		RateLimit:   time.Duration(cd.RequestDelay * float64(time.Second)),
		Cardigann:   cd,
	}
	def.Search.Type = "cardigann"
	def.Search.Modes = cd.Caps.Modes

	hasFlare := false
	for _, s := range cd.Settings {
		if strings.HasPrefix(s.Type, "info") || s.Name == "" {
			continue // informational text, no value
		}
		if s.Name == "use_flaresolverr" {
			hasFlare = true
		}
		def.Settings = append(def.Settings, UserSetting{
			Name: s.Name, Type: s.Type, Label: s.Label, Default: s.Default, Options: s.Options,
		})
	}
	if !hasFlare {
		def.Settings = append(def.Settings, UserSetting{
			Name: "use_flaresolverr", Type: "checkbox", Label: "Use FlareSolverr", Default: "false",
		})
	}

	byName := make(map[string]int, len(StandardCategories))
	for id, c := range StandardCategories {
		byName[strings.ToLower(c.Name)] = id
	}
	for _, cm := range cd.Caps.CategoryMappings {
		id, ok := byName[strings.ToLower(cm.Cat)]
		if !ok {
			slog.Debug("Unknown Torznab category in Cardigann definition", "indexer", cd.ID, "cat", cm.Cat)
			continue
		}
		def.CategoryMappings = append(def.CategoryMappings, CategoryMapping{IndexerCategory: cm.ID, TorznabCategory: id})
	}
	return def, nil
}

// searchCardigann runs a search for an indexer loaded from a Cardigann definition.
func (m *Manager) searchCardigann(ctx context.Context, def *Definition, params SearchParams, siteCats []string) ([]SearchResult, error) {
	doer := &cardigannDoer{m: m, def: def, client: m.getClient(def.Key)}
	res, err := def.Cardigann.Run(ctx, doer, cardigann.Query{
		Keywords:   params.Query,
		IMDBID:     params.IMDBID,
		TVDBID:     params.TVDBID,
		Season:     params.Season,
		Episode:    params.Episode,
		Categories: siteCats,
	}, def.UserConfig)
	if err != nil {
		m.recordFailure(def.Key)
		return nil, fmt.Errorf("search failed for indexer '%s': %w", def.Name, err)
	}
	m.recordSuccess(def.Key)

	out := make([]SearchResult, 0, len(res))
	for _, r := range res {
		out = append(out, SearchResult{
			Title:       r.Title,
			DownloadURL: r.Download,
			Size:        r.Size,
			Seeders:     r.Seeders,
			Leechers:    r.Leechers,
			PublishDate: r.PublishDate,
			Indexer:     def.Name,
		})
	}
	return out, nil
}

// cardigannDoer sends the engine's requests directly, or through FlareSolverr
// when the indexer's "Use FlareSolverr" setting is on.
type cardigannDoer struct {
	m      *Manager
	def    *Definition
	client *http.Client
}

func (d *cardigannDoer) Do(req *http.Request) (*http.Response, error) {
	if d.def.UserConfig["use_flaresolverr"] != "true" {
		return d.client.Do(req)
	}
	payload := map[string]interface{}{
		"cmd": "request." + strings.ToLower(req.Method),
		"url": req.URL.String(),
	}
	d.m.mu.RLock()
	if s := d.m.flaresolverrSessions[d.def.Key]; s != "" {
		payload["session"] = s
	}
	d.m.mu.RUnlock()
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		payload["postData"] = string(b)
	}
	if c := req.Header.Get("Cookie"); c != "" {
		payload["cookies"] = parseCookieString(c)
	}
	resp, err := d.m.executeFlareSolverrRequest(req.Context(), payload)
	if err == nil && resp.Request == nil {
		resp.Request = req
	}
	return resp, err
}

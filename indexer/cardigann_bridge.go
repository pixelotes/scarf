package indexer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-indexer/indexer/cardigann"

	"golang.org/x/net/publicsuffix"
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
	_ = cardigann.Unmarshal(data, &extra)

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

// cardigannLoginMu serialises logins so concurrent searches on a private
// tracker do not sign in twice.
var cardigannLoginMu sync.Mutex

// cardigannClient returns the HTTP client for an indexer. Indexers with a
// login block get their own client and cookie jar, signed in on first use.
func (m *Manager) cardigannClient(ctx context.Context, def *Definition) (*http.Client, error) {
	if !def.Cardigann.NeedsLogin() {
		return m.defaultClient, nil
	}
	cardigannLoginMu.Lock()
	defer cardigannLoginMu.Unlock()
	m.mu.RLock()
	c, ok := m.authClients[def.Key]
	m.mu.RUnlock()
	if ok {
		return c, nil
	}
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	c = newHttpClient(jar)
	slog.Info("Logging in", "indexer", def.Name, "method", def.Cardigann.Login.Method)
	if err := def.Cardigann.DoLogin(ctx, &cardigannDoer{m: m, def: def, client: c}, jar, def.UserConfig); err != nil {
		return nil, fmt.Errorf("login failed for indexer '%s': %w", def.Name, err)
	}
	slog.Info("Logged in", "indexer", def.Name)
	m.mu.Lock()
	m.authClients[def.Key] = c
	m.mu.Unlock()
	return c, nil
}

// forgetCardigannLogin drops an indexer's session so the next search signs in again.
func (m *Manager) forgetCardigannLogin(key string) {
	m.mu.Lock()
	delete(m.authClients, key)
	m.mu.Unlock()
}

// cardigannCategories maps a Torznab "cat" parameter ("2000,5040") to site
// categories. A parent category matches its subcategories. ok is false when
// categories were requested and the indexer has none of them, so the search
// is skipped instead of returning everything.
func cardigannCategories(def *Definition, param string) (cats []string, ok bool) {
	var want []int
	for _, p := range strings.Split(param, ",") {
		if id, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			want = append(want, id)
		}
	}
	if len(want) == 0 {
		return nil, true
	}
	seen := map[string]bool{}
	for _, m := range def.CategoryMappings {
		for _, w := range want {
			if m.TorznabCategory == w || (w%1000 == 0 && m.TorznabCategory/1000*1000 == w) {
				if !seen[m.IndexerCategory] {
					seen[m.IndexerCategory] = true
					cats = append(cats, m.IndexerCategory)
				}
			}
		}
	}
	return cats, len(cats) > 0
}

// searchCardigann runs a search for an indexer loaded from a Cardigann definition.
func (m *Manager) searchCardigann(ctx context.Context, def *Definition, params SearchParams, siteCats []string) ([]SearchResult, error) {
	q := cardigann.Query{
		Keywords:   params.Query,
		IMDBID:     params.IMDBID,
		TVDBID:     params.TVDBID,
		Season:     params.Season,
		Episode:    params.Episode,
		Categories: siteCats,
	}
	run := func() ([]cardigann.Result, error) {
		client, err := m.cardigannClient(ctx, def)
		if err != nil {
			return nil, err
		}
		return def.Cardigann.Run(ctx, &cardigannDoer{m: m, def: def, client: client}, q, def.UserConfig)
	}
	res, err := run()
	if errors.Is(err, cardigann.ErrLoginRequired) && def.Cardigann.NeedsLogin() {
		slog.Info("Session expired, logging in again", "indexer", def.Name)
		m.forgetCardigannLogin(def.Key)
		res, err = run()
	}
	if err != nil {
		m.recordFailure(def.Key)
		return nil, fmt.Errorf("search failed for indexer '%s': %w", def.Name, err)
	}
	m.recordSuccess(def.Key)

	proxy := def.Cardigann.NeedsLogin() || def.Cardigann.NeedsResolve()
	out := make([]SearchResult, 0, len(res))
	for _, r := range res {
		out = append(out, SearchResult{
			IndexerKey:  def.Key,
			Proxied:     proxy && !strings.HasPrefix(r.Download, "magnet:"),
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
	// Requests through FlareSolverr bypass the client's cookie jar, so the
	// session cookies from a login are passed along explicitly.
	var cookies []string
	if c := req.Header.Get("Cookie"); c != "" {
		cookies = append(cookies, c)
	}
	if d.client.Jar != nil {
		for _, c := range d.client.Jar.Cookies(req.URL) {
			cookies = append(cookies, c.Name+"="+c.Value)
		}
	}
	if len(cookies) > 0 {
		payload["cookies"] = parseCookieString(strings.Join(cookies, "; "))
	}
	resp, err := d.m.executeFlareSolverrRequest(req.Context(), payload)
	if err == nil && resp.Request == nil {
		resp.Request = req
	}
	return resp, err
}

// ErrIndexerNotFound is returned for an unknown or non-Cardigann indexer key.
var ErrIndexerNotFound = errors.New("indexer not found")

// Download resolves a proxied result link with the indexer's session. It
// returns either a magnet link to redirect to, or the .torrent response; the
// caller closes its body.
func (m *Manager) Download(ctx context.Context, key, link string) (string, *http.Response, error) {
	def, ok := m.GetIndexer(key)
	if !ok || def.Cardigann == nil {
		return "", nil, ErrIndexerNotFound
	}
	m.respectRateLimit(key, def)
	fetch := func() (string, *http.Response, error) {
		client, err := m.cardigannClient(ctx, def)
		if err != nil {
			return "", nil, err
		}
		doer := &cardigannDoer{m: m, def: def, client: client}
		target, err := def.Cardigann.ResolveDownload(ctx, doer, link, def.UserConfig)
		if err != nil {
			return "", nil, err
		}
		if strings.HasPrefix(target, "magnet:") {
			return target, nil, nil
		}
		// The .torrent itself is fetched directly: FlareSolverr returns page
		// text and would corrupt binary files.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("Referer", def.Cardigann.BaseURL(def.UserConfig))
		resp, err := client.Do(req)
		if err != nil {
			return "", nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return "", nil, fmt.Errorf("%s: status %s", target, resp.Status)
		}
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			resp.Body.Close()
			if def.Cardigann.NeedsLogin() {
				return "", nil, cardigann.ErrLoginRequired
			}
			return "", nil, fmt.Errorf("%s returned a web page, not a torrent", target)
		}
		return "", resp, nil
	}
	redirect, resp, err := fetch()
	if errors.Is(err, cardigann.ErrLoginRequired) && def.Cardigann.NeedsLogin() {
		m.forgetCardigannLogin(key)
		redirect, resp, err = fetch()
	}
	return redirect, resp, err
}

// check probes every tracker definition and emits a JSON report on stdout.
// Designed to be run from CI (see .github/workflows/tracker-status.yaml).
//
// All trackers are tested regardless of `enabled:` — most ship disabled by
// default. Trackers with `health_check.requires_auth: true` are not searched
// (we have no credentials in CI); we just probe the host and mark them yellow
// if reachable. Trackers with `health_check.skip: true` are skipped entirely.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	"go-indexer/indexer"
)

const (
	defaultQuery   = "1080p"
	probeUA        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	searchTimeout  = 30 * time.Second
	probeTimeout   = 15 * time.Second
	maxConcurrent  = 4
)

type Result struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Status    string `json:"status"` // green | yellow | red | skipped
	Results   int    `json:"results"`
	LatencyMs int64  `json:"latency_ms"`
	Note      string `json:"note,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	// Silence the manager's slog output so it doesn't pollute the JSON on stdout.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mgr, err := indexer.NewManager("./definitions", 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load definitions:", err)
		os.Exit(1)
	}

	defs := mgr.GetAllIndexers()
	results := make([]Result, 0, len(defs))

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	for _, def := range defs {
		wg.Add(1)
		sem <- struct{}{}
		go func(d *indexer.Definition) {
			defer wg.Done()
			defer func() { <-sem }()
			r := check(mgr, d)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(def)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, "encode error:", err)
		os.Exit(1)
	}
}

func check(mgr *indexer.Manager, def *indexer.Definition) (r Result) {
	r = Result{Key: def.Key, Name: def.Name, Enabled: bool(def.Enabled)}
	hc := def.HealthCheck

	if hc.Skip {
		r.Status = "skipped"
		r.Note = "skip: true in definition"
		return
	}

	start := time.Now()
	defer func() { r.LatencyMs = time.Since(start).Milliseconds() }()

	if hc.RequiresAuth {
		r.Status, r.Note, r.Error = probeHost(def)
		return r
	}

	query := hc.Query
	if query == "" {
		query = defaultQuery
	}

	// Manager.Search rejects disabled indexers, but the check tool must probe
	// every definition regardless. Flip the in-memory flag (the process is
	// short-lived; nothing persists).
	def.Enabled = true

	// Apply form defaults to UserConfig. Scarf only reads runtime flags
	// (e.g. use_flaresolverr) from UserConfig, not from the form default,
	// so without this step trackers that need FlareSolverr by default would
	// silently skip it during checks.
	if def.UserConfig == nil {
		def.UserConfig = map[string]string{}
	}
	for _, s := range def.Settings {
		if _, set := def.UserConfig[s.Name]; !set && s.Default != "" {
			def.UserConfig[s.Name] = s.Default
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
	defer cancel()

	searchResults, err := mgr.Search(ctx, def.Key, indexer.SearchParams{Query: query})
	if err != nil {
		r.Status = "red"
		r.Error = truncate(err.Error(), 200)
		return r
	}
	r.Results = len(searchResults)
	if r.Results == 0 {
		r.Status = "yellow"
		r.Note = "HTTP OK but 0 results — selectors may be stale"
	} else {
		r.Status = "green"
	}
	return r
}

// probeHost issues a GET against the host root of the first search URL and
// returns yellow if it responds 200 (best we can do without credentials).
func probeHost(def *indexer.Definition) (status, note, errStr string) {
	if len(def.Search.URLs) == 0 {
		return "red", "", "no search URLs in definition"
	}
	u, err := url.Parse(def.Search.URLs[0])
	if err != nil || u.Host == "" {
		return "red", "", "could not parse search URL"
	}
	probeURL := u.Scheme + "://" + u.Host + "/"

	client := &http.Client{Timeout: probeTimeout}
	req, _ := http.NewRequest(http.MethodGet, probeURL, nil)
	req.Header.Set("User-Agent", probeUA)
	resp, err := client.Do(req)
	if err != nil {
		return "red", "", truncate(err.Error(), 200)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "yellow", "auth required — host reachable", ""
	}
	return "red", "", fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

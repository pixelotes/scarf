package indexer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go-indexer/config"
	"go-indexer/indexer/cardigann"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Response body size limits to prevent DoS attacks via memory exhaustion
const (
	// MaxHTMLResponseSize is the maximum size for HTML pages (10MB)
	// This handles large HTML responses from scrapers
	MaxHTMLResponseSize = 10 * 1024 * 1024

	// MaxLogResponseSize is the maximum size for debug logging responses (100KB)
	MaxLogResponseSize = 100 * 1024
)

// limitedReadAll reads from a reader with a size limit to prevent DoS attacks.
// If the content exceeds the limit, it returns an error instead of consuming unlimited memory.
func limitedReadAll(reader io.Reader, maxBytes int64) ([]byte, error) {
	limitedReader := io.LimitReader(reader, maxBytes+1) // +1 to detect overflow
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	// Check if we hit the limit
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes", maxBytes)
	}

	return data, nil
}

// Manager holds all loaded indexer definitions and authenticated clients
type Manager struct {
	Indexers           map[string]*Definition
	authClients        map[string]*http.Client
	defaultClient      *http.Client
	flaresolverrClient *http.Client
	flaresolverrURL    string
	definitionsPath    string
	watcher            *fsnotify.Watcher
	reloadCallback     func()
	mu                 sync.RWMutex
	failureTimestamps  map[string][]time.Time
	lastRequest        map[string]time.Time
	maxFailures        int
	state              *StateStore
	upstreamDir        string
	upstreamURL        string
	upstreamMu         sync.Mutex // one catalog sync at a time
	catalog            []CatalogEntry
}

// ManagerOptions holds optional manager settings.
type ManagerOptions struct {
	// StatePath is the indexers.yml file with enabled flags and settings.
	// Empty keeps them in memory only.
	StatePath string
	// UpstreamDir holds downloaded upstream definitions. Empty disables
	// the upstream catalog.
	UpstreamDir string
	// UpstreamURL is the tarball to download the catalog from.
	UpstreamURL string
}

// newHttpClient creates a new HTTP client with our logging transport and custom TLS settings.
func newHttpClient(jar http.CookieJar) *http.Client {
	skipVerify := config.GetEnvAsBool("SKIP_TLS_VERIFY", false)
	if skipVerify {
		slog.Warn("TLS certificate verification is disabled. Use with caution.")
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipVerify},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   10,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     false,
	}

	return &http.Client{
		Jar:       jar,
		Timeout:   20 * time.Second,
		Transport: &loggingRoundTripper{proxied: transport},
	}
}

// NewManager creates a manager and loads definitions from a given path
func NewManager(definitionsPath string, maxFailures int, opts ManagerOptions) (*Manager, error) {
	state, err := NewStateStore(opts.StatePath)
	if err != nil {
		return nil, err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	flaresolverrURL := config.GetEnv("FLARESOLVERR_URL", "")
	var flaresolverrClient *http.Client
	if flaresolverrURL != "" {
		slog.Info("FlareSolverr is configured", "url", flaresolverrURL)
		flaresolverrClient = &http.Client{Timeout: 2 * time.Minute} // Longer timeout for FlareSolverr
	}

	m := &Manager{
		Indexers:           make(map[string]*Definition),
		authClients:        make(map[string]*http.Client),
		defaultClient:      newHttpClient(nil),
		flaresolverrClient: flaresolverrClient,
		flaresolverrURL:    flaresolverrURL,
		definitionsPath:    definitionsPath,
		watcher:            watcher,
		failureTimestamps:  make(map[string][]time.Time),
		lastRequest:        make(map[string]time.Time),
		maxFailures:        maxFailures,
		state:              state,
		upstreamDir:        opts.UpstreamDir,
		upstreamURL:        opts.UpstreamURL,
	}

	if err := m.Reload(); err != nil {
		return nil, err
	}

	go m.watchForChanges()

	if err := m.watcher.Add(definitionsPath); err != nil {
		slog.Warn("Could not start watching definitions path", "path", definitionsPath, "error", err)
	}

	return m, nil
}

func (m *Manager) recordSuccess(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// If there's a failure history, log that it's being cleared.
	if len(m.failureTimestamps[key]) > 0 {
		slog.Info("Indexer connection successful, resetting failure history", "indexer", key)
		delete(m.failureTimestamps, key) // Clear the history
	}
}

// recordFailure logs a failure and disables the indexer if the threshold is met within 24 hours.
func (m *Manager) recordFailure(key string) {
	// If auto-disable is turned off, do nothing.
	if m.maxFailures == 0 {
		return
	}

	m.mu.Lock()
	now := time.Now()
	// Append the current failure time.
	timestamps := append(m.failureTimestamps[key], now)

	// Filter out failures older than 24 hours.
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	recentFailures := []time.Time{}
	for _, ts := range timestamps {
		if ts.After(twentyFourHoursAgo) {
			recentFailures = append(recentFailures, ts)
		}
	}
	m.failureTimestamps[key] = recentFailures
	count := len(recentFailures)
	def, exists := m.Indexers[key]
	m.mu.Unlock()

	slog.Warn("Indexer request failed", "indexer", key, "recent_failure_count", count, "threshold", m.maxFailures)

	if exists && bool(def.Enabled) && count >= m.maxFailures {
		slog.Warn("Disabling indexer due to excessive failures within 24 hours", "indexer", key, "threshold", m.maxFailures)
		// Run in a goroutine to prevent blocking the caller
		// Note: We don't need to pass 'key' as it's already captured by the closure
		go func(indexerKey string) {
			if err := m.ToggleIndexerEnabled(indexerKey, false); err != nil {
				slog.Error("Failed to auto-disable indexer", "indexer", indexerKey, "error", err)
			} else {
				// Reset failure history only on successful disable
				// This is now safe because ToggleIndexerEnabled releases the lock before this executes
				m.mu.Lock()
				delete(m.failureTimestamps, indexerKey)
				m.mu.Unlock()
				slog.Info("Indexer auto-disabled and failure history cleared", "indexer", indexerKey)
			}
		}(key)
	}
}

// parseCookieString converts a standard cookie string into the format FlareSolverr expects.
func parseCookieString(cookieStr string) []map[string]string {
	var cookies []map[string]string
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		if cookieParts := strings.SplitN(strings.TrimSpace(part), "=", 2); len(cookieParts) == 2 {
			cookies = append(cookies, map[string]string{
				"name":  cookieParts[0],
				"value": cookieParts[1],
			})
		}
	}
	return cookies
}

// executeFlareSolverrRequest sends a request through the FlareSolverr proxy.
func (m *Manager) executeFlareSolverrRequest(ctx context.Context, payload map[string]interface{}) (*http.Response, error) {
	if m.flaresolverrClient == nil || m.flaresolverrURL == "" {
		return nil, fmt.Errorf("FlareSolverr is not configured")
	}

	jsonReq, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal FlareSolverr request: %w", err)
	}

	flareSolverrEndpoint := strings.TrimRight(m.flaresolverrURL, "/") + "/v1"

	req, err := http.NewRequestWithContext(ctx, "POST", flareSolverrEndpoint, bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, fmt.Errorf("failed to create FlareSolverr request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.flaresolverrClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to FlareSolverr: %w", err)
	}

	// The response body from FlareSolverr contains the actual response from the target site
	var flareResp struct {
		Solution struct {
			URL      string            `json:"url"`
			Status   int               `json:"status"`
			Headers  map[string]string `json:"headers"`
			Response string            `json:"response"`
			Cookies  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"cookies"`
		} `json:"solution"`
		Status  string `json:"status"`
		Session string `json:"session"`
		Message string `json:"message"`
	}

	// Use limited read to prevent DoS attacks via large responses
	bodyBytes, err := limitedReadAll(resp.Body, MaxHTMLResponseSize)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to read FlareSolverr response body: %w", err)
	}
	resp.Body.Close()

	if err := json.Unmarshal(bodyBytes, &flareResp); err != nil {
		slog.Error("Failed to decode FlareSolverr JSON response", "body", string(bodyBytes))
		return nil, fmt.Errorf("failed to decode FlareSolverr response: %w", err)
	}

	// Check the 'status' field for success, not the 'message' field.
	if flareResp.Status != "ok" {
		return nil, fmt.Errorf("FlareSolverr error: %s", flareResp.Message)
	}

	slog.Debug("Full response from FlareSolverr", "html_body", flareResp.Solution.Response)

	// Reconstruct the HTTP response from the FlareSolverr solution
	httpResp := &http.Response{
		StatusCode: flareResp.Solution.Status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(flareResp.Solution.Response)),
	}
	for k, v := range flareResp.Solution.Headers {
		httpResp.Header.Set(k, v)
	}

	// If using an authenticated client, update its cookie jar
	if sessionKey, ok := payload["session"].(string); ok {
		if client, ok := m.authClients[sessionKey]; ok {
			if u, err := url.Parse(flareResp.Solution.URL); err == nil {
				var cookies []*http.Cookie
				for _, c := range flareResp.Solution.Cookies {
					cookies = append(cookies, &http.Cookie{Name: c.Name, Value: c.Value})
				}
				client.Jar.SetCookies(u, cookies)
			}
		}
	}

	return httpResp, nil
}

// GetIndexer safely retrieves an indexer definition by key.
func (m *Manager) GetIndexer(key string) (*Definition, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	def, ok := m.Indexers[key]
	return def, ok
}

// Reload reads all YAML files from the definitions path and populates the manager
func (m *Manager) Reload() error {
	m.mu.Lock()

	slog.Info("Reloading all indexer definitions...")
	m.Indexers = make(map[string]*Definition)
	m.authClients = make(map[string]*http.Client)

	err := filepath.Walk(m.definitionsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
			if err := m.loadDefinition(path, SourceLocal); err != nil {
				slog.Warn("Skipping definition file due to error", "file", info.Name(), "error", err)
			}
		}
		return nil
	})
	// Upstream definitions are parsed only when enabled. A local file with
	// the same key wins.
	for _, key := range m.state.EnabledKeys() {
		if _, ok := m.Indexers[key]; ok {
			continue
		}
		if path := m.upstreamFile(key); path != "" {
			if err := m.loadDefinition(path, SourceUpstream); err != nil {
				slog.Warn("Skipping upstream definition due to error", "indexer", key, "error", err)
			}
		}
	}

	callback := m.reloadCallback
	count := len(m.Indexers)
	m.mu.Unlock()

	if err != nil {
		return fmt.Errorf("could not walk definitions path: %w", err)
	}

	if callback != nil {
		callback()
	}
	slog.Info("Indexer definitions reloaded", "count", count)
	return nil
}

// loadDefinition loads a single definition file and populates its UserConfig.
func (m *Manager) loadDefinition(path, source string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read file: %w", err)
	}

	if !cardigann.IsCardigann(data) {
		return fmt.Errorf("not a Cardigann definition (Scarf's old format is no longer supported; see docs/cardigann.md)")
	}
	cd, err := loadCardigann(data)
	if err != nil {
		return err
	}
	def := *cd

	def.Source = source

	// Initialize UserConfig and populate from settings defaults
	def.UserConfig = make(map[string]string)
	for _, setting := range def.Settings {
		def.UserConfig[setting.Name] = setting.Default
	}

	// The user's choices in indexers.yml override what the definition file
	// says (older Scarf versions wrote them into the file).
	if st, ok := m.state.Get(def.Key); ok {
		if st.Enabled != nil {
			def.Enabled = Bool(*st.Enabled)
		}
		for k, v := range st.Settings {
			def.UserConfig[k] = v
		}
	}

	// Override UserConfig with any environment variables
	for key := range def.UserConfig {
		envKey := strings.ToUpper(fmt.Sprintf("%s_%s", def.Key, key))
		if val, ok := os.LookupEnv(envKey); ok {
			def.UserConfig[key] = val
		}
	}

	if _, exists := m.Indexers[def.Key]; exists {
		slog.Warn("Duplicate indexer key found, skipping", "key", def.Key, "file", path)
		return nil
	}

	m.Indexers[def.Key] = &def
	slog.Info("Loaded indexer definition", "name", def.Name)
	return nil
}

// watchForChanges listens for events from the file watcher and triggers reloads
func (m *Manager) watchForChanges() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) {
				slog.Info("Change detected in definitions folder, reloading...", "event", event.String())
				if err := m.Reload(); err != nil {
					slog.Error("Error reloading definitions", "error", err)
				}
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("File watcher error", "error", err)
		}
	}
}

// GetAllIndexers returns the currently loaded indexer definitions
func (m *Manager) GetAllIndexers() map[string]*Definition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Indexers
}

// SetReloadCallback registers a function to be called after definitions are reloaded
func (m *Manager) SetReloadCallback(cb func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadCallback = cb
}

// Close stops the file watcher
func (m *Manager) Close() error {
	// Here you would also destroy any active FlareSolverr sessions
	// For simplicity, this is omitted, but in a production app, you'd loop through
	// m.flaresolverrSessions and send a 'sessions.destroy' command for each.
	return m.watcher.Close()
}

// UpdateIndexerUserConfig updates the default values in the 'settings' block of a definition file.
func (m *Manager) UpdateIndexerUserConfig(key string, config map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	def, ok := m.Indexers[key]
	if !ok {
		return fmt.Errorf("indexer not found: %s", key)
	}
	secret := map[string]bool{}
	for _, s := range def.Settings {
		if s.Type == "password" {
			secret[s.Name] = true
		}
	}
	changes := map[string]string{}
	for k, v := range config {
		if secret[k] && v == "" {
			continue // the UI never receives saved passwords: empty means unchanged
		}
		changes[k] = v
	}
	if err := m.state.SetSettings(key, changes); err != nil {
		return fmt.Errorf("could not save settings: %w", err)
	}
	for k, v := range changes {
		def.UserConfig[k] = v
	}
	delete(m.authClients, key) // credentials may have changed: sign in again
	slog.Info("Indexer settings updated", "indexer", key)
	return nil
}

// ToggleIndexerEnabled enables or disables an indexer and records it in the
// state file. Enabling an upstream definition loads it; disabling it unloads it.
func (m *Manager) ToggleIndexerEnabled(key string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	def, loaded := m.Indexers[key]
	upstream := m.upstreamFile(key)
	if !loaded && (!enabled || upstream == "") {
		return fmt.Errorf("indexer not found: %s", key)
	}
	if err := m.state.SetEnabled(key, enabled); err != nil {
		return fmt.Errorf("could not save state: %w", err)
	}
	switch {
	case !loaded:
		if err := m.loadDefinition(upstream, SourceUpstream); err != nil {
			_ = m.state.SetEnabled(key, false)
			return err
		}
	case !enabled && def.Source == SourceUpstream:
		delete(m.Indexers, key) // free the memory; enabling loads it again
		delete(m.authClients, key)
	default:
		def.Enabled = Bool(enabled)
	}
	slog.Info("Indexer enabled status updated", "indexer", key, "enabled", enabled)
	if m.reloadCallback != nil {
		go m.reloadCallback()
	}
	return nil
}

// Test performs a simple search to test if an indexer is working
func (m *Manager) Test(ctx context.Context, indexerKey string) error {
	_, err := m.Search(ctx, indexerKey, SearchParams{Query: "test"})
	if err != nil {
		m.recordFailure(indexerKey) // Record failure
		return err
	}
	m.recordSuccess(indexerKey) // Record success
	return nil
}

// GetFailureStats returns the number of recent failures for each indexer.
func (m *Manager) GetFailureStats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := make(map[string]int)
	for key, timestamps := range m.failureTimestamps {
		stats[key] = len(timestamps)
	}
	return stats
}

func (m *Manager) respectRateLimit(indexerKey string, def *Definition) {
	if def.RateLimit <= 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if last, ok := m.lastRequest[indexerKey]; ok {
		elapsed := time.Since(last)
		if elapsed < def.RateLimit {
			waitUntil := def.RateLimit - elapsed
			slog.Debug("Rate limit active, waiting", "indexer", indexerKey, "duration", waitUntil)
			time.Sleep(waitUntil)
		}
	}
	m.lastRequest[indexerKey] = time.Now()
}

// Search queries a specific indexer using the appropriate search mode.
func (m *Manager) Search(ctx context.Context, indexerKey string, params SearchParams) ([]SearchResult, error) {
	def, ok := m.GetIndexer(indexerKey)
	if !ok {
		return nil, fmt.Errorf("indexer '%s' not found", indexerKey)
	}

	if !bool(def.Enabled) {
		return nil, fmt.Errorf("indexer '%s' is disabled", indexerKey)
	}

	// Respect the indexer's rate limit
	m.respectRateLimit(indexerKey, def)

	slog.Debug("Starting search", "indexer", def.Name, "query", params.Query, "imdbid", params.IMDBID, "season", params.Season, "ep", params.Episode)

	cats, ok := cardigannCategories(def, params.Category)
	if !ok {
		return nil, nil // none of the requested categories exist on this indexer
	}
	return m.searchCardigann(ctx, def, params, cats)
}

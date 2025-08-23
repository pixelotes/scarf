package indexer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go-indexer/config"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

var (
	sizeRegex       = regexp.MustCompile(`(?i)(\d+(\.\d+)?)\s*(kb|mb|gb|tb)`)
	timeagoRegex    = regexp.MustCompile(`(\d+)\s+(min|hour|day|week|month|year)s?\s+ago`)
	timeagoDayRegex = regexp.MustCompile(`(?i)yesterday`)
	dateTimeRegex   = regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}`)
)

// Manager holds all loaded indexer definitions and authenticated clients
type Manager struct {
	Indexers             map[string]*Definition
	authClients          map[string]*http.Client
	defaultClient        *http.Client
	flaresolverrClient   *http.Client
	flaresolverrURL      string
	flaresolverrSessions map[string]string // New: Store for FlareSolverr sessions
	definitionsPath      string
	watcher              *fsnotify.Watcher
	reloadCallback       func()
	mu                   sync.RWMutex
}

// newHttpClient creates a new HTTP client with our logging transport and custom TLS settings.
func newHttpClient(jar http.CookieJar) *http.Client {
	skipVerify := config.GetEnvAsBool("INSECURE_SKIP_VERIFY", false)
	if skipVerify {
		slog.Warn("TLS certificate verification is disabled. Use with caution.")
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipVerify},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   10,
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
func NewManager(definitionsPath string) (*Manager, error) {
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
		Indexers:             make(map[string]*Definition),
		authClients:          make(map[string]*http.Client),
		defaultClient:        newHttpClient(nil),
		flaresolverrClient:   flaresolverrClient,
		flaresolverrURL:      flaresolverrURL,
		flaresolverrSessions: make(map[string]string),
		definitionsPath:      definitionsPath,
		watcher:              watcher,
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
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

	// Handle session creation response
	if cmd, ok := payload["cmd"].(string); ok && cmd == "sessions.create" {
		if flareResp.Session == "" {
			return nil, fmt.Errorf("FlareSolverr did not return a session ID")
		}
		// Store the session ID
		if sessionKey, ok := payload["session"].(string); ok {
			m.mu.Lock()
			m.flaresolverrSessions[sessionKey] = flareResp.Session
			m.mu.Unlock()
		}
	}

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

// ensureFlareSolverrSession creates and warms up a FlareSolverr session if one doesn't exist.
func (m *Manager) ensureFlareSolverrSession(ctx context.Context, def *Definition) error {
	m.mu.RLock()
	_, exists := m.flaresolverrSessions[def.Key]
	m.mu.RUnlock()

	if exists {
		return nil // Session already exists
	}

	slog.Info("Creating new FlareSolverr session", "indexer", def.Name)
	sessionID := uuid.New().String()

	// 1. Create the session
	createPayload := map[string]interface{}{
		"cmd":     "sessions.create",
		"session": sessionID,
	}
	// Add cookies to session creation if they are defined
	if cookie, ok := def.UserConfig["cookie"]; ok && cookie != "" {
		createPayload["cookies"] = parseCookieString(cookie)
	}

	_, err := m.executeFlareSolverrRequest(ctx, createPayload)
	if err != nil {
		return fmt.Errorf("failed to create FlareSolverr session: %w", err)
	}

	// 2. Warm up the session by visiting the login page to solve initial challenges
	slog.Debug("Warming up FlareSolverr session", "indexer", def.Name, "url", def.Login.URL)
	getPayload := map[string]interface{}{
		"cmd":     "request.get",
		"url":     def.Login.URL,
		"session": sessionID,
	}
	resp, err := m.executeFlareSolverrRequest(ctx, getPayload)
	if err != nil {
		return fmt.Errorf("failed to warm up FlareSolverr session: %w", err)
	}
	resp.Body.Close()

	m.mu.Lock()
	m.flaresolverrSessions[def.Key] = sessionID
	m.mu.Unlock()

	return nil
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
	// Do not clear FlareSolverr sessions on reload, they might still be valid

	err := filepath.Walk(m.definitionsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) {
			if err := m.loadDefinition(path); err != nil {
				slog.Warn("Skipping definition file due to error", "file", info.Name(), "error", err)
			}
		}
		return nil
	})

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
func (m *Manager) loadDefinition(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read file: %w", err)
	}

	var def Definition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return fmt.Errorf("could not parse yaml: %w", err)
	}

	// Initialize UserConfig and populate from settings defaults
	def.UserConfig = make(map[string]string)
	for _, setting := range def.Settings {
		def.UserConfig[setting.Name] = setting.Default
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

	filePath := m.findIndexerFile(key)
	if filePath == "" {
		return fmt.Errorf("definition file for %s not found", key)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("could not read definition file: %w", err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("could not unmarshal yaml: %w", err)
	}

	// Traverse the YAML to find the 'settings' block
	settingsNode := findNodeByKey(&node, "settings")
	if settingsNode == nil || settingsNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("'settings' block not found or not a sequence in %s", key)
	}

	// Iterate through each setting in the settings block
	for _, settingNode := range settingsNode.Content {
		if settingNode.Kind != yaml.MappingNode {
			continue
		}
		settingName := findNodeValueByKey(settingNode, "name")
		if newValue, ok := config[settingName]; ok {
			// Find the 'default' key and update its value
			updateNodeValueByKey(settingNode, "default", newValue)
		}
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&node); err != nil {
		return fmt.Errorf("could not marshal yaml: %w", err)
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("could not write definition file: %w", err)
	}
	return nil
}

// findIndexerFile locates the YAML file for a given indexer key.
func (m *Manager) findIndexerFile(key string) string {
	for _, ext := range []string{".yml", ".yaml"} {
		filePath := filepath.Join(m.definitionsPath, key+ext)
		if _, err := os.Stat(filePath); err == nil {
			return filePath
		}
	}
	return ""
}

// ToggleIndexerEnabled updates the enabled status of an indexer and saves it to the definition file.
func (m *Manager) ToggleIndexerEnabled(key string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	def, ok := m.Indexers[key]
	if !ok {
		return fmt.Errorf("indexer not found: %s", key)
	}

	filePath := m.findIndexerFile(key)
	if filePath == "" {
		return fmt.Errorf("definition file for %s not found", key)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("could not read definition file: %w", err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("could not unmarshal yaml: %w", err)
	}

	if rootNode := node.Content[0]; rootNode.Kind == yaml.MappingNode {
		updateNodeValueByKey(rootNode, "enabled", strconv.FormatBool(enabled))
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&node); err != nil {
		return fmt.Errorf("could not marshal yaml: %w", err)
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("could not write definition file: %w", err)
	}

	def.Enabled = Bool(enabled)
	return nil
}

// --- YAML Node Helpers ---
func findNodeByKey(node *yaml.Node, key string) *yaml.Node {
	if node.Kind == yaml.DocumentNode {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func findNodeValueByKey(node *yaml.Node, key string) string {
	if valueNode := findNodeByKey(node, key); valueNode != nil {
		return valueNode.Value
	}
	return ""
}

func updateNodeValueByKey(node *yaml.Node, key, value string) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1].SetString(value)
			return
		}
	}
	// If key doesn't exist, add it
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key})
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

// authenticate handles the login process for a tracker.
func (m *Manager) authenticate(def *Definition) error {
	key := def.Key
	m.mu.Lock()
	if _, ok := m.authClients[key]; ok {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	slog.Info("Authenticating", "indexer", def.Name)
	ctx := context.Background()

	useFlareSolverr := def.UserConfig["use_flaresolverr"] == "true"
	if useFlareSolverr {
		if err := m.ensureFlareSolverrSession(ctx, def); err != nil {
			return err
		}
	}

	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := newHttpClient(jar)
	m.mu.Lock()
	m.authClients[key] = client
	m.mu.Unlock()

	form := url.Values{}
	for k, vTpl := range def.Login.Body {
		val, _ := m.executeTemplate(vTpl, def.UserConfig)
		form.Set(k, val)
	}

	var resp *http.Response
	var err error

	if useFlareSolverr {
		m.mu.RLock()
		sessionID := m.flaresolverrSessions[key]
		m.mu.RUnlock()

		payload := map[string]interface{}{
			"cmd":      "request.post",
			"url":      def.Login.URL,
			"postData": form.Encode(),
			"session":  sessionID,
		}
		// Add cookies if they are defined in the settings
		if cookie, ok := def.UserConfig["cookie"]; ok && cookie != "" {
			payload["cookies"] = parseCookieString(cookie)
		}
		resp, err = m.executeFlareSolverrRequest(ctx, payload)
	} else {
		req, err_req := http.NewRequest(def.Login.Method, def.Login.URL, strings.NewReader(form.Encode()))
		if err_req != nil {
			return err_req
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		// Add custom headers for login, only if they are defined
		if def.Login.Headers != nil {
			for key, valTpl := range def.Login.Headers {
				val, _ := m.executeTemplate(valTpl, def.UserConfig)
				req.Header.Set(key, val)
			}
		}
		resp, err = client.Do(req)
	}

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if def.Login.SuccessCheck.Contains != "" && !strings.Contains(string(body), def.Login.SuccessCheck.Contains) {
		slog.Warn("Login failed, response did not contain success string", "indexer", def.Name, "expected", def.Login.SuccessCheck.Contains)
		return fmt.Errorf("login success check failed; did not find '%s' in response", def.Login.SuccessCheck.Contains)
	}

	slog.Info("Successfully authenticated", "indexer", def.Name)
	return nil
}

// getClient returns an authenticated client if available, otherwise the default client
func (m *Manager) getClient(key string) *http.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if client, ok := m.authClients[key]; ok {
		return client
	}
	return m.defaultClient
}

// Test performs a simple search to test if an indexer is working
func (m *Manager) Test(ctx context.Context, indexerKey string) error {
	_, err := m.Search(ctx, indexerKey, "test", "")
	return err
}

// Search queries a specific indexer.
func (m *Manager) Search(ctx context.Context, indexerKey, query, category string) ([]SearchResult, error) {
	def, ok := m.GetIndexer(indexerKey)
	if !ok {
		return nil, fmt.Errorf("indexer '%s' not found", indexerKey)
	}

	if !bool(def.Enabled) {
		return nil, fmt.Errorf("indexer '%s' is disabled", indexerKey)
	}

	if def.Login.URL != "" {
		if err := m.authenticate(def); err != nil {
			return nil, fmt.Errorf("authentication failed for indexer '%s': %w", def.Name, err)
		}
	}

	slog.Debug("Starting search", "indexer", def.Name, "query", query, "category", category)

	indexerCategory := category
	if catID, err := strconv.Atoi(category); err == nil {
		for _, mapping := range def.CategoryMappings {
			if mapping.TorznabCategory == catID {
				indexerCategory = mapping.IndexerCategory
				break
			}
		}
	}

	client := m.getClient(indexerKey)
	useFlareSolverr := def.UserConfig["use_flaresolverr"] == "true"
	tplData := struct {
		Query    string
		Config   map[string]string
		Category string
	}{query, def.UserConfig, indexerCategory}

	var lastErr error
	for _, urlTemplate := range def.Search.URLs {
		baseURL, err := m.executeTemplate(urlTemplate, tplData)
		if err != nil {
			lastErr = fmt.Errorf("invalid URL template '%s': %w", urlTemplate, err)
			continue
		}

		methodTpl := def.Search.Method
		if methodTpl == "" {
			methodTpl = "GET"
		}
		method, _ := m.executeTemplate(methodTpl, tplData)
		method = strings.ToUpper(method)

		var resp *http.Response
		var reqBody string

		if method == "POST" {
			bodyTpl := def.Search.Body
			bodyString, err := m.executeTemplate(bodyTpl, tplData)
			if err != nil {
				lastErr = fmt.Errorf("invalid body template: %w", err)
				continue
			}
			reqBody = bodyString
		} else { // GET
			u, _ := url.Parse(baseURL)
			q := u.Query()
			for key, valTpl := range def.Search.Params {
				val, err := m.executeTemplate(valTpl, tplData)
				if err != nil {
					q.Set(key, valTpl)
				} else {
					q.Set(key, val)
				}
			}
			u.RawQuery = q.Encode()
			baseURL = u.String()
		}

		if useFlareSolverr {
			if def.Login.URL != "" { // Ensure session exists for private trackers
				if err := m.ensureFlareSolverrSession(ctx, def); err != nil {
					return nil, err
				}
			}

			m.mu.RLock()
			sessionID := m.flaresolverrSessions[def.Key]
			m.mu.RUnlock()

			payload := map[string]interface{}{
				"cmd":     fmt.Sprintf("request.%s", strings.ToLower(method)),
				"url":     baseURL,
				"session": sessionID,
			}
			if method == "POST" {
				payload["postData"] = reqBody
			}
			// Add cookies if they are defined in the settings
			if cookie, ok := def.UserConfig["cookie"]; ok && cookie != "" {
				payload["cookies"] = parseCookieString(cookie)
			}
			resp, err = m.executeFlareSolverrRequest(ctx, payload)

		} else {
			req, err_req := http.NewRequestWithContext(ctx, method, baseURL, strings.NewReader(reqBody))
			if err_req != nil {
				lastErr = err_req
				continue
			}
			if method == "POST" {
				contentType := def.Search.ContentType
				if contentType == "" {
					contentType = "application/x-www-form-urlencoded"
				}
				req.Header.Set("Content-Type", contentType)
			}
			// Add custom search headers, only if they are defined
			if def.Search.Headers != nil {
				for key, valTpl := range def.Search.Headers {
					val, _ := m.executeTemplate(valTpl, tplData)
					req.Header.Set(key, val)
				}
			}
			resp, err = client.Do(req)
		}

		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("search request failed for %s: %w", baseURL, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			slog.Warn("Search failed with non-200 status",
				"indexer", def.Name,
				"url", baseURL,
				"status", resp.Status,
				"body", string(body),
			)
			lastErr = fmt.Errorf("search failed for %s, status: %s", baseURL, resp.Status)
			continue
		}

		switch def.Search.Type {
		case "json":
			return m.parseJSONResults(resp.Body, def)
		case "html":
			return m.parseHTMLResults(ctx, resp.Body, def, baseURL)
		default:
			return nil, fmt.Errorf("unsupported search type: '%s'", def.Search.Type)
		}
	}

	return nil, fmt.Errorf("all search attempts failed for indexer '%s', last error: %w", def.Name, lastErr)
}

// ... (The rest of the parsing helper functions remain unchanged)
func (m *Manager) extractText(s *goquery.Selection, selector Selector) string {
	selection := s.Find(selector.Selector)
	if selector.Remove != "" {
		selection.Find(selector.Remove).Remove()
	}
	return strings.TrimSpace(selection.Text())
}
func (m *Manager) extractAttr(s *goquery.Selection, selector Selector) string {
	parts := strings.Split(selector.Selector, "@")
	if len(parts) == 2 {
		val, _ := s.Find(parts[0]).Attr(parts[1])
		return val
	}
	return m.extractText(s, selector)
}
func (m *Manager) parseHTMLResults(ctx context.Context, body io.Reader, def *Definition, baseURL string) ([]SearchResult, error) {
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, err
	}
	fields := def.Search.Results.Fields
	var results []SearchResult
	var wg sync.WaitGroup
	resultsChan := make(chan SearchResult, 100)

	doc.Find(def.Search.Results.RowsSelector).Each(func(i int, s *goquery.Selection) {
		var sr SearchResult
		sr.Title = m.extractAttr(s, fields.Title)
		sr.Size = m.parseSize(m.extractText(s, fields.Size))
		sr.Seeders, _ = strconv.Atoi(m.extractText(s, fields.Seeders))
		sr.Leechers, _ = strconv.Atoi(m.extractText(s, fields.Leechers))

		dateStr := m.extractText(s, fields.PublishDate)
		if dateStr != "" {
			pubDate, err := parseFuzzyDate(dateStr)
			if err == nil {
				sr.PublishDate = pubDate
			}
		}

		detailsURL := m.absURL(baseURL, m.extractAttr(s, fields.DetailsURL))
		if detailsURL != "" && def.Search.Results.DownloadSelector != "" {
			wg.Add(1)
			go func(searchResult SearchResult, detailURL string) {
				defer wg.Done()
				downloadSelector := Selector{Selector: def.Search.Results.DownloadSelector}
				downloadURL, err := m.fetchDownloadLinkFromDetails(ctx, detailURL, downloadSelector, def)
				if err != nil {
					slog.Warn("Failed to fetch details page", "url", detailURL, "error", err)
					return
				}
				searchResult.DownloadURL = downloadURL
				if searchResult.Title != "" && searchResult.DownloadURL != "" {
					resultsChan <- searchResult
				}
			}(sr, detailsURL)
		} else {
			sr.DownloadURL = m.absURL(baseURL, m.extractAttr(s, fields.DownloadURL))
			if sr.Title != "" && sr.DownloadURL != "" {
				results = append(results, sr)
			}
		}
	})

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}
func (m *Manager) fetchDownloadLinkFromDetails(ctx context.Context, detailURL string, selector Selector, def *Definition) (string, error) {
	var resp *http.Response
	var err error
	useFlareSolverr := def.UserConfig["use_flaresolverr"] == "true"
	tplData := struct { // Define tplData for header templating
		Query    string
		Config   map[string]string
		Category string
	}{"", def.UserConfig, ""}

	if useFlareSolverr {
		m.mu.RLock()
		sessionID := m.flaresolverrSessions[def.Key]
		m.mu.RUnlock()
		payload := map[string]interface{}{
			"cmd":     "request.get",
			"url":     detailURL,
			"session": sessionID,
		}
		// Add cookies if they are defined in the settings
		if cookie, ok := def.UserConfig["cookie"]; ok && cookie != "" {
			payload["cookies"] = parseCookieString(cookie)
		}
		resp, err = m.executeFlareSolverrRequest(ctx, payload)
	} else {
		client := m.getClient(def.Key)
		req, err_req := http.NewRequestWithContext(ctx, "GET", detailURL, nil)
		if err_req != nil {
			return "", err_req
		}
		// Add custom search headers to details page request, only if they are defined
		if def.Search.Headers != nil {
			for key, valTpl := range def.Search.Headers {
				val, _ := m.executeTemplate(valTpl, tplData)
				req.Header.Set(key, val)
			}
		}
		resp, err = client.Do(req)
	}

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("details page returned status %s", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	downloadLink := m.extractAttr(doc.Selection, selector)
	if downloadLink == "" {
		return "", fmt.Errorf("download link not found with selector '%s'", selector.Selector)
	}

	return m.absURL(detailURL, downloadLink), nil
}
func (m *Manager) parseJSONResults(body io.Reader, def *Definition) ([]SearchResult, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	jsonBody := string(data)
	fields := def.Search.Results.Fields

	var results []SearchResult
	resultPath := def.Search.Results.Path
	if resultPath == "" {
		resultPath = "@this"
	}

	gjson.Get(jsonBody, resultPath).ForEach(func(key, parentValue gjson.Result) bool {
		parentRaw := make(map[string]interface{})
		parentValue.ForEach(func(k, v gjson.Result) bool {
			parentRaw[k.String()] = v.Value()
			return true
		})

		if def.Search.Results.SubPath == "" {
			processResult(m, parentValue, parentRaw, nil, fields, &results)
			return true
		}

		parentValue.Get(def.Search.Results.SubPath).ForEach(func(subKey, childValue gjson.Result) bool {
			processResult(m, childValue, nil, parentRaw, fields, &results)
			return true
		})

		return true
	})
	return results, nil
}
func processResult(m *Manager, resultValue gjson.Result, resultRaw, parentRaw map[string]interface{}, fields FieldDefinition, results *[]SearchResult) {
	if resultRaw == nil {
		resultRaw = make(map[string]interface{})
		resultValue.ForEach(func(k, v gjson.Result) bool {
			resultRaw[k.String()] = v.Value()
			return true
		})
	}

	templateContext := map[string]interface{}{
		"Result": resultRaw,
		"Parent": parentRaw,
	}

	var title string
	if strings.Contains(fields.Title.Selector, "{{") {
		title, _ = m.executeTemplate(fields.Title.Selector, templateContext)
	} else {
		title = resultValue.Get(fields.Title.Selector).String()
	}

	var downloadURL string
	if strings.Contains(fields.DownloadURL.Selector, "{{") {
		downloadURL, _ = m.executeTemplate(fields.DownloadURL.Selector, templateContext)
	} else {
		downloadURL = resultValue.Get(fields.DownloadURL.Selector).String()
	}

	size := resultValue.Get(fields.Size.Selector).Int()
	if size == 0 {
		size = m.parseSize(resultValue.Get(fields.Size.Selector).String())
	}

	pubDateStr := resultValue.Get(fields.PublishDate.Selector).String()
	pubDate, _ := parseFuzzyDate(pubDateStr)

	if title == "" || downloadURL == "" {
		return
	}

	*results = append(*results, SearchResult{
		Title:       title,
		DownloadURL: downloadURL,
		Size:        size,
		Seeders:     int(resultValue.Get(fields.Seeders.Selector).Int()),
		Leechers:    int(resultValue.Get(fields.Leechers.Selector).Int()),
		PublishDate: pubDate,
	})
}
func (m *Manager) executeTemplate(tplStr string, data any) (string, error) {
	if !strings.Contains(tplStr, "{{") {
		return tplStr, nil
	}

	var buf bytes.Buffer
	tpl, err := template.New("").Parse(tplStr)
	if err != nil {
		return "", err
	}
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
func (m *Manager) absURL(base, path string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return path
	}
	relURL, err := url.Parse(path)
	if err != nil {
		return path
	}
	return baseURL.ResolveReference(relURL).String()
}
func (m *Manager) parseSize(s string) int64 {
	s = strings.ReplaceAll(s, "\u00A0", " ")
	matches := sizeRegex.FindStringSubmatch(s)
	if len(matches) < 4 {
		return 0
	}
	val, _ := strconv.ParseFloat(matches[1], 64)
	unit := strings.ToLower(matches[3])
	var multiplier float64 = 1
	switch unit {
	case "kb":
		multiplier = 1024
	case "mb":
		multiplier = 1024 * 1024
	case "gb":
		multiplier = 1024 * 1024 * 1024
	case "tb":
		multiplier = 1024 * 1024 * 1024 * 1024
	}
	return int64(val * multiplier)
}
func parseFuzzyDate(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)
	now := time.Now()

	if strings.Contains(dateStr, "a.m.") || strings.Contains(dateStr, "p.m.") {
		cleanStr := strings.ReplaceAll(dateStr, ".", "")
		cleanStr = strings.Replace(cleanStr, "am", "AM", 1)
		cleanStr = strings.Replace(cleanStr, "pm", "PM", 1)
		layout := "Jan 2, 2006, 3:04 PM"
		if t, err := time.Parse(layout, cleanStr); err == nil {
			return t, nil
		}
	}

	if dateTimeMatch := dateTimeRegex.FindString(dateStr); dateTimeMatch != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", dateTimeMatch); err == nil {
			return t, nil
		}
	}

	if timeagoDayRegex.MatchString(dateStr) {
		return now.AddDate(0, 0, -1), nil
	}

	if matches := timeagoRegex.FindStringSubmatch(dateStr); len(matches) == 3 {
		value, _ := strconv.Atoi(matches[1])
		unit := matches[2]

		switch unit {
		case "min":
			return now.Add(-time.Duration(value) * time.Minute), nil
		case "hour":
			return now.Add(-time.Duration(value) * time.Hour), nil
		case "day":
			return now.AddDate(0, 0, -value), nil
		case "week":
			return now.AddDate(0, 0, -value*7), nil
		case "month":
			return now.AddDate(0, -value, 0), nil
		case "year":
			return now.AddDate(-value, 0, 0), nil
		}
	}

	if unixTime, err := strconv.ParseInt(dateStr, 10, 64); err == nil {
		if unixTime > 1e12 {
			return time.Unix(0, unixTime*int64(time.Millisecond)), nil
		}
		return time.Unix(unixTime, 0), nil
	}

	formats := []string{
		time.RFC3339, "2006-01-02 15:04:05", time.RFC1123, "Jan 2, 2006", time.RFC822,
	}
	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse date: %s", dateStr)
}

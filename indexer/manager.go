package indexer

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/tidwall/gjson"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

var (
	sizeRegex        = regexp.MustCompile(`(?i)(\d+(\.\d+)?)\s*(kb|mb|gb|tb)`)
	timeagoRegex     = regexp.MustCompile(`(\d+)\s+(min|hour|day|week|month|year)s?\s+ago`)
	timeagoDayRegex  = regexp.MustCompile(`(?i)yesterday`)
	dateTimeRegex    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}`)
)

// Manager holds all loaded indexer definitions and authenticated clients
type Manager struct {
	Indexers      map[string]*Definition
	authClients   map[string]*http.Client
	defaultClient *http.Client
}

// NewManager creates a manager and loads definitions from a given path
func NewManager(definitionsPath string) (*Manager, error) {
	m := &Manager{
		Indexers:      make(map[string]*Definition),
		authClients:   make(map[string]*http.Client),
		defaultClient: &http.Client{Timeout: 20 * time.Second},
	}

	files, err := os.ReadDir(definitionsPath)
	if err != nil {
		return nil, fmt.Errorf("could not read definitions directory: %w", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".yml") && !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(definitionsPath, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Warning: could not read file %s: %v", path, err)
			continue
		}

		var def Definition
		if err := yaml.Unmarshal(data, &def); err != nil {
			log.Printf("Warning: could not parse definition %s: %v", path, err)
			continue
		}

		for key := range def.UserConfig {
			envKey := strings.ToUpper(fmt.Sprintf("%s_%s", def.Key, key))
			if val, ok := os.LookupEnv(envKey); ok {
				def.UserConfig[key] = val
			}
		}

		m.Indexers[def.Key] = &def
		log.Printf("Loaded indexer definition: %s", def.Name)

		if def.Login.URL != "" {
			if err := m.authenticate(def.Key); err != nil {
				log.Printf("Warning: initial authentication failed for %s: %v", def.Name, err)
			}
		}
	}
	return m, nil
}

// authenticate handles the login process for a tracker
func (m *Manager) authenticate(key string) error {
	def := m.Indexers[key]
	log.Printf("Authenticating with %s...", def.Name)

	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{Jar: jar, Timeout: 20 * time.Second}

	form := url.Values{}
	for k, vTpl := range def.Login.Body {
		val, _ := m.executeTemplate(vTpl, def.UserConfig)
		form.Set(k, val)
	}

	req, err := http.NewRequest(def.Login.Method, def.Login.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if def.Login.SuccessCheck.Contains != "" && !strings.Contains(string(body), def.Login.SuccessCheck.Contains) {
		return fmt.Errorf("login success check failed; did not find '%s' in response", def.Login.SuccessCheck.Contains)
	}

	log.Printf("Successfully authenticated with %s", def.Name)
	m.authClients[key] = client
	return nil
}

// getClient returns an authenticated client if available, otherwise the default client
func (m *Manager) getClient(key string) *http.Client {
	if client, ok := m.authClients[key]; ok {
		return client
	}
	return m.defaultClient
}

// Test performs a simple search to test if an indexer is working
func (m *Manager) Test(indexerKey string) error {
	_, err := m.Search(indexerKey, "test", "")
	return err
}

// Search queries a specific indexer
// Search queries a specific indexer, with support for both GET and POST requests.
func (m *Manager) Search(indexerKey, query, category string) ([]SearchResult, error) {
	def, ok := m.Indexers[indexerKey]
	if !ok {
		return nil, fmt.Errorf("indexer '%s' not found", indexerKey)
	}

	client := m.getClient(indexerKey)
	tplData := struct {
		Query    string
		Config   map[string]string
		Category string
	}{query, def.UserConfig, category}

	// Determine method, defaulting to GET
	methodTpl := def.Search.Method
	if methodTpl == "" {
		methodTpl = "GET"
	}
	method, _ := m.executeTemplate(methodTpl, tplData)
	method = strings.ToUpper(method)

	baseURL, err := m.executeTemplate(def.Search.URL, tplData)
	if err != nil {
		return nil, fmt.Errorf("invalid URL template: %w", err)
	}

	var req *http.Request

	// Handle POST requests
	if method == "POST" {
		bodyTpl := def.Search.Body
		bodyString, err := m.executeTemplate(bodyTpl, tplData)
		if err != nil {
			return nil, fmt.Errorf("invalid body template: %w", err)
		}
		
		req, err = http.NewRequest("POST", baseURL, strings.NewReader(bodyString))
		if err != nil {
			return nil, err
		}
		
		contentType := def.Search.ContentType
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded" // Default content type
		}
		req.Header.Set("Content-Type", contentType)
	} else { // Handle GET requests
		req, err = http.NewRequest("GET", baseURL, nil)
		if err != nil {
			return nil, err
		}
		
		q := req.URL.Query()
		for key, valTpl := range def.Search.Params {
			// Try to execute as template, if it fails, use the raw string value
			val, err := m.executeTemplate(valTpl, tplData)
			if err != nil {
				q.Set(key, valTpl)
			} else {
				q.Set(key, val)
			}
		}

		if category != "" {
			if catVal, ok := def.Categories[category]; ok {
				q.Set("cat", catVal)
			} else {
				q.Set("cat", category)
			}
		}
		req.URL.RawQuery = q.Encode()
	}

	// This part is the same for both GET and POST
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed, status: %s, body: %s", resp.Status, body)
	}

	switch def.Search.Type {
	case "json":
		return m.parseJSONResults(resp.Body, def)
	case "html":
		return m.parseHTMLResults(resp.Body, def)
	default:
		return nil, fmt.Errorf("unsupported search type: '%s'", def.Search.Type)
	}
}

// parseJSONResults processes a JSON API response with support for nested results.
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

// processResult is a helper to parse a single result item (child) with access to its parent data.
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

	// This is the new, robust logic for handling fields.
	var title string
	if strings.Contains(fields.Title, "{{") {
		title, _ = m.executeTemplate(fields.Title, templateContext)
	} else {
		title = resultValue.Get(fields.Title).String()
	}

	var downloadURL string
	if strings.Contains(fields.DownloadURL, "{{") {
		downloadURL, _ = m.executeTemplate(fields.DownloadURL, templateContext)
	} else {
		downloadURL = resultValue.Get(fields.DownloadURL).String()
	}

	size := resultValue.Get(fields.Size).Int()
	if size == 0 {
		size = m.parseSize(resultValue.Get(fields.Size).String())
	}
	
	pubDateStr := resultValue.Get(fields.PublishDate).String()
	pubDate, _ := parseFuzzyDate(pubDateStr)

	// Do not add results that don't have a title
	if title == "" {
		return
	}

	*results = append(*results, SearchResult{
		Title:       title,
		DownloadURL: downloadURL,
		Size:        size,
		Seeders:     int(resultValue.Get(fields.Seeders).Int()),
		Leechers:    int(resultValue.Get(fields.Leechers).Int()),
		PublishDate: pubDate,
	})
}

// parseHTMLResults processes an HTML page response using goquery
func (m *Manager) parseHTMLResults(body io.Reader, def *Definition) ([]SearchResult, error) {
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, err
	}
	fields := def.Search.Results.Fields
	var results []SearchResult

	doc.Find(def.Search.Results.RowsSelector).Each(func(i int, s *goquery.Selection) {
		var sr SearchResult
		sr.Title = strings.TrimSpace(s.Find(fields.Title).Text())
		sr.DownloadURL = m.absURL(def.Search.URL, m.extractAttr(s, fields.DownloadURL))
		sr.Size = m.parseSize(s.Find(fields.Size).Text())

		// FIX: Handle static seeders/leechers defined as numbers in the YAML
		seeders, err := strconv.Atoi(fields.Seeders)
		if err != nil {
			seeders, _ = strconv.Atoi(s.Find(fields.Seeders).Text())
		}
		sr.Seeders = seeders

		leechers, err := strconv.Atoi(fields.Leechers)
		if err != nil {
			leechers, _ = strconv.Atoi(s.Find(fields.Leechers).Text())
		}
		sr.Leechers = leechers
		// END FIX

		dateStr := m.extractAttr(s, fields.PublishDate)
		if dateStr != "" {
			pubDate, err := parseFuzzyDate(dateStr)
			if err == nil {
				sr.PublishDate = pubDate
			}
		}

		if sr.Title != "" && sr.DownloadURL != "" {
			results = append(results, sr)
		}
	})
	return results, nil
}

// --- Helper Functions ---

// executeTemplate now gracefully handles non-template strings.
func (m *Manager) executeTemplate(tplStr string, data any) (string, error) {
	// If it doesn't look like a template, just return the raw string.
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

func (m *Manager) extractAttr(s *goquery.Selection, field string) string {
	parts := strings.Split(field, "@")
	if len(parts) == 2 {
		val, _ := s.Find(parts[0]).Attr(parts[1])
		return val
	}
	return s.Find(field).Text()
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

	// NEW: Handle Shana Project's specific format
	if strings.Contains(dateStr, "a.m.") || strings.Contains(dateStr, "p.m.") {
		// Clean up the string: remove periods, replace "a.m." with "AM"
		cleanStr := strings.ReplaceAll(dateStr, ".", "")
		cleanStr = strings.Replace(cleanStr, "am", "AM", 1)
		cleanStr = strings.Replace(cleanStr, "pm", "PM", 1)
		
		// Define the layout Go uses to parse this format
		// "Jan 2, 2006, 3:04 PM" corresponds to "MMM d, yyyy, h:mm AM/PM"
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
		return time.Unix(unixTime, 0), nil
	}

	formats := []string{
		time.RFC3339, "2006-01-02 15:04:05", time.RFC1123, "Jan 2, 2006",
	}
	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse date: %s", dateStr)
}
package cardigann

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/htmlindex"
)

// Query is what Scarf asks an indexer for.
type Query struct {
	Keywords   string
	IMDBID     string
	TVDBID     string
	Season     int
	Episode    int
	Categories []string // site category IDs, already mapped from Torznab
}

// Result is one release found by a search.
type Result struct {
	Title       string
	Details     string
	Download    string // .torrent URL or magnet link
	Size        int64
	Seeders     int
	Leechers    int
	Grabs       int
	PublishDate time.Time
	Category    string // site category ID
}

// Doer sends HTTP requests. *http.Client satisfies it; Scarf passes an
// adapter that routes through FlareSolverr when the indexer asks for it.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// MaxBodySize caps how much of a results page is read.
const MaxBodySize = 10 << 20

// Run runs every matching search path and returns the merged, de-duplicated results.
func (d *Definition) Run(ctx context.Context, client Doer, q Query, config map[string]string) ([]Result, error) {
	bases := d.candidateLinks(config)
	var lastErr error
	for i, base := range bases {
		res, err := d.runOnce(ctx, client, base, q, config)
		if err == nil {
			if i > 0 {
				d.setActiveLink(base)
			}
			return res, nil
		}
		lastErr = err
		if errors.Is(err, ErrLoginRequired) || ctx.Err() != nil {
			break // a mirror will not fix these
		}
	}
	return nil, lastErr
}

// candidateLinks lists the site links to try: the "sitelink" setting alone
// when the user set one, else every link starting with the last one that worked.
func (d *Definition) candidateLinks(config map[string]string) []string {
	if s := strings.TrimSpace(config["sitelink"]); s != "" {
		return []string{ensureSlash(s)}
	}
	start := int(d.activeLink.Load())
	out := make([]string, 0, len(d.Links))
	for i := range d.Links {
		out = append(out, ensureSlash(d.Links[(start+i)%len(d.Links)]))
	}
	return out
}

func (d *Definition) setActiveLink(base string) {
	for i, l := range d.Links {
		if ensureSlash(l) == base {
			d.activeLink.Store(int32(i))
			return
		}
	}
}

func (d *Definition) runOnce(ctx context.Context, client Doer, base string, q Query, config map[string]string) ([]Result, error) {
	tctx := d.newContext(q, config)
	tctx.Config["sitelink"] = base

	kw, err := applyFilters(tctx.Keywords, d.Search.KeywordsFilters, tctx)
	if err != nil {
		return nil, fmt.Errorf("keywordsfilters: %w", err)
	}
	tctx.Keywords = strings.TrimSpace(kw)
	tctx.Query["Keywords"] = tctx.Keywords

	var (
		results []Result
		seen    = map[string]bool{}
		lastErr error
		ran     int
	)
	for _, p := range d.Search.Paths {
		if !pathMatches(p, q.Categories) {
			continue
		}
		ran++
		rs, err := d.runPath(ctx, client, base, p, tctx)
		if err != nil {
			lastErr = err
			continue
		}
		for _, r := range rs {
			key := r.Download
			if key == "" {
				key = r.Title
			}
			if !seen[key] {
				seen[key] = true
				results = append(results, r)
			}
		}
	}
	if ran == 0 {
		return nil, nil
	}
	if len(results) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return results, nil
}

// BaseURL is the site link to use: the "sitelink" setting when set, else the
// link that last worked (the first one until a search falls back).
func (d *Definition) BaseURL(config map[string]string) string {
	return d.candidateLinks(config)[0]
}

func ensureSlash(s string) string {
	if !strings.HasSuffix(s, "/") {
		return s + "/"
	}
	return s
}

func pathMatches(p Path, cats []string) bool {
	if len(p.Categories) == 0 || len(cats) == 0 {
		return true
	}
	for _, want := range p.Categories {
		for _, c := range cats {
			if want == c {
				return true
			}
		}
	}
	return false
}

func (d *Definition) newContext(q Query, config map[string]string) *Context {
	cfg := make(map[string]string, len(config)+1)
	for _, s := range d.Settings {
		v, ok := config[s.Name]
		if !ok {
			v = s.Default
		}
		if s.Type == "checkbox" {
			// Cardigann templates test checkboxes with {{ if .Config.x }},
			// so false must be the empty string.
			if b, _ := strconv.ParseBool(v); b {
				v = ".True"
			} else {
				v = ""
			}
		}
		cfg[s.Name] = v
	}
	for k, v := range config {
		if _, ok := cfg[k]; !ok {
			cfg[k] = v
		}
	}
	cfg["sitelink"] = d.BaseURL(config)

	keywords := q.Keywords
	season, ep := "", ""
	if q.Season > 0 {
		season = strconv.Itoa(q.Season)
		if q.Episode > 0 {
			ep = strconv.Itoa(q.Episode)
			keywords = strings.TrimSpace(fmt.Sprintf("%s S%02dE%02d", keywords, q.Season, q.Episode))
		} else {
			keywords = strings.TrimSpace(fmt.Sprintf("%s S%02d", keywords, q.Season))
		}
	}
	imdb := q.IMDBID
	if imdb != "" && !strings.HasPrefix(imdb, "tt") {
		imdb = "tt" + imdb
	}
	return &Context{
		Keywords: keywords,
		Query: QueryVars{
			"Q": q.Keywords, "Keywords": keywords, "Type": queryType(q), "Season": season, "Ep": ep,
			"IMDBID": imdb, "IMDBIDShort": strings.TrimPrefix(imdb, "tt"), "TVDBID": q.TVDBID,
			"Limit": "100", "Offset": "0",
		},
		Config:     cfg,
		Categories: q.Categories,
	}
}

// queryType is Torznab's search type, which some definitions branch on.
func queryType(q Query) string {
	switch {
	case q.Season > 0 || q.TVDBID != "":
		return "tvsearch"
	case q.IMDBID != "":
		return "movie"
	default:
		return "search"
	}
}

func (d *Definition) runPath(ctx context.Context, client Doer, base string, p Path, tctx *Context) ([]Result, error) {
	rawPath, err := render(p.Path, tctx)
	if err != nil {
		return nil, err
	}
	reqURL, err := resolve(base, rawPath)
	if err != nil {
		return nil, fmt.Errorf("path %q: %w", rawPath, err)
	}

	inputs := map[string]string{}
	if p.InheritInputs == nil || *p.InheritInputs {
		for k, v := range d.Search.Inputs {
			inputs[k] = v
		}
	}
	for k, v := range p.Inputs {
		inputs[k] = v
	}
	values := url.Values{}
	var raw string
	for k, tpl := range inputs {
		v, err := render(tpl, tctx)
		if err != nil {
			return nil, err
		}
		if k == "$raw" {
			raw = v
			continue
		}
		values.Set(k, v)
	}

	m, err := render(p.Method, tctx)
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(m))
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if method == http.MethodPost {
		form := d.encodeValues(values)
		if raw != "" {
			form = joinQuery(form, raw)
		}
		body = strings.NewReader(form)
	} else {
		q := reqURL.Query()
		for k, vs := range values {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		reqURL.RawQuery = joinQuery(d.encodeValues(q), raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	setHeaders(req, d.Search.Headers, tctx)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", reqURL.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.Request != nil && d.isLoginPage(resp.Request.URL) {
		return nil, fmt.Errorf("%s: %w", reqURL.Redacted(), ErrLoginRequired)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request %s: status %s", reqURL.Redacted(), resp.Status)
	}

	var r io.Reader = io.LimitReader(resp.Body, MaxBodySize)
	enc := resp.Header.Get("Content-Type")
	if d.Encoding != "" && !strings.EqualFold(d.Encoding, "utf-8") {
		enc = "text/html; charset=" + d.Encoding
	}
	if enc != "" && p.Response.Type != "json" {
		if cr, err := charset.NewReader(r, enc); err == nil {
			r = cr
		}
	}
	pageURL := reqURL.String()
	if resp.Request != nil && resp.Request.URL != nil {
		pageURL = resp.Request.URL.String() // after redirects
	}
	switch p.Response.Type {
	case "json":
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return d.ParseJSON(data, pageURL, p, tctx)
	case "xml":
		doc, err := parseXML(r)
		if err != nil {
			return nil, err
		}
		return d.parseDocument(doc, pageURL, tctx)
	default:
		return d.ParseHTML(r, pageURL, tctx)
	}
}

func joinQuery(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "&" + b
	}
}

// resolve joins a path template result onto the site link. Keywords inside
// the path may contain spaces and other characters that need escaping.
func resolve(base, path string) (*url.URL, error) {
	b, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	ref, err := url.Parse(path)
	if err != nil {
		ref, err = url.Parse(escapePath(path))
		if err != nil {
			return nil, err
		}
	}
	return b.ResolveReference(ref), nil
}

func escapePath(p string) string {
	pathPart, query, hasQuery := strings.Cut(p, "?")
	segs := strings.Split(pathPart, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	out := strings.Join(segs, "/")
	if hasQuery {
		out += "?" + query
	}
	return out
}

// ParseHTML extracts results from a results page. pageURL resolves relative links.
func (d *Definition) ParseHTML(r io.Reader, pageURL string, tctx *Context) ([]Result, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, err
	}
	return d.parseDocument(doc, pageURL, tctx)
}

func (d *Definition) parseDocument(doc *goquery.Document, pageURL string, tctx *Context) ([]Result, error) {
	rowSel, err := render(d.Search.Rows.Selector, tctx)
	if err != nil {
		return nil, err
	}
	rows := doc.Find(rowSel)
	if d.Search.Rows.Remove != "" {
		rows.Find(d.Search.Rows.Remove).Remove()
	}

	var results []Result
	var firstErr error
	n := rows.Length()
	step := 1 + d.Search.Rows.After
	for i := 0; i < n; i += step {
		row := rows.Eq(i)
		for j := 1; j <= d.Search.Rows.After && i+j < n; j++ {
			// "after: N" merges the following N rows into this one.
			row = row.AddSelection(rows.Eq(i + j))
		}
		extract := func(f Field, ctx *Context) (string, error) { return extractField(row, f, ctx) }
		if dh := d.Search.Rows.DateHeaders; dh != nil {
			extract = withDateHeader(extract, rows.Eq(i), *dh)
		}
		res, err := d.buildResult(extract, pageURL, tctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if d.andMatch(res.Title, tctx.Keywords) {
			results = append(results, res)
		}
	}
	if len(results) == 0 && firstErr != nil {
		return nil, fmt.Errorf("%d rows found, none parsed: %w", n, firstErr)
	}
	return results, nil
}

// withDateHeader supplies the "date" field from the closest preceding header
// row matching rows.dateheaders, for sites that group releases under a date.
func withDateHeader(next func(Field, *Context) (string, error), row *goquery.Selection, dh Field) func(Field, *Context) (string, error) {
	return func(f Field, ctx *Context) (string, error) {
		v, err := next(f, ctx)
		if f.Name != "date" || err == nil {
			return v, err
		}
		for n := row; n.Length() > 0; n = n.Parent() {
			if h := n.PrevAllFiltered(dh.Selector).First(); h.Length() > 0 {
				hf := dh
				hf.Selector = ""
				return extractField(h, hf, ctx)
			}
		}
		return v, err
	}
}

// implicitlyOptional are fields Cardigann treats as optional even when the
// definition does not say so: informational values Scarf can do without.
var implicitlyOptional = map[string]bool{
	"imdb": true, "imdbid": true, "tmdbid": true, "rageid": true, "tvdbid": true, "tvmazeid": true,
	"traktid": true, "doubanid": true, "poster": true, "banner": true, "description": true, "genre": true,
}

// buildResult runs the field definitions through extract and maps the values to a Result.
func (d *Definition) buildResult(extract func(Field, *Context) (string, error), pageURL string, tctx *Context) (Result, error) {
	vals := make(map[string]string, len(d.Search.Fields))
	rctx := *tctx
	rctx.Result = vals

	hasDate := false
	for _, f := range d.Search.Fields {
		if f.Name == "date" {
			hasDate = true
		}
		v, err := extract(f, &rctx)
		if err != nil {
			if !f.Optional && !implicitlyOptional[f.Name] {
				return Result{}, fmt.Errorf("field %s: %w", f.Name, err)
			}
			v = ""
			if f.Default != nil {
				v, _ = render(*f.Default, &rctx)
			}
		}
		vals[f.Name] = v
	}
	if !hasDate && d.Search.Rows.DateHeaders != nil {
		if v, err := extract(Field{Name: "date"}, &rctx); err == nil {
			vals["date"] = v
		}
	}

	res := Result{
		Title:    strings.TrimSpace(vals["title"]),
		Details:  absURL(pageURL, vals["details"]),
		Size:     parseSize(vals["size"]),
		Seeders:  parseInt(vals["seeders"]),
		Leechers: parseInt(vals["leechers"]),
		Grabs:    parseInt(vals["grabs"]),
		Category: vals["category"],
	}
	res.PublishDate = parseDate(vals["date"])
	switch {
	case vals["download"] != "":
		res.Download = absURL(pageURL, vals["download"])
	case vals["magnet"] != "":
		res.Download = vals["magnet"]
	case vals["infohash"] != "":
		res.Download = "magnet:?xt=urn:btih:" + vals["infohash"] + "&dn=" + url.QueryEscape(res.Title)
	}
	if res.Title == "" || res.Download == "" {
		return Result{}, fmt.Errorf("row has no title or download link")
	}
	return res, nil
}

var errNotFound = fmt.Errorf("selector matched nothing")

func extractField(row *goquery.Selection, f Field, ctx *Context) (string, error) {
	var v string
	switch {
	case f.Text != nil:
		r, err := render(*f.Text, ctx)
		if err != nil {
			return "", err
		}
		v = r
	default:
		sel, err := render(f.Selector, ctx)
		if err != nil {
			return "", err
		}
		node := row
		if sel != "" {
			node = row.Find(sel).First()
			if node.Length() == 0 && row.Is(sel) {
				node = row.First()
			}
		}
		if node.Length() == 0 {
			return "", errNotFound
		}
		if f.Case != nil {
			// Case selectors are tested against the selected element:
			// it matches them itself or contains a match.
			matched := false
			for _, k := range caseKeys(f.Case) {
				if k == "*" || node.Is(k) || node.Find(k).Length() > 0 {
					v, matched = f.Case[k], true
					break
				}
			}
			if !matched {
				return "", errNotFound
			}
			return applyFilters(v, f.Filters, ctx)
		}
		if f.Remove != "" {
			node = node.Clone()
			node.Find(f.Remove).Remove()
		}
		if f.Attribute != "" {
			a, ok := node.Attr(f.Attribute)
			if !ok {
				return "", errNotFound
			}
			v = a
		} else {
			v = strings.TrimSpace(node.Text())
		}
	}
	return applyFilters(v, f.Filters, ctx)
}

// caseKeys returns the case selectors with the "*" fallback last. YAML maps
// lose their order, so the remaining keys are sorted for stable results.
func caseKeys(c map[string]string) []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		if k != "*" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if _, ok := c["*"]; ok {
		keys = append(keys, "*")
	}
	return keys
}

func absURL(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "magnet:") {
		return ref
	}
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

func parseInt(s string) int {
	s = strings.NewReplacer(",", "", ".", "", " ", "").Replace(strings.TrimSpace(s))
	n, _ := strconv.Atoi(s)
	return n
}

var sizeRe = regexp.MustCompile(`(?i)([\d.,]+)\s*([kmgtp]?i?b|bytes?)?`)

func parseSize(s string) int64 {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", " ")
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	num := m[1]
	if strings.Count(num, ",") > 0 && !strings.Contains(num, ".") && len(num)-strings.LastIndex(num, ",") == 3 {
		num = strings.ReplaceAll(num, ",", ".") // "1,5 GB"
	} else {
		num = strings.ReplaceAll(num, ",", "")
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0
	}
	mult := 1.0
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(m[2]), "ib"), "b")) {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	case "t":
		mult = 1 << 40
	case "p":
		mult = 1 << 50
	}
	return int64(f * mult)
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 100000000 {
		return time.Unix(n, 0).UTC()
	}
	for _, layout := range []string{time.RFC3339, time.RFC1123Z, time.RFC1123, "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if r, err := timeAgo(s, time.Now()); err == nil {
		t, _ := time.Parse(time.RFC3339, r)
		return t
	}
	return time.Time{}
}

// andMatch implements the "andmatch" rows filter: every keyword must appear in
// the title. Without the filter, or without keywords, all rows pass.
func (d *Definition) andMatch(title, keywords string) bool {
	use := false
	for _, f := range d.Search.Rows.Filters {
		if f.Name == "andmatch" {
			use = true
		}
	}
	if !use || keywords == "" {
		return true
	}
	t := strings.ToLower(title)
	for _, w := range strings.FieldsFunc(strings.ToLower(keywords), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}) {
		if !strings.Contains(t, w) {
			return false
		}
	}
	return true
}

// encodeValues URL-encodes values in the definition's charset. Sites with a
// legacy encoding (windows-1251, ...) expect percent-encoded bytes in that
// charset, not UTF-8.
func (d *Definition) encodeValues(v url.Values) string {
	if d.Encoding == "" || strings.EqualFold(d.Encoding, "utf-8") {
		return v.Encode()
	}
	enc, err := htmlindex.Get(d.Encoding)
	if err != nil {
		return v.Encode()
	}
	e := enc.NewEncoder()
	conv := func(s string) string {
		if out, err := e.String(s); err == nil {
			return out
		}
		return s
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, val := range v[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(conv(k)) + "=" + url.QueryEscape(conv(val)))
		}
	}
	return b.String()
}

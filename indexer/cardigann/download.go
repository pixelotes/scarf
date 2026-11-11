package cardigann

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Download is the download block: how to turn a result's link (usually a
// details page) into the actual .torrent or magnet link at grab time.
type Download struct {
	Method    string            `yaml:"method"`
	Headers   map[string]any    `yaml:"headers"`
	Before    *DownloadRequest  `yaml:"before"`
	Selectors []DownloadField   `yaml:"selectors"`
	Infohash  *DownloadInfohash `yaml:"infohash"`
}

// DownloadRequest is a request sent before the download, such as a "thanks" POST.
type DownloadRequest struct {
	Path   string            `yaml:"path"`
	Method string            `yaml:"method"`
	Inputs map[string]string `yaml:"inputs"`
}

// DownloadField finds the download link on the details page.
type DownloadField struct {
	Field             `yaml:",inline"`
	UseBeforeResponse bool `yaml:"usebeforeresponse"`
}

// DownloadInfohash builds a magnet link from a hash and title on the details page.
type DownloadInfohash struct {
	Hash              Field `yaml:"hash"`
	Title             Field `yaml:"title"`
	UseBeforeResponse bool  `yaml:"usebeforeresponse"`
}

// DownloadURI mirrors Cardigann's .DownloadUri template variable.
type DownloadURI struct {
	AbsoluteUri  string
	AbsolutePath string
	PathAndQuery string
	Query        map[string]string
}

// NeedsResolve reports whether links from this indexer must go through
// ResolveDownload (and Scarf's download proxy) instead of being handed to
// the client as they are.
func (d *Definition) NeedsResolve() bool { return d.Download != nil }

// ResolveDownload follows the download block for a result link and returns
// the .torrent URL or magnet link to fetch. Without a download block the link
// is returned unchanged.
func (d *Definition) ResolveDownload(ctx context.Context, client Doer, link string, config map[string]string) (string, error) {
	dl := d.Download
	if dl == nil || strings.HasPrefix(link, "magnet:") {
		return link, nil
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	tctx := d.newContext(Query{}, config)
	q := map[string]string{}
	for k, v := range u.Query() {
		q[k] = v[0]
	}
	tctx.DownloadUri = DownloadURI{AbsoluteUri: u.String(), AbsolutePath: u.Path, PathAndQuery: u.RequestURI(), Query: q}

	var before *goquery.Document
	if dl.Before != nil {
		values, err := renderInputs(dl.Before.Inputs, tctx)
		if err != nil {
			return "", err
		}
		method := strings.ToUpper(dl.Before.Method)
		if method == "" {
			method = http.MethodGet
		}
		path := dl.Before.Path
		if path == "" {
			path = link
		}
		base, _ := url.Parse(d.BaseURL(config))
		if before, err = d.downloadRequest(ctx, client, method, base, path, values, dl.Headers, tctx); err != nil {
			return "", fmt.Errorf("download.before: %w", err)
		}
	}
	if len(dl.Selectors) == 0 && dl.Infohash == nil {
		return link, nil
	}

	var page *goquery.Document
	pageFor := func(useBefore bool) (*goquery.Document, error) {
		if useBefore && before != nil {
			return before, nil
		}
		if page == nil {
			method := strings.ToUpper(dl.Method)
			if method == "" {
				method = http.MethodGet
			}
			p, err := d.downloadRequest(ctx, client, method, u, "", nil, dl.Headers, tctx)
			if err != nil {
				return nil, err
			}
			page = p
		}
		return page, nil
	}

	for _, s := range dl.Selectors {
		doc, err := pageFor(s.UseBeforeResponse)
		if err != nil {
			return "", err
		}
		v, err := extractField(doc.Selection, s.Field, tctx)
		if err != nil || strings.TrimSpace(v) == "" {
			continue // try the next selector
		}
		return absURL(link, v), nil
	}
	if ih := dl.Infohash; ih != nil {
		doc, err := pageFor(ih.UseBeforeResponse)
		if err != nil {
			return "", err
		}
		hash, err := extractField(doc.Selection, ih.Hash, tctx)
		if err == nil && hash != "" {
			title, _ := extractField(doc.Selection, ih.Title, tctx)
			return "magnet:?xt=urn:btih:" + hash + "&dn=" + url.QueryEscape(title), nil
		}
	}
	return "", fmt.Errorf("download link not found on %s", u.Redacted())
}

func (d *Definition) downloadRequest(ctx context.Context, client Doer, method string, base *url.URL, path string, values url.Values, headers map[string]any, tctx *Context) (*goquery.Document, error) {
	p, err := render(path, tctx)
	if err != nil {
		return nil, err
	}
	u, err := resolve(base.String(), p)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(d.encodeValues(values))
	} else if len(values) > 0 {
		qv := u.Query()
		for k, vs := range values {
			qv[k] = vs
		}
		u.RawQuery = d.encodeValues(qv)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	setHeaders(req, d.Search.Headers, tctx)
	setHeaders(req, headers, tctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && d.isLoginPage(resp.Request.URL) {
		return nil, ErrLoginRequired
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: status %s", u.Redacted(), resp.Status)
	}
	return d.decodeHTML(resp)
}

// decodeHTML parses a response body as HTML in the definition's encoding.
func (d *Definition) decodeHTML(resp *http.Response) (*goquery.Document, error) {
	return goquery.NewDocumentFromReader(d.bodyReader(resp))
}

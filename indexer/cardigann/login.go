package cardigann

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html/charset"
	"gopkg.in/yaml.v3"
)

// Login describes how to sign in to a private tracker.
type Login struct {
	Path           string            `yaml:"path"`
	SubmitPath     string            `yaml:"submitpath"`
	Method         string            `yaml:"method"` // post, get, form, cookie
	Form           string            `yaml:"form"`
	Inputs         map[string]string `yaml:"inputs"`
	SelectorInputs map[string]Field  `yaml:"selectorinputs"`
	Cookies        []string          `yaml:"cookies"`
	Headers        map[string]any    `yaml:"headers"`
	Captcha        yaml.Node         `yaml:"captcha"`
	Error          []LoginError      `yaml:"error"`
	Test           struct {
		Path     string `yaml:"path"`
		Selector string `yaml:"selector"`
	} `yaml:"test"`
}

// LoginError is a page condition that means the login failed.
type LoginError struct {
	Path     string `yaml:"path"`
	Selector string `yaml:"selector"`
	Message  *Field `yaml:"message"`
}

// ErrLoginRequired means the site answered with its login page: the session
// expired and the caller should log in again.
var ErrLoginRequired = errors.New("login required")

// NeedsLogin reports whether the definition has a login block.
func (d *Definition) NeedsLogin() bool { return d.Login != nil }

// DoLogin signs in. Session cookies end up in jar, which must be the jar of
// the client used for later searches. For the cookie method the user's cookie
// string is stored in jar instead.
func (d *Definition) DoLogin(ctx context.Context, client Doer, jar http.CookieJar, config map[string]string) error {
	l := d.Login
	if l == nil {
		return nil
	}
	tctx := d.newContext(Query{}, config)
	base, err := url.Parse(d.BaseURL(config))
	if err != nil {
		return err
	}
	if jar != nil {
		for _, c := range l.Cookies {
			jar.SetCookies(base, parseCookies(c))
		}
	}

	var page *goquery.Document
	switch strings.ToLower(l.Method) {
	case "cookie":
		if jar == nil {
			return fmt.Errorf("cookie login needs a cookie jar")
		}
		raw, err := render(l.Inputs["cookie"], tctx)
		if err != nil {
			return err
		}
		if raw == "" {
			raw = config["cookie"]
		}
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("the cookie setting is empty")
		}
		jar.SetCookies(base, parseCookies(raw))
	case "post", "":
		values, err := renderInputs(l.Inputs, tctx)
		if err != nil {
			return err
		}
		page, err = d.loginRequest(ctx, client, http.MethodPost, base, l.Path, values, tctx)
		if err != nil {
			return err
		}
	case "get":
		values, err := renderInputs(l.Inputs, tctx)
		if err != nil {
			return err
		}
		page, err = d.loginRequest(ctx, client, http.MethodGet, base, l.Path, values, tctx)
		if err != nil {
			return err
		}
	case "form":
		page, err = d.formLogin(ctx, client, base, tctx)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("login method %q is not supported", l.Method)
	}

	if page != nil {
		if err := d.checkLoginErrors(page, tctx); err != nil {
			return err
		}
	}
	return d.TestLogin(ctx, client, config)
}

// TestLogin checks the login.test page: it must load without bouncing to the
// login page, and contain the test selector when one is given.
func (d *Definition) TestLogin(ctx context.Context, client Doer, config map[string]string) error {
	l := d.Login
	if l == nil || l.Test.Path == "" {
		return nil
	}
	tctx := d.newContext(Query{}, config)
	base, err := url.Parse(d.BaseURL(config))
	if err != nil {
		return err
	}
	doc, err := d.loginRequest(ctx, client, http.MethodGet, base, l.Test.Path, nil, tctx)
	if err != nil {
		return err
	}
	if l.Test.Selector != "" {
		sel, err := render(l.Test.Selector, tctx)
		if err != nil {
			return err
		}
		if doc.Find(sel).Length() == 0 {
			if err := d.checkLoginErrors(doc, tctx); err != nil {
				return err
			}
			return fmt.Errorf("login test failed: %q not found on %s", sel, l.Test.Path)
		}
	}
	return nil
}

func renderInputs(inputs map[string]string, tctx *Context) (url.Values, error) {
	values := url.Values{}
	for k, tpl := range inputs {
		v, err := render(tpl, tctx)
		if err != nil {
			return nil, err
		}
		values.Set(k, v)
	}
	return values, nil
}

// formLogin loads the login page, fills its form (keeping hidden inputs such
// as CSRF tokens) and submits it.
func (d *Definition) formLogin(ctx context.Context, client Doer, base *url.URL, tctx *Context) (*goquery.Document, error) {
	l := d.Login
	page, err := d.loginRequest(ctx, client, http.MethodGet, base, l.Path, nil, tctx)
	if err != nil {
		return nil, err
	}
	formSel := l.Form
	if formSel == "" {
		formSel = "form"
	}
	form := page.Find(formSel).First()
	if form.Length() == 0 {
		return nil, fmt.Errorf("login form %q not found on %s", formSel, l.Path)
	}

	values := url.Values{}
	form.Find("input[name], textarea[name], select[name]").Each(func(_ int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		typ := strings.ToLower(s.AttrOr("type", ""))
		if (typ == "checkbox" || typ == "radio") && s.AttrOr("checked", "\x00") == "\x00" {
			return
		}
		if goquery.NodeName(s) == "select" {
			values.Set(name, s.Find("option[selected]").AttrOr("value", s.Find("option").First().AttrOr("value", "")))
			return
		}
		if goquery.NodeName(s) == "textarea" {
			values.Set(name, s.Text())
			return
		}
		values.Set(name, s.AttrOr("value", ""))
	})
	for name, f := range l.SelectorInputs {
		v, err := extractField(page.Selection, f, tctx)
		if err != nil {
			return nil, fmt.Errorf("selectorinput %s: %w", name, err)
		}
		values.Set(name, v)
	}
	extra, err := renderInputs(l.Inputs, tctx)
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		values[k] = v
	}

	action := l.SubmitPath
	if action == "" {
		action = form.AttrOr("action", l.Path)
	}
	method := strings.ToUpper(form.AttrOr("method", http.MethodPost))
	pageURL := base.ResolveReference(mustParse(l.Path))
	return d.loginRequest(ctx, client, method, pageURL, action, values, tctx)
}

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{}
	}
	return u
}

// loginRequest sends a login-related request and parses the answer as HTML.
func (d *Definition) loginRequest(ctx context.Context, client Doer, method string, base *url.URL, path string, values url.Values, tctx *Context) (*goquery.Document, error) {
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
		q := u.Query()
		for k, vs := range values {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u.RawQuery = d.encodeValues(q)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	setHeaders(req, d.Search.Headers, tctx)
	if d.Login != nil {
		setHeaders(req, d.Login.Headers, tctx)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request %s: %w", u.Redacted(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login request %s: status %s", u.Redacted(), resp.Status)
	}
	var r io.Reader = io.LimitReader(resp.Body, MaxBodySize)
	enc := resp.Header.Get("Content-Type")
	if d.Encoding != "" && !strings.EqualFold(d.Encoding, "utf-8") {
		enc = "text/html; charset=" + d.Encoding
	}
	if enc != "" {
		if cr, err := charset.NewReader(r, enc); err == nil {
			r = cr
		}
	}
	return goquery.NewDocumentFromReader(r)
}

func (d *Definition) checkLoginErrors(doc *goquery.Document, tctx *Context) error {
	for _, e := range d.Login.Error {
		if e.Selector == "" {
			continue
		}
		sel, err := render(e.Selector, tctx)
		if err != nil {
			continue
		}
		hit := doc.Find(sel)
		if hit.Length() == 0 {
			continue
		}
		msg := strings.TrimSpace(hit.First().Text())
		if e.Message != nil {
			if m, err := extractField(doc.Selection, *e.Message, tctx); err == nil && m != "" {
				msg = strings.TrimSpace(m)
			}
		}
		if msg == "" {
			msg = "error selector " + sel + " matched"
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("login failed: %s", msg)
	}
	return nil
}

// isLoginPage reports whether a search response landed on the login page,
// which means the session expired.
func (d *Definition) isLoginPage(finalURL *url.URL) bool {
	if d.Login == nil || finalURL == nil || strings.EqualFold(d.Login.Method, "cookie") {
		return false
	}
	p := strings.TrimPrefix(strings.SplitN(d.Login.Path, "?", 2)[0], "/")
	if p == "" || strings.Contains(p, "{{") {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(finalURL.Path, "/"), "/"+strings.TrimSuffix(p, "/"))
}

func setHeaders(req *http.Request, headers map[string]any, tctx *Context) {
	for k, v := range headers {
		hv := ""
		switch t := v.(type) {
		case string:
			hv = t
		case []any:
			if len(t) > 0 {
				hv = fmt.Sprint(t[0])
			}
		default:
			hv = fmt.Sprint(t)
		}
		if r, err := render(hv, tctx); err == nil && r != "" {
			req.Header.Set(k, r)
		}
	}
}

// parseCookies parses "a=1; b=2" into cookies.
func parseCookies(s string) []*http.Cookie {
	var out []*http.Cookie
	for _, part := range strings.Split(s, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || name == "" {
			continue
		}
		out = append(out, &http.Cookie{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return out
}

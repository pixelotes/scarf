package cardigann

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

const loginDef = `
id: private
name: Private
type: private
links: [https://example.invalid/]
settings:
  - {name: username, type: text}
  - {name: password, type: password}
login:
  path: login.php
  method: form
  form: form#login
  inputs:
    user: "{{ .Config.username }}"
    pass: "{{ .Config.password }}"
  selectorinputs:
    token:
      selector: meta[name="csrf"]
      attribute: content
  error:
    - selector: div.error
  test:
    path: index.php
    selector: a[href="logout.php"]
search:
  paths: [{path: browse.php}]
  inputs: {q: "{{ .Keywords }}"}
  rows: {selector: tr.t}
  fields:
    title: {selector: a}
    download: {selector: a, attribute: href}
`

// fakeTracker accepts user/secret with the right hidden and CSRF tokens.
func fakeTracker(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	loggedIn := func(r *http.Request) bool {
		c, err := r.Cookie("sid")
		return err == nil && c.Value == "ok"
	}
	mux.HandleFunc("/login.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(`<meta name="csrf" content="T0K"><form id="login" action="takelogin.php" method="post">
<input type="hidden" name="hidden" value="h1"><input name="user"><input name="pass" type="password">
<input type="checkbox" name="remember"></form>`))
			return
		}
	})
	mux.HandleFunc("/takelogin.php", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("hidden") != "h1" || r.Form.Get("token") != "T0K" || r.Form.Has("remember") {
			t.Errorf("bad form: %v", r.Form)
		}
		if r.Form.Get("user") != "user" || r.Form.Get("pass") != "secret" {
			w.Write([]byte(`<div class="error">Wrong password</div>`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
		http.Redirect(w, r, "/index.php", http.StatusFound)
	})
	mux.HandleFunc("/index.php", func(w http.ResponseWriter, r *http.Request) {
		if loggedIn(r) {
			w.Write([]byte(`<a href="logout.php">logout</a>`))
		} else {
			w.Write([]byte(`welcome guest`))
		}
	})
	mux.HandleFunc("/browse.php", func(w http.ResponseWriter, r *http.Request) {
		if !loggedIn(r) {
			http.Redirect(w, r, "/login.php", http.StatusFound)
			return
		}
		w.Write([]byte(`<table><tr class="t"><td><a href="/dl/1.torrent">Ubuntu</a></td></tr></table>`))
	})
	return httptest.NewServer(mux)
}

func TestFormLogin(t *testing.T) {
	srv := fakeTracker(t)
	defer srv.Close()
	d, err := Parse([]byte(loginDef))
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	cfg := map[string]string{"sitelink": srv.URL, "username": "user", "password": "secret"}
	ctx := context.Background()

	if _, err := d.Run(ctx, client, Query{Keywords: "ubuntu"}, cfg); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("search before login: want ErrLoginRequired, got %v", err)
	}
	bad := map[string]string{"sitelink": srv.URL, "username": "user", "password": "nope"}
	if err := d.DoLogin(ctx, client, jar, bad); err == nil || !strings.Contains(err.Error(), "Wrong password") {
		t.Fatalf("want error message from the page, got %v", err)
	}
	if err := d.DoLogin(ctx, client, jar, cfg); err != nil {
		t.Fatal(err)
	}
	res, err := d.Run(ctx, client, Query{Keywords: "ubuntu"}, cfg)
	if err != nil || len(res) != 1 || res[0].Title != "Ubuntu" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestCookieLogin(t *testing.T) {
	srv := fakeTracker(t)
	defer srv.Close()
	def := strings.Replace(loginDef, "  method: form\n", "  method: cookie\n", 1)
	def = strings.Replace(def, `    user: "{{ .Config.username }}"`+"\n"+`    pass: "{{ .Config.password }}"`, `    cookie: "{{ .Config.cookie }}"`, 1)
	d, err := Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if err := d.DoLogin(context.Background(), client, jar, map[string]string{"sitelink": srv.URL, "cookie": "sid=bad"}); err == nil {
		t.Fatal("bad cookie accepted")
	}
	if err := d.DoLogin(context.Background(), client, jar, map[string]string{"sitelink": srv.URL, "cookie": "sid=ok; other=1"}); err != nil {
		t.Fatal(err)
	}
}

package cardigann

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveDownload(t *testing.T) {
	thanked := false
	mux := http.NewServeMux()
	mux.HandleFunc("/thanks.php", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Method == http.MethodPost && r.Form.Get("torrentid") == "42" {
			thanked = true
		}
	})
	mux.HandleFunc("/details.php", func(w http.ResponseWriter, r *http.Request) {
		if !thanked {
			w.Write([]byte(`say thanks first`))
			return
		}
		w.Write([]byte(`<a href="download.php?id=42&key=abc&x=1">get</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	def := strings.Replace(testDef, "search:\n", `download:
  before:
    path: thanks.php
    method: post
    inputs:
      torrentid: "{{ .DownloadUri.Query.id }}"
  selectors:
    - selector: a.missing
      attribute: href
    - selector: a[href^="download.php"]
      attribute: href
      filters:
        - name: regexp
          args: "^(.+?)&x="
search:
`, 1)
	d, err := Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.ResolveDownload(context.Background(), srv.Client(), srv.URL+"/details.php?id=42", map[string]string{"sitelink": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if want := srv.URL + "/download.php?id=42&key=abc"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

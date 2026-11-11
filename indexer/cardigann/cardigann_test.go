package cardigann

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A small hand-written definition exercising ordered fields, .Result,
// dashed config names, checkboxes, optional/default fields and filters.
const testDef = `
id: example
name: Example
type: public
links:
  - https://example.invalid/
caps:
  categorymappings:
    - {id: 1_2, cat: TV/Anime, desc: Anime}
  modes:
    search: [q]
settings:
  - name: prefer_magnet_links
    type: checkbox
    default: true
  - name: filter-id
    type: select
    default: 2
search:
  paths:
    - path: /search
  inputs:
    q: "{{ .Keywords }}"
    f: "{{ .Config.filter-id }}"
    c: "{{ join .Categories \",\" }}"
  keywordsfilters:
    - name: re_replace
      args: ["(?i)\\bS0?1\\b", ""]
  rows:
    selector: tr.row
  fields:
    category:
      selector: td.cat a
      attribute: href
      filters:
        - name: split
          args: ["=", -1]
    title_raw:
      selector: td.name a
    title:
      text: "{{ .Result.title_raw }}"
      filters:
        - name: re_replace
          args: ["(?<=\\]) +", " "]
        - name: append
          args: " [x]"
    details:
      selector: td.name a
      attribute: href
    download_torrent:
      selector: td.dl a[href$=".torrent"]
      attribute: href
      optional: true
    download:
      text: "{{ if .Config.prefer_magnet_links }}{{ else }}{{ .Result.download_torrent }}{{ end }}"
      optional: true
    magnet:
      selector: td.dl a[href^="magnet:"]
      attribute: href
    size:
      selector: td.size
    date:
      selector: td.date
      filters:
        - name: append
          args: " +00:00"
        - name: dateparse
          args: "yyyy-MM-dd HH:mm zzz"
    seeders:
      selector: td.seed:not(:empty)
      optional: true
      default: 0
    leechers:
      selector: td.leech
`

const testHTML = `<html><body><table>
<tr class="row">
  <td class="cat"><a href="/?c=1_2">Anime</a></td>
  <td class="name"><a href="/view/1">[Grp]   Show - 01</a></td>
  <td class="dl"><a href="/download/1.torrent">t</a><a href="magnet:?xt=urn:btih:AAA">m</a></td>
  <td class="size">1.5 GiB</td><td class="date">2026-01-02 03:04</td>
  <td class="seed">1,024</td><td class="leech">7</td>
</tr>
<tr class="row">
  <td class="cat"><a href="/?c=1_2">Anime</a></td>
  <td class="name"><a href="/view/2">No magnet</a></td>
  <td class="dl"><a href="/download/2.torrent">t</a></td>
  <td class="size">700 MiB</td><td class="date">2026-01-02 03:04</td>
  <td class="seed"></td><td class="leech">0</td>
</tr>
</table></body></html>`

func TestRunAgainstTestServer(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(testHTML))
	}))
	defer srv.Close()

	d, err := Parse([]byte(testDef))
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Run(context.Background(), srv.Client(), Query{Keywords: "Show S01", Categories: []string{"1_2"}},
		map[string]string{"sitelink": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"q=Show", "f=2", "c=1_2"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q missing %q", gotQuery, want)
		}
	}
	// Row 2 has no magnet and magnet is not optional, so it is skipped.
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(res), res)
	}
	r := res[0]
	if r.Title != "[Grp] Show - 01 [x]" {
		t.Errorf("title = %q", r.Title)
	}
	if r.Download != "magnet:?xt=urn:btih:AAA" {
		t.Errorf("download = %q (prefer_magnet_links is on)", r.Download)
	}
	if r.Details != srv.URL+"/view/1" {
		t.Errorf("details = %q", r.Details)
	}
	if r.Size != 1610612736 || r.Seeders != 1024 || r.Leechers != 7 || r.Category != "1_2" {
		t.Errorf("unexpected values: %+v", r)
	}
	if want := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC); !r.PublishDate.Equal(want) {
		t.Errorf("date = %v", r.PublishDate)
	}
}

func TestCheckboxOffUsesTorrent(t *testing.T) {
	d, err := Parse([]byte(testDef))
	if err != nil {
		t.Fatal(err)
	}
	ctx := d.newContext(Query{}, map[string]string{"prefer_magnet_links": "false"})
	res, err := d.ParseHTML(strings.NewReader(testHTML), "https://example.invalid/search", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || res[0].Download != "https://example.invalid/download/1.torrent" {
		t.Fatalf("got %+v", res)
	}
}

func TestParseRejectsUnsupported(t *testing.T) {
	def := strings.Replace(testDef, "search:\n  paths:", "login:\n  path: login.php\n  method: form\n  captcha:\n    type: image\nsearch:\n  paths:", 1)
	if _, err := Parse([]byte(def)); err == nil || !strings.Contains(err.Error(), "captcha") {
		t.Fatalf("want captcha rejection, got %v", err)
	}
	def = strings.Replace(testDef, "name: append", "name: nosuchfilter", 1)
	if _, err := Parse([]byte(def)); err == nil || !strings.Contains(err.Error(), "nosuchfilter") {
		t.Fatalf("want filter rejection, got %v", err)
	}
}

func TestIsCardigann(t *testing.T) {
	if !IsCardigann([]byte(testDef)) {
		t.Error("testDef not detected")
	}
	if IsCardigann([]byte("key: eztv\nname: EZTV\nsearch: {}\n")) {
		t.Error("Scarf definition detected as Cardigann")
	}
}

func TestFilters(t *testing.T) {
	cases := []struct {
		f    Filter
		in   string
		want string
	}{
		{Filter{"split", []string{"_", "0"}}, "1_2", "1"},
		{Filter{"regexp", []string{`(\d+)p`}}, "Show 1080p", "1080"},
		{Filter{"querystring", []string{"id"}}, "/x.php?id=42&a=b", "42"},
		{Filter{"re_replace", []string{`(?i)(?<![a-z])ova`, "OVA"}}, "an ova", "an OVA"},
		{Filter{"re_replace", []string{`([\p{IsCyrillic}]+)`, ""}}, "Доктор House", " House"},
		{Filter{"re_replace", []string{`\p{IsCJKUnifiedIdeographs}+`, "."}}, "航海王 One", ". One"},
		{Filter{"diacritics", []string{"replace"}}, "Pokémon", "Pokemon"},
	}
	for _, c := range cases {
		got, err := applyFilters(c.in, []Filter{c.f}, &Context{})
		if err != nil || got != c.want {
			t.Errorf("%s(%q) = %q, %v; want %q", c.f.Name, c.in, got, err, c.want)
		}
	}
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	if got, _ := timeAgo("2 days, 3 hours ago", now); got != "2026-01-08T09:00:00Z" {
		t.Errorf("timeago = %s", got)
	}
}

// TestUpstreamDefinitions loads real Jackett/Prowlarr definitions from the
// directory in CARDIGANN_DEFS (not bundled: they are GPL) and, when
// CARDIGANN_LIVE=1, runs a search against each site.
func TestUpstreamDefinitions(t *testing.T) {
	dir := os.Getenv("CARDIGANN_DEFS")
	if dir == "" {
		t.Skip("set CARDIGANN_DEFS to a directory of Cardigann definitions")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	live := os.Getenv("CARDIGANN_LIVE") == "1"
	query := os.Getenv("CARDIGANN_QUERY")
	if query == "" {
		query = "ubuntu"
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, _ := os.ReadFile(f)
			d, err := Parse(data)
			if err != nil {
				t.Skip(err)
			}
			if !live {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			client := &http.Client{Timeout: 30 * time.Second, Transport: uaTransport{}}
			res, err := d.Run(ctx, client, Query{Keywords: query}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d results", len(res))
			for i, r := range res {
				if i == 3 {
					break
				}
				t.Logf("  %s | %d B | S%d L%d | %s | %.60s", r.Title, r.Size, r.Seeders, r.Leechers, r.PublishDate.Format(time.DateOnly), r.Download)
			}
			if len(res) == 0 {
				t.Error("no results")
			}
		})
	}
}

type uaTransport struct{}

func (uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
	return http.DefaultTransport.RoundTrip(r)
}

func TestRawStrings(t *testing.T) {
	got, err := render(`{{ re_replace .Keywords "[\s]+" "+" }}`, &Context{Keywords: "a  b c"})
	if err != nil || got != "a+b+c" {
		t.Fatalf("got %q, %v", got, err)
	}
}

package cardigann

import (
	"strings"
	"testing"
)

const jsonDef = `
id: jsonex
name: JSON example
links: [https://example.invalid/]
search:
  paths:
    - path: api
      response:
        type: json
        noResultsMessage: ""
  rows:
    selector: "data.movies:not(hidden:contains(True))"
    attribute: torrents
    multiple: true
    count:
      selector: data.movie_count
  fields:
    _q:
      selector: quality
    title:
      selector: ..title
      filters:
        - name: append
          args: " {{ .Result._q }}"
    category:
      selector: quality
      case:
        "1080p": 44
        "*": 45
    download:
      selector: url
    size:
      selector: size_bytes
    seeders:
      selector: seeds
    date:
      selector: ..uploaded
    tags:
      selector: ..tags
      optional: true
      filters:
        - name: jsonjoinarray
          args: ["$", ", "]
`

const jsonBody = `{"data":{"movie_count":2,"movies":[
 {"title":"Big Buck","uploaded":1767225600,"tags":["a","b"],"torrents":[
   {"quality":"1080p","url":"/t/1","size_bytes":1000,"seeds":5},
   {"quality":"720p","url":"/t/2","size_bytes":500,"seeds":3}]},
 {"title":"Hidden","hidden":true,"torrents":[{"quality":"720p","url":"/t/3","size_bytes":1,"seeds":1}]}
]}}`

func TestParseJSON(t *testing.T) {
	d, err := Parse([]byte(jsonDef))
	if err != nil {
		t.Fatal(err)
	}
	ctx := d.newContext(Query{}, nil)
	res, err := d.ParseJSON([]byte(jsonBody), "https://example.invalid/api", d.Search.Paths[0], ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d results: %+v", len(res), res)
	}
	r := res[0]
	if r.Title != "Big Buck 1080p" || r.Category != "44" || r.Download != "https://example.invalid/t/1" ||
		r.Size != 1000 || r.Seeders != 5 || r.PublishDate.Year() != 2026 {
		t.Errorf("unexpected %+v", r)
	}
	if res[1].Category != "45" {
		t.Errorf("case fallback: %+v", res[1])
	}
	if res, err := d.ParseJSON([]byte(""), "", d.Search.Paths[0], ctx); err != nil || res != nil {
		t.Errorf("noResultsMessage: %v %v", res, err)
	}
	if res, _ := d.ParseJSON([]byte(`{"data":{"movie_count":0}}`), "", d.Search.Paths[0], ctx); res != nil {
		t.Errorf("count 0: %v", res)
	}
}

func TestParseXML(t *testing.T) {
	def := `
id: xmlex
name: XML
links: [https://example.invalid/]
search:
  paths: [{path: rss, response: {type: xml}}]
  rows: {selector: item}
  fields:
    title: {selector: title}
    download: {selector: link}
    seeders: {selector: 'torznab\:attr[name="seeders"]', attribute: value}
`
	feed := `<?xml version="1.0"?><rss xmlns:torznab="http://torznab.com/schemas/2015/feed"><channel>
<item><title>Ubuntu</title><link>https://example.invalid/1.torrent</link><torznab:attr name="seeders" value="9"/></item>
</channel></rss>`
	d, err := Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseXML(strings.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.parseDocument(doc, "https://example.invalid/rss", d.newContext(Query{}, nil))
	if err != nil || len(res) != 1 || res[0].Download != "https://example.invalid/1.torrent" || res[0].Seeders != 9 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

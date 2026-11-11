package cardigann

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// parseXML builds a goquery document from an XML response. Going through the
// HTML parser would break feeds: <link> is a void element in HTML, so RSS
// <link>url</link> would lose its text. Tag names keep their prefix
// ("torznab:attr") and are lower-cased, as CSS selectors expect.
func parseXML(r io.Reader) (*goquery.Document, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	dec.CharsetReader = func(label string, in io.Reader) (io.Reader, error) { return in, nil }
	root := &html.Node{Type: html.DocumentNode}
	cur := root
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &html.Node{Type: html.ElementNode, Data: xmlName(t.Name)}
			for _, a := range t.Attr {
				n.Attr = append(n.Attr, html.Attribute{Key: xmlName(a.Name), Val: a.Value})
			}
			cur.AppendChild(n)
			cur = n
		case xml.EndElement:
			if cur.Parent != nil {
				cur = cur.Parent
			}
		case xml.CharData:
			cur.AppendChild(&html.Node{Type: html.TextNode, Data: string(t)})
		}
	}
	return goquery.NewDocumentFromNode(root), nil
}

func xmlName(n xml.Name) string {
	name := n.Local
	if n.Space != "" {
		// The decoder resolves prefixes to namespace URLs; keep a short prefix
		// for the common feed namespaces so "torznab|attr"-style selectors work.
		switch {
		case strings.Contains(n.Space, "torznab"):
			name = "torznab:" + name
		case strings.Contains(n.Space, "newznab"):
			name = "newznab:" + name
		}
	}
	return strings.ToLower(name)
}

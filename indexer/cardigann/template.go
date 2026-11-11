package cardigann

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/dlclark/regexp2"
)

// Context is the data a Cardigann template sees.
type Context struct {
	Keywords   string
	Query      QueryVars
	Config     map[string]string
	Categories []string
	Result     map[string]string
}

// QueryVars mirrors Cardigann's .Query.* variables.
type QueryVars struct {
	Q           string
	Keywords    string
	Season      string
	Ep          string
	IMDBID      string
	IMDBIDShort string
	TVDBID      string
	Year        string
}

var (
	// .Config.foo-bar and .Result.foo-bar are not valid Go template syntax;
	// they are rewritten to (index .Config "foo-bar"). Plain names are
	// rewritten too, so a missing key yields "" instead of "<no value>".
	dottedVar = regexp2.MustCompile(`\.(Config|Result)\.([A-Za-z0-9_\-]+)`, regexp2.None)

	tplCache sync.Map // string -> *template.Template
)

var tplFuncs = template.FuncMap{
	"re_replace": func(s, pattern, repl string) (string, error) {
		re, err := compileRegex(pattern)
		if err != nil {
			return "", err
		}
		return re.Replace(s, repl, -1, -1)
	},
	"join": func(items []string, sep string) string { return strings.Join(items, sep) },
}

// render executes a Cardigann template string. Strings without "{{" are returned as-is.
func render(src string, ctx *Context) (string, error) {
	if !strings.Contains(src, "{{") {
		return src, nil
	}
	t, err := compileTemplate(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("template %q: %w", src, err)
	}
	return buf.String(), nil
}

func compileTemplate(src string) (*template.Template, error) {
	if t, ok := tplCache.Load(src); ok {
		return t.(*template.Template), nil
	}
	rewritten, err := dottedVar.Replace(rawStrings(src), `(index .$1 "$2")`, -1, -1)
	if err != nil {
		return nil, err
	}
	t, err := template.New("").Funcs(tplFuncs).Option("missingkey=zero").Parse(rewritten)
	if err != nil {
		return nil, fmt.Errorf("template %q: %w", src, err)
	}
	tplCache.Store(src, t)
	return t, nil
}

var reCache sync.Map // string -> *regexp2.Regexp

// compileRegex compiles a .NET-style regex (Cardigann definitions use
// lookbehind and other features Go's regexp lacks). Results are cached.
func compileRegex(pattern string) (*regexp2.Regexp, error) {
	if re, ok := reCache.Load(pattern); ok {
		return re.(*regexp2.Regexp), nil
	}
	re, err := regexp2.Compile(translateBlocks(pattern), regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("regex %q: %w", pattern, err)
	}
	re.MatchTimeout = defaultRegexTimeout
	reCache.Store(pattern, re)
	return re, nil
}

// rawStrings rewrites double-quoted string literals inside {{ }} actions.
// Cardigann (C#) treats backslashes in them literally, so "[\s]+" is a regex,
// while Go would reject \s as an invalid escape. Only \" is an escape.
func rawStrings(src string) string {
	var b strings.Builder
	inAction := false
	for i := 0; i < len(src); i++ {
		switch {
		case !inAction && strings.HasPrefix(src[i:], "{{"):
			inAction = true
			b.WriteString("{{")
			i++
		case inAction && strings.HasPrefix(src[i:], "}}"):
			inAction = false
			b.WriteString("}}")
			i++
		case inAction && src[i] == '"':
			var lit strings.Builder
			j := i + 1
			for ; j < len(src) && src[j] != '"'; j++ {
				if src[j] == '\\' && j+1 < len(src) && src[j+1] == '"' {
					j++
				}
				lit.WriteByte(src[j])
			}
			if v := lit.String(); strings.Contains(v, "`") {
				b.WriteString(strconv.Quote(v))
			} else {
				b.WriteString("`" + v + "`")
			}
			i = j
		default:
			b.WriteByte(src[i])
		}
	}
	return b.String()
}

// .NET named Unicode blocks (\p{IsCyrillic}) are not supported by regexp2;
// they are rewritten as code point ranges.
var unicodeBlocks = map[string]string{
	"BasicLatin":                 `\u0000-\u007F`,
	"Latin-1Supplement":          `\u0080-\u00FF`,
	"Greek":                      `\u0370-\u03FF`,
	"GreekandCoptic":             `\u0370-\u03FF`,
	"Cyrillic":                   `\u0400-\u04FF`,
	"Hebrew":                     `\u0590-\u05FF`,
	"Arabic":                     `\u0600-\u06FF`,
	"Thai":                       `\u0E00-\u0E7F`,
	"Hiragana":                   `\u3040-\u309F`,
	"Katakana":                   `\u30A0-\u30FF`,
	"CJKSymbolsandPunctuation":   `\u3000-\u303F`,
	"CJKUnifiedIdeographs":       `\u4E00-\u9FFF`,
	"HangulSyllables":            `\uAC00-\uD7AF`,
	"HalfwidthandFullwidthForms": `\uFF00-\uFFEF`,
}

func translateBlocks(p string) string {
	if !strings.Contains(p, "{Is") {
		return p
	}
	var b strings.Builder
	inClass := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			if (p[i+1] == 'p' || p[i+1] == 'P') && strings.HasPrefix(p[i+2:], "{Is") {
				if end := strings.IndexByte(p[i+2:], '}'); end > 0 {
					if r, ok := unicodeBlocks[p[i+5:i+2+end]]; ok {
						neg := p[i+1] == 'P'
						switch {
						case inClass && !neg:
							b.WriteString(r)
						case neg:
							b.WriteString("[^" + r + "]")
						default:
							b.WriteString("[" + r + "]")
						}
						i += 2 + end
						continue
					}
				}
			}
			b.WriteByte(c)
			b.WriteByte(p[i+1])
			i++
			continue
		}
		if c == '[' && !inClass {
			inClass = true
		} else if c == ']' && inClass {
			inClass = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

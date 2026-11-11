package cardigann

import (
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const defaultRegexTimeout = 2 * time.Second

type filterFunc func(value string, args []string) (string, error)

// filters implements the most used Cardigann filters. Filters not listed here
// make Parse reject the definition.
var filters = map[string]filterFunc{
	"replace": func(v string, a []string) (string, error) {
		if len(a) < 2 {
			return v, fmt.Errorf("replace needs 2 args")
		}
		return strings.ReplaceAll(v, a[0], a[1]), nil
	},
	"re_replace": func(v string, a []string) (string, error) {
		if len(a) < 2 {
			return v, fmt.Errorf("re_replace needs 2 args")
		}
		re, err := compileRegex(a[0])
		if err != nil {
			return v, err
		}
		return re.Replace(v, a[1], -1, -1)
	},
	"regexp": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, fmt.Errorf("regexp needs 1 arg")
		}
		re, err := compileRegex(a[0])
		if err != nil {
			return v, err
		}
		m, err := re.FindStringMatch(v)
		if err != nil || m == nil {
			return "", err
		}
		groups := m.Groups()
		if len(groups) > 1 {
			return groups[1].String(), nil
		}
		return m.String(), nil
	},
	"append": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, nil
		}
		return v + a[0], nil
	},
	"prepend": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, nil
		}
		return a[0] + v, nil
	},
	"trim": func(v string, a []string) (string, error) {
		if len(a) > 0 && a[0] != "" {
			return strings.Trim(v, a[0]), nil
		}
		return strings.TrimSpace(v), nil
	},
	"tolower": func(v string, _ []string) (string, error) { return strings.ToLower(v), nil },
	"toupper": func(v string, _ []string) (string, error) { return strings.ToUpper(v), nil },
	"split": func(v string, a []string) (string, error) {
		if len(a) < 2 {
			return v, fmt.Errorf("split needs 2 args")
		}
		parts := strings.Split(v, a[0])
		i, err := strconv.Atoi(a[1])
		if err != nil {
			return v, fmt.Errorf("split index %q: %w", a[1], err)
		}
		if i < 0 {
			i += len(parts)
		}
		if i < 0 || i >= len(parts) {
			return "", nil
		}
		return parts[i], nil
	},
	"urldecode": func(v string, _ []string) (string, error) {
		if d, err := url.QueryUnescape(v); err == nil {
			return d, nil
		}
		return v, nil
	},
	"urlencode": func(v string, _ []string) (string, error) { return url.QueryEscape(v), nil },
	"querystring": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, fmt.Errorf("querystring needs 1 arg")
		}
		u, err := url.Parse(v)
		if err != nil {
			return "", nil
		}
		return u.Query().Get(a[0]), nil
	},
	"dateparse": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, fmt.Errorf("dateparse needs 1 arg")
		}
		layout := dotnetLayout(a[0])
		t, err := time.Parse(layout, strings.TrimSpace(v))
		if err != nil && strings.Contains(layout, "-07:00") {
			// .NET's zzz also accepts offsets without a colon (+0800).
			t, err = time.Parse(strings.Replace(layout, "-07:00", "-0700", 1), strings.TrimSpace(v))
		}
		if err != nil {
			return v, fmt.Errorf("dateparse %q with %q: %w", v, a[0], err)
		}
		return t.Format(time.RFC3339), nil
	},
	"htmldecode": func(v string, _ []string) (string, error) { return html.UnescapeString(v), nil },
	"htmlencode": func(v string, _ []string) (string, error) { return html.EscapeString(v), nil },
	// validate keeps the words of v that appear in the comma-separated list in args[0].
	"validate": func(v string, a []string) (string, error) {
		if len(a) < 1 {
			return v, nil
		}
		allowed := map[string]bool{}
		for _, w := range strings.Split(a[0], ",") {
			allowed[strings.ToLower(strings.TrimSpace(w))] = true
		}
		var keep []string
		for _, w := range strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == '/' || r == ' ' || r == '|' || r == ';' || r == '.'
		}) {
			if allowed[strings.ToLower(w)] {
				keep = append(keep, w)
			}
		}
		return strings.Join(keep, ", "), nil
	},
	// jsonjoinarray selects an array from a JSON value and joins its items.
	"jsonjoinarray": func(v string, a []string) (string, error) {
		if len(a) < 2 {
			return v, fmt.Errorf("jsonjoinarray needs 2 args")
		}
		doc, err := decodeJSON([]byte(v))
		if err != nil {
			return "", err
		}
		tok, ok := jsonPath(doc, a[0])
		if !ok {
			return "", nil
		}
		arr, ok := tok.([]any)
		if !ok {
			s, _ := jsonString(tok)
			return s, nil
		}
		parts := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := jsonString(e); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, a[1]), nil
	},
	"timeago":   func(v string, _ []string) (string, error) { return timeAgo(v, time.Now()) },
	"fuzzytime": func(v string, _ []string) (string, error) { return timeAgo(v, time.Now()) },
	"diacritics": func(v string, _ []string) (string, error) {
		// Only the common "replace" mode; strips combining marks from Latin letters.
		return stripDiacritics(v), nil
	},
}

func init() { filters["timeparse"] = filters["dateparse"] }

func applyFilters(v string, fs []Filter, ctx *Context) (string, error) {
	for _, f := range fs {
		fn, ok := filters[f.Name]
		if !ok {
			return v, fmt.Errorf("unsupported filter %q", f.Name)
		}
		args := make([]string, len(f.Args))
		for i, a := range f.Args {
			r, err := render(a, ctx)
			if err != nil {
				return v, err
			}
			args[i] = r
		}
		var err error
		if v, err = fn(v, args); err != nil {
			return v, fmt.Errorf("filter %s: %w", f.Name, err)
		}
	}
	return v, nil
}

// dotnetLayout converts a .NET custom date format (as used by Cardigann's
// dateparse) into a Go time layout.
func dotnetLayout(f string) string {
	tokens := []struct{ net, goLayout string }{
		{"yyyy", "2006"}, {"yy", "06"},
		{"MMMM", "January"}, {"MMM", "Jan"}, {"MM", "01"}, {"M", "1"},
		{"dddd", "Monday"}, {"ddd", "Mon"}, {"dd", "02"}, {"d", "2"},
		{"HH", "15"}, {"H", "15"}, {"hh", "03"}, {"h", "3"},
		{"mm", "04"}, {"m", "4"}, {"ss", "05"}, {"s", "5"},
		{"fff", "000"}, {"ff", "00"}, {"f", "0"},
		{"tt", "PM"}, {"zzz", "-07:00"}, {"zz", "-07"}, {"z", "-07"},
		{"K", "Z07:00"},
	}
	var b strings.Builder
	for i := 0; i < len(f); {
		if f[i] == '\'' || f[i] == '"' { // quoted literal
			q := f[i]
			j := strings.IndexByte(f[i+1:], q)
			if j < 0 {
				b.WriteString(f[i+1:])
				break
			}
			b.WriteString(f[i+1 : i+1+j])
			i += j + 2
			continue
		}
		matched := false
		for _, t := range tokens {
			if strings.HasPrefix(f[i:], t.net) {
				b.WriteString(t.goLayout)
				i += len(t.net)
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte(f[i])
			i++
		}
	}
	return b.String()
}

// timeAgo turns relative dates ("3 hours ago", "yesterday", "2 weeks") into RFC3339.
func timeAgo(v string, now time.Time) (string, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch {
	case s == "" || s == "now" || s == "just now":
		return now.Format(time.RFC3339), nil
	case strings.HasPrefix(s, "today"):
		return now.Format(time.RFC3339), nil
	case strings.HasPrefix(s, "yesterday"):
		return now.AddDate(0, 0, -1).Format(time.RFC3339), nil
	}
	s = strings.NewReplacer("ago", "", ",", " ", "and", " ").Replace(s)
	fields := strings.Fields(s)
	t := now
	found := false
	for i := 0; i < len(fields); i++ {
		n := 1.0
		if f, err := strconv.ParseFloat(fields[i], 64); err == nil {
			n = f
			i++
			if i >= len(fields) {
				break
			}
		} else if fields[i] == "a" || fields[i] == "an" || fields[i] == "last" {
			i++
			if i >= len(fields) {
				break
			}
		}
		unit := strings.TrimSuffix(fields[i], "s")
		switch unit {
		case "sec", "second":
			t = t.Add(-time.Duration(n * float64(time.Second)))
		case "min", "minute":
			t = t.Add(-time.Duration(n * float64(time.Minute)))
		case "hr", "hour":
			t = t.Add(-time.Duration(n * float64(time.Hour)))
		case "day":
			t = t.Add(-time.Duration(n * 24 * float64(time.Hour)))
		case "week", "wk":
			t = t.Add(-time.Duration(n * 7 * 24 * float64(time.Hour)))
		case "month", "mo":
			t = t.AddDate(0, -int(n), 0)
		case "year", "yr":
			t = t.AddDate(-int(n), 0, 0)
		default:
			continue
		}
		found = true
	}
	if !found {
		return v, fmt.Errorf("timeago: cannot parse %q", v)
	}
	return t.Format(time.RFC3339), nil
}

func stripDiacritics(s string) string {
	repl := strings.NewReplacer(
		"á", "a", "à", "a", "ä", "a", "â", "a", "ã", "a", "å", "a",
		"é", "e", "è", "e", "ë", "e", "ê", "e",
		"í", "i", "ì", "i", "ï", "i", "î", "i",
		"ó", "o", "ò", "o", "ö", "o", "ô", "o", "õ", "o",
		"ú", "u", "ù", "u", "ü", "u", "û", "u",
		"ñ", "n", "ç", "c",
		"Á", "A", "À", "A", "Ä", "A", "Â", "A", "Ã", "A", "Å", "A",
		"É", "E", "È", "E", "Ë", "E", "Ê", "E",
		"Í", "I", "Ì", "I", "Ï", "I", "Î", "I",
		"Ó", "O", "Ò", "O", "Ö", "O", "Ô", "O", "Õ", "O",
		"Ú", "U", "Ù", "U", "Ü", "U", "Û", "U",
		"Ñ", "N", "Ç", "C",
	)
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, repl.Replace(s))
}

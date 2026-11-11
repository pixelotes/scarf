package cardigann

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// jsonRow is one result row of a JSON response. parent is the object the row
// was taken from when rows.attribute is set; fields reach it with "..name".
type jsonRow struct {
	v      any
	parent any
}

func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// jsonPath resolves a Cardigann JSON selector such as "data.movies",
// "files[0].name", "$" or "$[0].id" against v.
func jsonPath(v any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$")
	cur := v
	for path != "" {
		switch path[0] {
		case '.':
			path = path[1:]
			continue
		case '[':
			end := strings.IndexByte(path, ']')
			if end < 0 {
				return nil, false
			}
			idx, err := strconv.Atoi(strings.Trim(path[1:end], `'" `))
			if err != nil {
				// ['key'] form
				key := strings.Trim(path[1:end], `'" `)
				m, ok := cur.(map[string]any)
				if !ok {
					return nil, false
				}
				if cur, ok = m[key]; !ok {
					return nil, false
				}
			} else {
				arr, ok := cur.([]any)
				if !ok || idx < 0 || idx >= len(arr) {
					return nil, false
				}
				cur = arr[idx]
			}
			path = path[end+1:]
		default:
			end := strings.IndexAny(path, ".[")
			if end < 0 {
				end = len(path)
			}
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			if cur, ok = m[path[:end]]; !ok {
				return nil, false
			}
			path = path[end:]
		}
	}
	return cur, true
}

// jsonString formats a value the way Json.NET's JToken.ToString does for the
// cases definitions rely on: booleans are "True"/"False", arrays and objects
// are JSON text (the jsonjoinarray filter parses them).
func jsonString(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		if t {
			return "True", true
		}
		return "False", true
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

// jsonRowCond is a ":has(path:contains(x))" or ":not(path:contains(x))"
// condition on a rows selector.
type jsonRowCond struct {
	neg      bool
	path     string
	contains string
}

// splitRowSelector separates a JSON rows selector from its pseudo-class conditions.
func splitRowSelector(sel string) (string, []jsonRowCond, error) {
	base := sel
	var conds []jsonRowCond
	if i := strings.Index(sel, ":"); i >= 0 {
		base = sel[:i]
		rest := sel[i:]
		for rest != "" {
			var neg bool
			switch {
			case strings.HasPrefix(rest, ":not("):
				neg = true
			case strings.HasPrefix(rest, ":has("):
			default:
				return "", nil, fmt.Errorf("unsupported JSON selector %q", sel)
			}
			rest = rest[5:]
			// find the matching close paren
			depth, end := 1, -1
			for j := 0; j < len(rest); j++ {
				if rest[j] == '(' {
					depth++
				} else if rest[j] == ')' {
					depth--
					if depth == 0 {
						end = j
						break
					}
				}
			}
			if end < 0 {
				return "", nil, fmt.Errorf("unbalanced JSON selector %q", sel)
			}
			inner := rest[:end]
			rest = rest[end+1:]
			p, arg, ok := strings.Cut(inner, ":contains(")
			if !ok || !strings.HasSuffix(arg, ")") {
				return "", nil, fmt.Errorf("unsupported JSON selector condition %q", inner)
			}
			conds = append(conds, jsonRowCond{neg: neg, path: p, contains: strings.Trim(strings.TrimSuffix(arg, ")"), `"'`)})
		}
	}
	return base, conds, nil
}

func (c jsonRowCond) match(row any) bool {
	v, ok := jsonPath(row, c.path)
	s, _ := jsonString(v)
	hit := ok && strings.Contains(s, c.contains)
	return hit != c.neg
}

// jsonRows selects the result rows from a parsed JSON document.
func (d *Definition) jsonRows(doc any, tctx *Context) ([]jsonRow, error) {
	r := d.Search.Rows
	if r.Count.Selector != "" {
		if v, ok := jsonPath(doc, r.Count.Selector); ok {
			if s, _ := jsonString(v); s == "0" {
				return nil, nil
			}
		}
	}
	sel, err := render(r.Selector, tctx)
	if err != nil {
		return nil, err
	}
	base, conds, err := splitRowSelector(sel)
	if err != nil {
		return nil, err
	}
	tok, ok := jsonPath(doc, base)
	if !ok || tok == nil {
		return nil, nil
	}
	var items []any
	switch t := tok.(type) {
	case []any:
		items = t
	case map[string]any:
		// Some APIs return an object keyed by ID instead of an array.
		for _, v := range t {
			items = append(items, v)
		}
	default:
		return nil, fmt.Errorf("rows selector %q is not an array", base)
	}

	var rows []jsonRow
	for _, it := range items {
		keep := true
		for _, c := range conds {
			if !c.match(it) {
				keep = false
				break
			}
		}
		if !keep {
			continue
		}
		if r.Attribute == "" {
			rows = append(rows, jsonRow{v: it})
			continue
		}
		a, ok := jsonPath(it, r.Attribute)
		if !ok || a == nil {
			continue // missingAttributeEqualsNoResults, or a row without it
		}
		if arr, isArr := a.([]any); isArr && r.Multiple {
			for _, e := range arr {
				rows = append(rows, jsonRow{v: e, parent: it})
			}
			continue
		}
		rows = append(rows, jsonRow{v: a, parent: it})
	}
	return rows, nil
}

func (row jsonRow) extract(f Field, ctx *Context) (string, error) {
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
		src := row.v
		if strings.HasPrefix(sel, "..") {
			src, sel = row.parent, sel[2:]
		}
		tok, ok := jsonPath(src, sel)
		if !ok {
			return "", errNotFound
		}
		s, ok := jsonString(tok)
		if !ok {
			return "", errNotFound
		}
		v = s
		if f.Case != nil {
			matched := false
			if cv, ok := f.Case[v]; ok {
				v, matched = cv, true
			} else if cv, ok := f.Case["*"]; ok {
				v, matched = cv, true
			}
			if !matched {
				return "", errNotFound
			}
		}
	}
	return applyFilters(v, f.Filters, ctx)
}

// ParseJSON extracts results from a JSON response.
func (d *Definition) ParseJSON(data []byte, pageURL string, p Path, tctx *Context) ([]Result, error) {
	if m := p.Response.NoResultsMessage; m != nil && strings.TrimSpace(string(data)) == *m {
		return nil, nil
	}
	doc, err := decodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	rows, err := d.jsonRows(doc, tctx)
	if err != nil {
		return nil, err
	}
	var (
		results  []Result
		firstErr error
	)
	for _, row := range rows {
		res, err := d.buildResult(row.extract, pageURL, tctx)
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
		return nil, fmt.Errorf("%d rows found, none parsed: %w", len(rows), firstErr)
	}
	return results, nil
}

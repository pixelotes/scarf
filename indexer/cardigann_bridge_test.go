package indexer

import (
	"reflect"
	"testing"
)

func TestCardigannCategories(t *testing.T) {
	def := &Definition{CategoryMappings: []CategoryMapping{
		{IndexerCategory: "1", TorznabCategory: 5070}, // TV/Anime
		{IndexerCategory: "2", TorznabCategory: 2000}, // Movies
		{IndexerCategory: "3", TorznabCategory: 5040}, // TV/HD
	}}
	cases := []struct {
		param string
		want  []string
		ok    bool
	}{
		{"", nil, true},
		{"5070", []string{"1"}, true},
		{"5000", []string{"1", "3"}, true},
		{"2000,5040", []string{"2", "3"}, true},
		{"3000", nil, false},
	}
	for _, c := range cases {
		got, ok := cardigannCategories(def, c.param)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v %v, want %v %v", c.param, got, ok, c.want, c.ok)
		}
	}
}

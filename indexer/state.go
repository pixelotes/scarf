package indexer

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// IndexerState is what the user chose for one indexer. It lives in its own
// file (indexers.yml) so definition files can be replaced by upstream updates
// without losing it.
type IndexerState struct {
	Enabled  *bool             `yaml:"enabled,omitempty"`
	Settings map[string]string `yaml:"settings,omitempty"`
}

// StateStore reads and writes indexers.yml.
type StateStore struct {
	path string
	mu   sync.Mutex
	data struct {
		Indexers map[string]*IndexerState `yaml:"indexers"`
	}
}

// NewStateStore loads the state file at path. A missing file is an empty state.
// An empty path keeps the state in memory only.
func NewStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path}
	s.data.Indexers = map[string]*IndexerState{}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read state file: %w", err)
	}
	if err := yaml.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("could not parse state file %s: %w", path, err)
	}
	if s.data.Indexers == nil {
		s.data.Indexers = map[string]*IndexerState{}
	}
	return s, nil
}

// Get returns a copy of an indexer's state; ok is false when there is none.
func (s *StateStore) Get(key string) (IndexerState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.data.Indexers[key]
	if !ok {
		return IndexerState{}, false
	}
	out := IndexerState{Enabled: st.Enabled, Settings: map[string]string{}}
	for k, v := range st.Settings {
		out.Settings[k] = v
	}
	return out, true
}

// EnabledKeys lists the indexers marked enabled.
func (s *StateStore) EnabledKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for k, st := range s.data.Indexers {
		if st.Enabled != nil && *st.Enabled {
			keys = append(keys, k)
		}
	}
	return keys
}

// SetEnabled records whether an indexer is enabled.
func (s *StateStore) SetEnabled(key string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entry(key).Enabled = &enabled
	return s.save()
}

// SetSettings merges settings into an indexer's saved values.
func (s *StateStore) SetSettings(key string, settings map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.entry(key)
	if st.Settings == nil {
		st.Settings = map[string]string{}
	}
	for k, v := range settings {
		st.Settings[k] = v
	}
	return s.save()
}

func (s *StateStore) entry(key string) *IndexerState {
	st, ok := s.data.Indexers[key]
	if !ok {
		st = &IndexerState{}
		s.data.Indexers[key] = st
	}
	return st
}

// save writes the file atomically. It holds credentials, so it is 0600.
func (s *StateStore) save() error {
	if s.path == "" {
		return nil
	}
	b, err := yaml.Marshal(&s.data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".indexers-*.yml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append([]byte("# Scarf indexer state: enabled flags and settings. Managed by Scarf.\n"), b...)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

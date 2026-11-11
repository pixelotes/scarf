package indexer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const upstreamPublic = `id: pubone
name: Pub One
description: A public tracker
language: en-US
type: public
links: [https://pub.invalid/]
settings:
  - {name: sort, type: select, default: date, options: {date: Date, size: Size}}
search:
  paths: [{path: search}]
  rows: {selector: tr}
  fields:
    title: {selector: a}
    download: {selector: a, attribute: href}
`

const upstreamPrivate = `id: privone
name: Priv One
type: private
links: [https://priv.invalid/]
settings:
  - {name: username, type: text}
  - {name: password, type: password}
login:
  path: login.php
  method: post
  inputs: {u: "{{ .Config.username }}", p: "{{ .Config.password }}"}
search:
  paths: [{path: search}]
  rows: {selector: tr}
  fields:
    title: {selector: a}
    download: {selector: a, attribute: href}
`

const upstreamCaptcha = `id: capone
name: Cap One
type: private
links: [https://cap.invalid/]
login:
  path: login.php
  method: form
  captcha: {type: image, selector: img, input: c}
search:
  paths: [{path: search}]
  rows: {selector: tr}
  fields:
    title: {selector: a}
`

func tarball(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestUpstreamCatalog(t *testing.T) {
	archive := tarball(t, map[string]string{
		"Indexers-master/definitions/v11/pubone.yml":  upstreamPublic,
		"Indexers-master/definitions/v11/privone.yml": upstreamPrivate,
		"Indexers-master/definitions/v11/capone.yml":  upstreamCaptcha,
		"Indexers-master/definitions/v10/old.yml":     upstreamPublic, // other schema: ignored
		"Indexers-master/definitions/v11/../x.yml":    upstreamPublic, // path tricks: ignored
		"Indexers-master/README.md":                   "readme",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()

	data := t.TempDir()
	local := t.TempDir()
	opts := ManagerOptions{
		StatePath:   filepath.Join(data, "indexers.yml"),
		UpstreamDir: filepath.Join(data, "upstream"),
		UpstreamURL: srv.URL,
	}
	m, err := NewManager(local, 5, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if cat, err := m.UpstreamCatalog(); err != nil || len(cat.Entries) != 0 {
		t.Fatalf("before sync: %+v %v", cat, err)
	}
	n, err := m.SyncUpstream(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("sync: %d %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(data, "x.yml")); err == nil {
		t.Fatal("archive path escaped the upstream directory")
	}
	cat, err := m.UpstreamCatalog()
	if err != nil || len(cat.Entries) != 3 {
		t.Fatalf("catalog: %+v %v", cat, err)
	}
	for _, e := range cat.Entries {
		if e.ID == "capone" && (e.Supported || !strings.Contains(e.Reason, "captcha")) {
			t.Errorf("captcha entry: %+v", e)
		}
		if e.ID == "pubone" && (!e.Supported || e.Name != "Pub One" || e.Enabled) {
			t.Errorf("pubone entry: %+v", e)
		}
	}
	if len(m.GetAllIndexers()) != 0 {
		t.Fatal("upstream definitions must not load until enabled")
	}

	// Enable, configure, then check everything survives a restart.
	if err := m.ToggleIndexerEnabled("privone", true); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateIndexerUserConfig("privone", map[string]string{"username": "me", "password": "s3cret"}); err != nil {
		t.Fatal(err)
	}
	// An empty password from the UI means "unchanged".
	if err := m.UpdateIndexerUserConfig("privone", map[string]string{"username": "me2", "password": ""}); err != nil {
		t.Fatal(err)
	}
	if err := m.ToggleIndexerEnabled("capone", true); err == nil {
		t.Error("unsupported definition enabled")
	}
	if err := m.ToggleIndexerEnabled("nope", true); err == nil {
		t.Error("unknown definition enabled")
	}
	m.Close()

	if info, err := os.Stat(opts.StatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", info, err)
	}
	m2, err := NewManager(local, 5, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	def, ok := m2.GetIndexer("privone")
	if !ok || !bool(def.Enabled) || def.Source != SourceUpstream {
		t.Fatalf("privone after restart: %+v %v", def, ok)
	}
	if def.UserConfig["username"] != "me2" || def.UserConfig["password"] != "s3cret" {
		t.Errorf("settings after restart: %v", def.UserConfig)
	}
	if _, ok := m2.GetIndexer("capone"); ok {
		t.Error("capone loaded")
	}

	// Disabling an upstream indexer unloads it; it stays in the catalog.
	if err := m2.ToggleIndexerEnabled("privone", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.GetIndexer("privone"); ok {
		t.Error("disabled upstream indexer still loaded")
	}
}

func TestLocalDefinitionWinsAndStateOverridesFile(t *testing.T) {
	data := t.TempDir()
	local := t.TempDir()
	// An older Scarf wrote enabled into the file; the state file wins once set.
	os.WriteFile(filepath.Join(local, "pubone.yml"), []byte(upstreamPublic+"enabled: true\n"), 0o644)
	os.MkdirAll(filepath.Join(data, "upstream"), 0o755)
	os.WriteFile(filepath.Join(data, "upstream", "pubone.yml"), []byte(upstreamPublic), 0o644)
	opts := ManagerOptions{StatePath: filepath.Join(data, "indexers.yml"), UpstreamDir: filepath.Join(data, "upstream")}

	m, err := NewManager(local, 5, opts)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := m.GetIndexer("pubone")
	if def.Source != SourceLocal || !bool(def.Enabled) {
		t.Fatalf("got %+v", def)
	}
	before, _ := os.ReadFile(filepath.Join(local, "pubone.yml"))
	if err := m.ToggleIndexerEnabled("pubone", false); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateIndexerUserConfig("pubone", map[string]string{"sort": "size"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(local, "pubone.yml"))
	if !bytes.Equal(before, after) {
		t.Error("definition file was modified")
	}
	m.Close()

	m2, err := NewManager(local, 5, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	def, _ = m2.GetIndexer("pubone")
	if bool(def.Enabled) || def.UserConfig["sort"] != "size" {
		t.Fatalf("state not applied: enabled=%v config=%v", def.Enabled, def.UserConfig)
	}
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"go-indexer/indexer"
)

// UpstreamCatalog lists the downloaded upstream definitions.
func (h *APIHandler) UpstreamCatalog(w http.ResponseWriter, r *http.Request) {
	cat, err := h.Manager.UpstreamCatalog()
	if errors.Is(err, indexer.ErrUpstreamDisabled) {
		http.Error(w, "upstream catalog is disabled (UPSTREAM_SYNC=false)", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Failed to read upstream catalog", "error", err)
		http.Error(w, "failed to read catalog", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cat)
}

// SyncUpstream downloads the upstream definitions and replaces the catalog.
func (h *APIHandler) SyncUpstream(w http.ResponseWriter, r *http.Request) {
	// Not tied to the request: a closed browser tab must not leave a half-done sync.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := h.Manager.SyncUpstream(ctx)
	if errors.Is(err, indexer.ErrUpstreamDisabled) {
		http.Error(w, "upstream catalog is disabled (UPSTREAM_SYNC=false)", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Upstream sync failed", "error", err)
		http.Error(w, "sync failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"count": n})
}

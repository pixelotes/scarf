package api

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"go-indexer/auth"
	"go-indexer/indexer"

	"github.com/go-chi/chi/v5"
)

// downloadLink returns the link a client should use for a result. Results of
// private trackers and of indexers with a download block go through Scarf's
// download proxy, which holds the session cookies and follows the block.
func downloadLink(r *http.Request, res indexer.SearchResult) string {
	if !res.Proxied || res.IndexerKey == "" {
		return res.DownloadURL
	}
	sig := auth.Sign(res.IndexerKey + "\n" + res.DownloadURL)
	return fmt.Sprintf("%s/torznab/%s/download?link=%s&sig=%s",
		publicBaseURL(r), url.PathEscape(res.IndexerKey), url.QueryEscape(res.DownloadURL), sig)
}

// publicBaseURL is the scheme and host the client used to reach Scarf,
// honouring a reverse proxy's X-Forwarded-* headers.
func publicBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host
}

// proxyLinks rewrites the download links of results for the given request.
func proxyLinks(r *http.Request, results []indexer.SearchResult) []indexer.SearchResult {
	out := make([]indexer.SearchResult, len(results))
	for i, res := range results {
		res.DownloadURL = downloadLink(r, res)
		res.Proxied = false
		out[i] = res
	}
	return out
}

// TorznabDownload serves /torznab/{indexer}/download: it checks the link's
// signature, resolves it with the indexer's session and streams the .torrent,
// or redirects to a magnet link.
func (h *APIHandler) TorznabDownload(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "indexer")
	link := r.URL.Query().Get("link")
	if link == "" || !auth.Verify(key+"\n"+link, r.URL.Query().Get("sig")) {
		http.Error(w, "invalid or expired download link", http.StatusForbidden)
		return
	}
	redirect, resp, err := h.Manager.Download(r.Context(), key, link)
	if err != nil {
		slog.Warn("Download failed", "indexer", key, "error", err)
		status := http.StatusBadGateway
		if errors.Is(err, indexer.ErrIndexerNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, "download failed: "+err.Error(), status)
		return
	}
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if ct == "" || strings.HasPrefix(ct, "application/octet-stream") {
		ct = "application/x-bittorrent"
	}
	w.Header().Set("Content-Type", ct)
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxTorrentSize)); err != nil {
		slog.Warn("Download copy failed", "indexer", key, "error", err)
	}
}

const maxTorrentSize = 20 << 20

package indexer

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"
)

// loggingRoundTripper is a middleware for http.Client that logs requests and responses.
type loggingRoundTripper struct {
	proxied http.RoundTripper
}

// RoundTrip executes a single HTTP transaction, returning a Response for the provided Request.
func (lrt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// We don't want to log the request body for binary data or large files.
	// We'll log headers and URL, which is usually enough for debugging.
	slog.Debug("Making HTTP request",
		"method", req.Method,
		"url", req.URL.String(),
	)

	start := time.Now()
	resp, err := lrt.proxied.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		slog.Error("HTTP request failed", "error", err, "duration", duration)
		return nil, err
	}

	// To log the response body, we must read it and then replace it.
	// Use limited read to prevent DoS attacks via large responses in debug mode
	bodyBytes, readErr := limitedReadAll(resp.Body, MaxLogResponseSize)
	if readErr != nil {
		slog.Warn("Failed to read response body for logging", "error", readErr)
		// If we can't read the body, close it and create an empty one
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewBuffer([]byte("<body too large or read failed>")))
	} else {
		// After reading, the original body is empty. We replace it with a new reader.
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Dump the full response for debugging.
	respDump, dumpErr := httputil.DumpResponse(resp, true)
	if dumpErr != nil {
		slog.Warn("Failed to dump response", "error", dumpErr)
	}

	slog.Debug("Received HTTP response",
		"status", resp.Status,
		"duration", duration,
		"full_response", string(respDump),
	)

	return resp, nil
}

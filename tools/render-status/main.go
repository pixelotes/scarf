// render-status reads check's JSON output and prints a markdown table.
// Usage: render-status [path-or-dash]   (default: stdin)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Result struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Status    string `json:"status"`
	Results   int    `json:"results"`
	LatencyMs int64  `json:"latency_ms"`
	Note      string `json:"note,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	src := os.Stdin
	if len(os.Args) > 1 && os.Args[1] != "-" {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		defer f.Close()
		src = f
	}

	var results []Result
	if err := json.NewDecoder(src).Decode(&results); err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}

	fmt.Println("| Tracker | Status | Enabled | Results | Latency | Note |")
	fmt.Println("|---|---|---|---:|---:|---|")
	for _, r := range results {
		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			r.Name,
			statusIcon(r.Status),
			boolIcon(r.Enabled),
			resultsCell(r),
			latencyCell(r),
			noteCell(r),
		)
	}

	var g, y, rd, sk int
	for _, r := range results {
		switch r.Status {
		case "green":
			g++
		case "yellow":
			y++
		case "red":
			rd++
		case "skipped":
			sk++
		}
	}
	fmt.Printf("\n**Summary**: 🟢 %d · 🟡 %d · 🔴 %d · ⏭️ %d (total %d)\n",
		g, y, rd, sk, len(results))
}

func statusIcon(s string) string {
	switch s {
	case "green":
		return "🟢 OK"
	case "yellow":
		return "🟡 Warn"
	case "red":
		return "🔴 Fail"
	case "skipped":
		return "⏭️ Skip"
	default:
		return "❓ ?"
	}
}

func boolIcon(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func resultsCell(r Result) string {
	if r.Status == "red" || r.Status == "skipped" {
		return "—"
	}
	return fmt.Sprintf("%d", r.Results)
}

func latencyCell(r Result) string {
	if r.LatencyMs == 0 {
		return "—"
	}
	return fmt.Sprintf("%dms", r.LatencyMs)
}

func noteCell(r Result) string {
	msg := r.Note
	if r.Error != "" {
		msg = r.Error
	}
	if len(msg) > 80 {
		msg = msg[:77] + "..."
	}
	return strings.ReplaceAll(msg, "|", `\|`)
}

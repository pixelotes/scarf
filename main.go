package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go-indexer/api"
	"go-indexer/auth"
	"go-indexer/cache"
	"go-indexer/config"
	"go-indexer/indexer"
	"go-indexer/logger"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/robfig/cron/v3"
)

// getScheduleInterval parses a cron expression and returns its execution interval.
func getScheduleInterval(scheduleStr string) (time.Duration, error) {
	// Handle standard cron descriptors first for efficiency.
	switch scheduleStr {
	case "@hourly":
		return time.Hour, nil
	case "@daily":
		return 24 * time.Hour, nil
	case "@weekly":
		return 7 * 24 * time.Hour, nil
	}
	// For `@every X` descriptors.
	if strings.HasPrefix(scheduleStr, "@every") {
		return time.ParseDuration(strings.TrimPrefix(scheduleStr, "@every "))
	}

	// Fallback to full cron expression parsing for custom schedules.
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(scheduleStr)
	if err != nil {
		return 0, err
	}

	// Calculate interval by finding the difference between the next two run times.
	now := time.Now()
	nextRun := schedule.Next(now)
	nextNextRun := schedule.Next(nextRun)

	return nextNextRun.Sub(nextRun), nil
}

// runScheduledSearch encapsulates the logic for a single scheduled indexer search.
func runScheduledSearch(cfg *config.ConfigOptions, idxManager *indexer.Manager, appCache *cache.Cache, indexerKey string, indexerDef *indexer.Definition) {
	slog.Info("Scheduler: Running job", "indexer", indexerDef.Name)
	// Create a new context with the configured timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout*2) // Give scheduled jobs double timeout
	defer cancel()

	results, err := idxManager.Search(ctx, indexerKey, indexer.SearchParams{})
	if err != nil {
		slog.Error("Scheduler: Failed to fetch latest", "indexer", indexerDef.Name, "error", err)
		return
	}
	slog.Info("Scheduler: Successfully fetched releases", "indexer", indexerDef.Name, "count", len(results))

	if len(results) > 0 && appCache != nil {
		latestCacheKey := api.GenerateLatestCacheKey(indexerKey)
		cachedResult := api.CachedSearchResult{
			Results:    results,
			CachedAt:   time.Now(),
			IndexerKey: indexerKey,
		}
		if jsonData, err := json.Marshal(cachedResult); err == nil {
			// Use the dedicated TTL for 'latest' results
			appCache.Set(latestCacheKey, jsonData, cfg.LatestCacheTTL)
			slog.Debug("Scheduler: Cached latest results", "indexer", indexerDef.Name, "key", latestCacheKey)
		}
	}
}

func main() {
	// Parse command line flags
	var showHelp bool
	var showConfig bool
	flag.BoolVar(&showHelp, "help", false, "Show configuration help")
	flag.BoolVar(&showHelp, "h", false, "Show configuration help (shorthand)")
	flag.BoolVar(&showConfig, "config", false, "Show current configuration")
	flag.Parse()

	if showHelp {
		config.PrintConfigHelp()
		os.Exit(0)
	}

	// --- Load and Validate Configuration ---
	cfg, err := config.GetConfig()
	if err != nil {
		slog.Error("Configuration error", "error", err)
		slog.Info("Run with --help to see available configuration options")
		os.Exit(1)
	}

	// --- Initialize Logger ---
	logger.Init(cfg.DebugMode)

	slog.Info("--- Go Indexer Starting Up ---", "version", "1.0.0")

	if showConfig {
		cfg.PrintConfig()
	}

	if cfg.DebugMode {
		slog.Info("Debug mode enabled - verbose logging active")
	}

	if cfg.SkipTLSVerify {
		slog.Warn("TLS certificate verification is DISABLED - use only for testing!")
	}

	slog.Info("Configuration loaded",
		"port", cfg.AppPort,
		"cache_enabled", cfg.CacheEnabled,
		"cache_ttl", cfg.CacheTTL,
		"web_ui", cfg.WebUIEnabled,
		"definitions_path", cfg.DefinitionsPath,
	)

	// --- Initialize Enhanced Cache ---
	var appCache *cache.Cache
	if cfg.CacheEnabled {
		slog.Info("Initializing cache", "path", cfg.DBPath, "max_size_mb", cfg.MaxCacheSize/(1024*1024))
		appCache, err = cache.NewCacheWithConfig(cfg.DBPath, cfg.MaxCacheSize)
		if err != nil {
			slog.Error("Failed to initialize cache", "error", err)
			os.Exit(1)
		}

		// Display initial cache statistics
		stats := appCache.GetStats()
		slog.Info("Cache initialized",
			"existing_entries", stats.EntryCount,
			"size_mb", stats.Size/(1024*1024),
			"hit_ratio", stats.HitRatio,
		)
	} else {
		slog.Info("Cache is disabled")
	}

	// --- Initialize Security ---
	auth.Configure(cfg.JWTSecret)
	slog.Info("Security configured", "flexget_api_key", maskAPIKey(cfg.FlexgetAPIKey))

	// --- Initialize Indexer Manager ---
	slog.Info("Loading indexer definitions", "path", cfg.DefinitionsPath)
	idxManager, err := indexer.NewManager(cfg.DefinitionsPath, cfg.MaxFailures)
	if err != nil {
		slog.Error("Failed to load indexer definitions", "error", err)
		os.Exit(1)
	}

	allIndexers := idxManager.GetAllIndexers()
	if len(allIndexers) == 0 {
		slog.Warn("No indexer definitions were loaded - check your definitions path")
	} else {
		enabledCount := 0
		for _, def := range allIndexers {
			if def.Enabled {
				enabledCount++
			}
		}
		slog.Info("Indexer definitions loaded",
			"total", len(allIndexers),
			"enabled", enabledCount,
		)
	}

	// --- Scheduler Setup ---
	if cfg.CronjobsEnabled && cfg.CacheEnabled {
		slog.Info("Scheduler is enabled")
		c := cron.New()

		// Function to update scheduled jobs when indexers are reloaded
		updateScheduledJobs := func() {
			slog.Info("Updating scheduled jobs after indexer reload...")

			// Stop existing cron jobs and create a new scheduler
			if c != nil {
				c.Stop()
			}
			c = cron.New()

			// Re-add jobs for all indexers with schedules
			jobCount := 0
			for key, def := range idxManager.GetAllIndexers() {
				if def.Schedule == "" || !def.Enabled {
					continue
				}
				indexerKey, indexerDef := key, def
				_, err := c.AddFunc(def.Schedule, func() {
					runScheduledSearch(cfg, idxManager, appCache, indexerKey, indexerDef)
				})
				if err != nil {
					slog.Warn("Could not schedule job", "indexer", def.Name, "error", err)
				} else {
					jobCount++
				}
			}

			if jobCount > 0 {
				c.Start()
				slog.Info("Scheduler updated", "jobs", jobCount)
			} else {
				slog.Info("No scheduled jobs configured")
			}
		}

		// Set up initial scheduled jobs
		updateScheduledJobs()

		// Trigger initial run of all scheduled jobs if their cache is stale, using a worker pool.
		slog.Info("Scheduler: Performing initial run check for all scheduled jobs...")

		type job struct {
			key string
			def *indexer.Definition
		}

		jobs := make(chan job, len(allIndexers))
		var wg sync.WaitGroup

		// Define the number of concurrent workers.
		numWorkers := cfg.MaxConcurrentSearches
		for w := 1; w <= numWorkers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for j := range jobs {
					if appCache != nil {
						latestCacheKey := api.GenerateLatestCacheKey(j.key)
						// --- START CHANGE: Use the new read-only Get method ---
						cachedData, found := appCache.GetWithoutUpdate(latestCacheKey)
						// --- END CHANGE ---

						if found {
							var cachedResult api.CachedSearchResult
							if err := json.Unmarshal(cachedData, &cachedResult); err == nil {
								scheduleInterval, err := getScheduleInterval(j.def.Schedule)
								if err != nil {
									slog.Warn("Could not parse schedule for initial run check, running job anyway.", "worker", workerID, "indexer", j.def.Name, "error", err)
									runScheduledSearch(cfg, idxManager, appCache, j.key, j.def)
									continue
								}

								if time.Since(cachedResult.CachedAt) < scheduleInterval {
									slog.Info("Scheduler: Skipping initial run, cache is recent", "worker", workerID, "indexer", j.def.Name, "cache_age", time.Since(cachedResult.CachedAt).Round(time.Second))
									continue
								}
								slog.Info("Scheduler: Cache is stale, performing initial run", "worker", workerID, "indexer", j.def.Name)
							}
						}
					}
					runScheduledSearch(cfg, idxManager, appCache, j.key, j.def)
				}
			}(w)
		}

		// Add jobs to the queue
		for key, def := range idxManager.GetAllIndexers() {
			if def.Schedule != "" && def.Enabled {
				jobs <- job{key: key, def: def}
			}
		}
		close(jobs)

		// Set the reload callback for the indexer manager
		idxManager.SetReloadCallback(updateScheduledJobs)
	} else {
		slog.Info("Scheduler is disabled (either by CRONJOBS_ENABLED=false or CACHE_ENABLED=false)")
	}

	// --- API Server Setup ---
	r := chi.NewRouter()

	// Enhanced middleware setup
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5)) // Enable gzip compression (level 5 = balanced speed/compression)
	r.Use(middleware.Timeout(cfg.RequestTimeout))

	// Security headers middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// Corrected Content-Security-Policy
			if !cfg.DebugMode {
				// This policy allows inline styles/scripts and WebSocket connections, which are needed by the UI.
				csp := "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
				w.Header().Set("Content-Security-Policy", csp)
			}

			// Limit request body size to 1MB
			r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
			next.ServeHTTP(w, r)
		})
	})

	// Create API handler with enhanced configuration
	apiHandler := api.NewAPIHandler(
		idxManager,
		appCache,
		cfg.CacheTTL,
		cfg.LatestCacheTTL,
		cfg.FlexgetAPIKey,
		cfg.UIPassword,
		cfg.DefaultAPILimit,
		cfg.MaxConcurrentSearches,
	)

	// --- Public / Unauthenticated Routes ---
	r.Get("/health", apiHandler.HealthCheck)
	r.Get("/api/health", apiHandler.HealthCheck)
	r.Get("/api/v1/test_indexer", apiHandler.TestIndexer)

	// Add cache statistics endpoint (useful for monitoring)
	r.Get("/api/cache/stats", func(w http.ResponseWriter, r *http.Request) {
		if appCache != nil {
			stats := appCache.GetStats()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(stats)
		} else {
			http.Error(w, `{"error": "cache is disabled"}`, http.StatusServiceUnavailable)
		}
	})

	// Torznab API endpoints
	r.Get("/torznab/{indexer}/api", apiHandler.TorznabAPI)
	r.Get("/torznab/{indexer}/latest", apiHandler.TorznabLatest)
	r.Get("/torznab/{indexer}", apiHandler.TorznabSearch)

	if !cfg.WebUIEnabled {
		slog.Info("Web UI is disabled")
		slog.Info("Available endpoints:")
		slog.Info("  Health check: http://localhost:" + cfg.AppPort + "/health")
		slog.Info("  Cache stats:  http://localhost:" + cfg.AppPort + "/api/cache/stats")
		slog.Info("  Torznab API:  http://localhost:" + cfg.AppPort + "/torznab/{indexer}/api")

		server := &http.Server{
			Addr:         ":" + cfg.AppPort,
			Handler:      r,
			ReadTimeout:  cfg.RequestTimeout,
			WriteTimeout: cfg.RequestTimeout * 2,
		}
		startServer(server, idxManager, appCache)
		return
	}

	// --- Web UI Routes (if enabled) ---
	slog.Info("Web UI enabled")
	slog.Info("Dashboard: http://localhost:" + cfg.AppPort)
	slog.Info("Login with password: " + maskAPIKey(cfg.UIPassword))

	r.Post("/api/v1/login", apiHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Get("/api/v1/indexers", apiHandler.ListIndexers)
		r.Get("/api/v1/search", apiHandler.WebSearch)
		r.Get("/api/v1/flexget_key", apiHandler.GetFlexgetAPIKey)
		r.Post("/api/v1/indexer/toggle", apiHandler.ToggleIndexer)
		r.Post("/api/v1/indexer/config", apiHandler.UpdateIndexerConfig)
		r.Get("/api/v1/logs", logger.WebSocketHandler)
		r.Get("/metrics", apiHandler.MetricsHandler)

		// Enhanced cache management endpoints
		r.Get("/api/v1/cache/stats", apiHandler.CacheStatsHandler)
		r.Get("/api/v1/cache/popular", func(w http.ResponseWriter, r *http.Request) {
			if appCache != nil {
				popular := appCache.GetPopularKeys(10)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"popular_keys": popular,
				})
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})
		r.Delete("/api/v1/cache", apiHandler.CacheManagementHandler)
		r.Post("/api/v1/cache/clear", func(w http.ResponseWriter, r *http.Request) {
			if appCache != nil {
				appCache.Clear()
				slog.Info("Cache cleared by user request")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})

		// Stats endpoint
		r.Get("/api/v1/stats", apiHandler.AppStatsHandler)
	})

	// --- Static File Serving ---
	// Serve all static files from web directory
	// This handles both the root index.html and any other assets
	fs := http.FileServer(http.Dir("./web/"))
	r.Handle("/*", http.StripPrefix("/", fs))

	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      r,
		ReadTimeout:  cfg.RequestTimeout,
		WriteTimeout: cfg.RequestTimeout * 2,
	}
	startServer(server, idxManager, appCache)
}

// startServer handles graceful shutdown with enhanced cleanup
func startServer(server *http.Server, idxManager *indexer.Manager, appCache *cache.Cache) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Server listening", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-sigChan
	slog.Info("Received signal, shutting down gracefully", "signal", sig)

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if appCache != nil {
		// Display final cache statistics before shutdown
		stats := appCache.GetStats()
		slog.Info("Final cache statistics",
			"hits", stats.Hits,
			"misses", stats.Misses,
			"hit_ratio", stats.HitRatio,
			"entries", stats.EntryCount,
			"size_mb", stats.Size/(1024*1024),
			"evictions", stats.Evictions,
		)
	}

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server shutdown error", "error", err)
	} else {
		slog.Info("Server shutdown completed")
	}

	// Close API handler (stops rate limiter cleanup)
	apiHandler.Close()
	slog.Info("API handler closed")

	// Close indexer manager
	if err := idxManager.Close(); err != nil {
		slog.Error("Error closing indexer manager", "error", err)
	} else {
		slog.Info("Indexer manager closed")
	}

	if appCache != nil {
		// Close enhanced cache
		if err := appCache.Close(); err != nil {
			slog.Error("Error closing cache", "error", err)
		} else {
			slog.Info("Cache closed")
		}
	}

	slog.Info("Application shutdown complete")
}

// maskAPIKey masks sensitive values for display
func maskAPIKey(key string) string {
	if len(key) <= 4 {
		return strings.Repeat("*", len(key))
	}
	return key[:2] + strings.Repeat("*", len(key)-4) + key[len(key)-2:]
}

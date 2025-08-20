package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

func main() {
	// --- Configuration ---
	port := config.GetEnv("APP_PORT", "8080")
	defPath := config.GetEnv("DEFINITIONS_PATH", "./definitions")
	cacheTTL := config.GetEnvAsDuration("CACHE_TTL", 15*time.Minute)
	dbPath := config.GetEnv("DB_PATH", "./data/indexer-cache.db")
	webUIEnabled := config.GetEnvAsBool("WEB_UI", true)
	debugMode := config.GetEnvAsBool("DEBUG", false)

	// Security Configuration
	uiPassword := config.GetEnv("UI_PASSWORD", "password")
	flexgetAPIKey := config.GetEnv("FLEXGET_API_KEY", config.GenerateRandomString(16))
	jwtSecret := config.GetEnv("JWT_SECRET", config.GenerateRandomString(32))

	// --- Initialization ---
	logger.Init(debugMode) // Initialize the logger first
	auth.Configure(jwtSecret)

	slog.Info("--- Go Indexer Starting Up ---", "log_level", ifThen(debugMode, "DEBUG", "INFO"))
	slog.Info("Flexget API Key", "key", flexgetAPIKey)

	appCache, err := cache.NewCache(dbPath)
	if err != nil {
		slog.Error("Failed to initialize cache", "error", err)
		os.Exit(1)
	}
	slog.Info("Cache initialized", "path", dbPath)

	idxManager, err := indexer.NewManager(defPath)
	if err != nil {
		slog.Error("Failed to load indexer definitions", "error", err)
		os.Exit(1)
	}
	if len(idxManager.GetAllIndexers()) == 0 {
		slog.Warn("No indexer definitions were loaded.")
	}

	// --- Scheduler setup ---
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
		for key, def := range idxManager.GetAllIndexers() {
			if def.Schedule == "" || !def.Enabled {
				continue
			}
			indexerKey, indexerDef := key, def
			_, err := c.AddFunc(def.Schedule, func() {
				slog.Info("Scheduler: Running job", "indexer", indexerDef.Name)
				// Create a new context for the background job.
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // Give scheduled jobs a longer timeout
				defer cancel()
				results, err := idxManager.Search(ctx, indexerKey, "", "")
				if err != nil {
					slog.Error("Scheduler: Failed to fetch latest", "indexer", indexerDef.Name, "error", err)
					return
				}
				slog.Info("Scheduler: Successfully fetched releases", "indexer", indexerDef.Name, "count", len(results))
			})
			if err != nil {
				slog.Warn("Could not schedule job", "indexer", def.Name, "error", err)
			}
		}

		if len(c.Entries()) > 0 {
			c.Start()
			slog.Info("Scheduler updated", "jobs", len(c.Entries()))
		}
	}

	// Set up initial scheduled jobs
	updateScheduledJobs()

	// Set the reload callback for the indexer manager
	idxManager.SetReloadCallback(updateScheduledJobs)

	// --- API Server Setup ---
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Create API handler with the new constructor
	apiHandler := api.NewAPIHandler(
		idxManager,
		appCache,
		cacheTTL,
		flexgetAPIKey,
		uiPassword,
	)

	// --- Public / Unauthenticated Routes ---
	r.Get("/health", apiHandler.HealthCheck)
	r.Get("/api/health", apiHandler.HealthCheck)

	r.Get("/torznab/{indexer}/api", apiHandler.TorznabAPI)
	r.Get("/torznab/{indexer}", apiHandler.TorznabSearch)

	if !webUIEnabled {
		slog.Info("Web UI is disabled. Set WEB_UI=true to enable it.")
		slog.Info("Health check available", "url", "http://localhost:"+port+"/health")
		slog.Info("Starting API-only server", "port", port)
		server := &http.Server{Addr: ":" + port, Handler: r}
		startServer(server, idxManager)
		return
	}

	// --- Web UI Routes (if enabled) ---
	slog.Info("Web UI is enabled", "password", uiPassword)
	slog.Info("Server starting", "url", "http://localhost:"+port)

	r.Post("/api/v1/login", apiHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Get("/api/v1/indexers", apiHandler.ListIndexers)
		r.Get("/api/v1/search", apiHandler.WebSearch)
		r.Get("/api/v1/test_indexer", apiHandler.TestIndexer)
		r.Get("/api/v1/flexget_key", apiHandler.GetFlexgetAPIKey)
		r.Post("/api/v1/indexer/toggle", apiHandler.ToggleIndexer)
		r.Post("/api/v1/indexer/config", apiHandler.UpdateIndexerConfig) // New route
		r.Get("/api/v1/logs", logger.WebSocketHandler)
	})

	fs := http.FileServer(http.Dir("./web"))
	r.Handle("/*", fs)

	server := &http.Server{Addr: ":" + port, Handler: r}
	startServer(server, idxManager)
}

// startServer handles graceful shutdown
func startServer(server *http.Server, idxManager *indexer.Manager) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server shutdown error", "error", err)
	} else {
		slog.Info("Server shutdown completed")
	}

	if err := idxManager.Close(); err != nil {
		slog.Error("Error closing indexer manager", "error", err)
	} else {
		slog.Info("Indexer manager closed")
	}

	slog.Info("Application shutdown complete")
}

// ifThen is a simple ternary helper
func ifThen[T any](condition bool, a, b T) T {
	if condition {
		return a
	}
	return b
}

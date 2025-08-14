package main

import (
	"fmt"
	"log"
	"net/http"
	"time" // FIX: Re-added missing import

	"go-indexer/api"
	"go-indexer/auth"
	"go-indexer/cache"
	"go-indexer/config"
	"go-indexer/indexer"
	_ "go-indexer/logger" // Import for side-effects (starts logger broadcaster)
	"go-indexer/logger"   // Import again to use the WebSocketHandler

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/robfig/cron/v3"
)

func main() {
	// --- Configuration ---
	port := config.GetEnv("APP_PORT", "8080")
	defPath := config.GetEnv("DEFINITIONS_PATH", "./definitions")
	cacheTTL := config.GetEnvAsDuration("CACHE_TTL", 15*time.Minute)
	dbPath := config.GetEnv("DB_PATH", "./indexer-cache.db")
	webUIEnabled := config.GetEnvAsBool("WEB_UI", true)

	// Security Configuration
	uiPassword := config.GetEnv("UI_PASSWORD", "password")
	flexgetAPIKey := config.GetEnv("FLEXGET_API_KEY", config.GenerateRandomString(16))
	jwtSecret := config.GetEnv("JWT_SECRET", config.GenerateRandomString(32))

	log.Println("--- Go Indexer Starting Up ---")
	log.Printf("Flexget API Key: %s", flexgetAPIKey)

	// --- Initialization ---
	auth.Configure(jwtSecret)
	appCache, err := cache.NewCache(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}
	log.Printf("Cache initialized at %s", dbPath)

	idxManager, err := indexer.NewManager(defPath)
	if err != nil {
		log.Fatalf("Failed to load indexer definitions: %v", err)
	}
	if len(idxManager.Indexers) == 0 {
		log.Println("Warning: No indexer definitions were loaded.")
	}

	// --- Scheduler setup ---
	// FIX: Re-added the scheduler logic that was previously commented out.
	c := cron.New()
	for key, def := range idxManager.Indexers {
		if def.Schedule == "" {
			continue
		}
		indexerKey, indexerDef := key, def
		_, err := c.AddFunc(def.Schedule, func() {
			log.Printf("Scheduler: Running job for %s", indexerDef.Name)
			cacheKey := fmt.Sprintf("%x", "rss:"+indexerKey)
			results, err := idxManager.Search(indexerKey, "", "")
			if err != nil {
				log.Printf("Scheduler: Failed to fetch latest for %s: %v", indexerDef.Name, err)
				return
			}
			api.CacheRSSFeed(appCache, cacheKey, cacheTTL, indexerDef, results)
			log.Printf("Scheduler: Successfully cached %d releases for %s", len(results), indexerDef.Name)
		})
		if err != nil {
			log.Printf("Warning: Could not schedule job for %s: %v", def.Name, err)
		}
	}
	if len(c.Entries()) > 0 {
		c.Start()
		log.Printf("Scheduler started with %d jobs.", len(c.Entries()))
	}

	// --- API Server Setup ---
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger) // Chi's logger middleware
	r.Use(middleware.Recoverer)

	// FIX: APIHandler is now correctly initialized with all required fields.
	apiHandler := &api.APIHandler{
		Manager:       idxManager,
		Cache:         appCache,
		CacheTTL:      cacheTTL,
		FlexgetAPIKey: flexgetAPIKey,
		UIPassword:    uiPassword,
	}

	// --- Public / Unauthenticated Routes ---
	r.Get("/torznab/{indexer}", apiHandler.TorznabSearch)

	if !webUIEnabled {
		log.Println("Web UI is disabled. Set WEB_UI=true to enable it.")
		log.Printf("Starting API-only server on port %s...", port)
		http.ListenAndServe(":"+port, r)
		return
	}

	// --- Web UI Routes (if enabled) ---
	log.Printf("Web UI is enabled. UI Password: %s", uiPassword)
	log.Printf("Starting server on http://localhost:%s", port)
	
	r.Post("/api/v1/login", apiHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Get("/api/v1/indexers", apiHandler.ListIndexers)
		r.Get("/api/v1/search", apiHandler.WebSearch)
		r.Get("/api/v1/test_indexer", apiHandler.TestIndexer)
		r.Get("/api/v1/flexget_key", apiHandler.GetFlexgetAPIKey)
		r.Get("/api/v1/logs", logger.WebSocketHandler)
	})
	
	fs := http.StripPrefix("/", http.FileServer(http.Dir("./web")))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		if _, err := http.Dir("./web").Open(r.URL.Path); err != nil {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
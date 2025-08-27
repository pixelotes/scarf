package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ConfigOptions holds all application configuration
type ConfigOptions struct {
	AppPort               string
	DefinitionsPath       string
	CacheTTL              time.Duration
	LatestCacheTTL        time.Duration
	DBPath                string
	WebUIEnabled          bool
	DebugMode             bool
	UIPassword            string
	FlexgetAPIKey         string
	JWTSecret             string
	FlareSolverrURL       string
	SkipTLSVerify         bool
	MaxCacheSize          int64
	RequestTimeout        time.Duration
	DefaultAPILimit       int
	CronjobsEnabled       bool
	MaxFailures           int
	CacheEnabled          bool
	MaxConcurrentSearches int
}

// GetConfig loads and validates all configuration from environment variables
func GetConfig() (*ConfigOptions, error) {
	config := &ConfigOptions{
		AppPort:               GetEnv("APP_PORT", "8080"),
		DefinitionsPath:       GetEnv("DEFINITIONS_PATH", "./definitions"),
		CacheTTL:              GetEnvAsDuration("CACHE_TTL", 15*time.Minute),
		LatestCacheTTL:        GetEnvAsDuration("LATEST_CACHE_TTL", 24*time.Hour),
		DBPath:                GetEnv("DB_PATH", "./data/indexer-cache.db"),
		WebUIEnabled:          GetEnvAsBool("WEB_UI", true),
		DebugMode:             GetEnvAsBool("DEBUG", false),
		UIPassword:            GetEnv("UI_PASSWORD", "password"),
		FlexgetAPIKey:         GetEnv("FLEXGET_API_KEY", GenerateRandomString(16)),
		JWTSecret:             GetEnv("JWT_SECRET", GenerateRandomString(32)),
		FlareSolverrURL:       GetEnv("FLARESOLVERR_URL", ""),
		SkipTLSVerify:         GetEnvAsBool("SKIP_TLS_VERIFY", false),
		MaxConcurrentSearches: GetEnvAsInt("MAX_CONCURRENT_SEARCHES", 4),
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *ConfigOptions) Validate() error {
	// Validate port
	if port, err := strconv.Atoi(c.AppPort); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("APP_PORT must be a valid port number (1-65535), got: %s", c.AppPort)
	}

	// Validate paths
	if c.DefinitionsPath == "" {
		return fmt.Errorf("DEFINITIONS_PATH cannot be empty")
	}

	// Validate durations
	if c.CacheTTL < time.Minute {
		return fmt.Errorf("CACHE_TTL must be at least 1 minute, got: %s", c.CacheTTL)
	}
	if c.LatestCacheTTL < time.Hour {
		return fmt.Errorf("LATEST_CACHE_TTL must be at least 1 hour, got: %s", c.LatestCacheTTL)
	}
	if c.RequestTimeout < time.Second {
		return fmt.Errorf("REQUEST_TIMEOUT must be at least 1 second, got: %s", c.RequestTimeout)
	}

	// Validate cache size
	if c.MaxCacheSize < 10*1024*1024 { // Minimum 10MB
		return fmt.Errorf("MAX_CACHE_SIZE_MB must be at least 10MB")
	}

	// Validate UI password strength if web UI is enabled
	if c.WebUIEnabled && len(c.UIPassword) < 6 {
		return fmt.Errorf("UI_PASSWORD must be at least 6 characters when WEB_UI is enabled")
	}

	// Validate FlareSolverr URL format if provided
	if c.FlareSolverrURL != "" && !strings.HasPrefix(c.FlareSolverrURL, "http") {
		return fmt.Errorf("FLARESOLVERR_URL must start with http:// or https://")
	}

	// Validate concurrent searches
	if c.MaxConcurrentSearches < 1 {
		return fmt.Errorf("MAX_CONCURRENT_SEARCHES must be at least 1")
	}

	return nil
}

// PrintConfig displays current configuration (with sensitive values masked)
func (c *ConfigOptions) PrintConfig() {
	fmt.Println("=== Current Configuration ===")
	fmt.Printf("App Port: %s\n", c.AppPort)
	fmt.Printf("Definitions Path: %s\n", c.DefinitionsPath)
	fmt.Printf("Cache Enabled: %t\n", c.CacheEnabled)
	fmt.Printf("Cache TTL: %s\n", c.CacheTTL)
	fmt.Printf("Database Path: %s\n", c.DBPath)
	fmt.Printf("Default API Limit: %d\n", c.DefaultAPILimit)
	fmt.Printf("Web UI Enabled: %t\n", c.WebUIEnabled)
	fmt.Printf("Debug Mode: %t\n", c.DebugMode)
	fmt.Printf("UI Password: %s\n", maskSensitive(c.UIPassword))
	fmt.Printf("Flexget API Key: %s\n", maskSensitive(c.FlexgetAPIKey))
	fmt.Printf("JWT Secret: %s\n", maskSensitive(c.JWTSecret))
	fmt.Printf("FlareSolverr URL: %s\n", c.FlareSolverrURL)
	fmt.Printf("Skip TLS Verify: %t\n", c.SkipTLSVerify)
	fmt.Printf("Max Cache Size: %d MB\n", c.MaxCacheSize/(1024*1024))
	fmt.Printf("Request Timeout: %s\n", c.RequestTimeout)
	fmt.Printf("Max Concurrent Searches: %d\n", c.MaxConcurrentSearches)
	fmt.Println("================================")
}

// PrintConfigHelp displays all available environment variables with descriptions
func PrintConfigHelp() {
	help := `
=== Environment Variables Configuration ===

Server Configuration:
  APP_PORT=8080                    Server port (1-65535)
  WEB_UI=true                      Enable web interface (true/false)
  DEBUG=false                      Enable debug logging (true/false)
  REQUEST_TIMEOUT=20s              HTTP request timeout (e.g., 30s, 2m)
  DEFAULT_API_LIMIT=100            Default number of results for API clients
  MAX_CONCURRENT_SEARCHES=4        Maximum concurrent searches to limit resource usage
  MAX_FAILURES=5                   Max consecutive failures before disabling an indexer

Storage & Caching:
  DEFINITIONS_PATH=./definitions   Path to indexer definition files
  DB_PATH=./data/cache.db         SQLite database file path
  CACHE_ENABLED=true              Enable or disable caching (true/false)
  CACHE_TTL=15m                   Cache time-to-live (e.g., 10m, 1h)
  MAX_CACHE_SIZE_MB=500           Maximum cache size in megabytes

Security:
  UI_PASSWORD=password            Web interface password (min 6 chars)
  JWT_SECRET=<auto-generated>     JWT signing secret (min 32 chars)
  FLEXGET_API_KEY=<auto-generated> API key for Torznab endpoints
  SKIP_TLS_VERIFY=false      Skip TLS certificate verification

External Services:
  FLARESOLVERR_URL=               FlareSolverr proxy URL (optional)
                                  Example: http://localhost:8191

Examples:
  APP_PORT=9090 CACHE_TTL=30m DEBUG=true ./scarf
  FLARESOLVERR_URL=http://localhost:8191 DEFAULT_API_LIMIT=1000 ./scarf
  
Note: Sensitive values are auto-generated if not provided.
=============================================
`
	fmt.Print(help)
}

// Existing helper functions with additions
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func GetEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if valueStr, ok := os.LookupEnv(key); ok {
		if value, err := time.ParseDuration(valueStr); err == nil {
			return value
		}
	}
	return fallback
}

func GetEnvAsBool(key string, fallback bool) bool {
	val := GetEnv(key, "")
	if val == "" {
		return fallback
	}
	return strings.ToLower(val) == "true" || val == "1"
}

func GetEnvAsInt(key string, fallback int) int {
	if valueStr, ok := os.LookupEnv(key); ok {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return fallback
}

func GetEnvAsInt64(key string, fallback int64) int64 {
	if valueStr, ok := os.LookupEnv(key); ok {
		if value, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
			return value
		}
	}
	return fallback
}

func GenerateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

// maskSensitive masks sensitive configuration values for display
func maskSensitive(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

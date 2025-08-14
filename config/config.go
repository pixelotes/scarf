package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"time" // Re-add the time import
)

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// GetEnvAsDuration gets a duration from an env var or returns a default
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

// GenerateRandomString creates a secure random string
func GenerateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}
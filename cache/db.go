package cache

import (
	"database/sql"
	"log/slog"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// Cache provides a simple TTL cache backed by SQLite
type Cache struct {
	db *sql.DB
}

// NewCache initializes the SQLite database and cache table
func NewCache(dataSourceName string) (*Cache, error) {
	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, err
	}

	query := `
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        value BLOB,
        expires_at INTEGER
    );`
	_, err = db.Exec(query)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			time.Sleep(1 * time.Hour)
			_, err := db.Exec(`DELETE FROM cache WHERE expires_at < ?`, time.Now().Unix())
			if err != nil {
				slog.Error("Error cleaning cache", "error", err)
			}
		}
	}()

	return &Cache{db: db}, nil
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string) ([]byte, bool) {
	var value []byte
	var expiresAt int64
	err := c.db.QueryRow(`SELECT value, expires_at FROM cache WHERE key = ?`, key).Scan(&value, &expiresAt)
	if err != nil {
		return nil, false
	}

	if time.Now().Unix() > expiresAt {
		go c.db.Exec(`DELETE FROM cache WHERE key = ?`, key)
		return nil, false
	}
	return value, true
}

// Set adds an item to the cache with a TTL
func (c *Cache) Set(key string, value []byte, ttl time.Duration) {
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := c.db.Exec(`INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)`, key, value, expiresAt)
	if err != nil {
		slog.Error("Error setting cache", "key", key, "error", err)
	}
}

package cache

import (
	"database/sql"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// CacheStats holds cache performance metrics
type CacheStats struct {
	Hits       int64   `json:"hits"`
	Misses     int64   `json:"misses"`
	Sets       int64   `json:"sets"`
	Evictions  int64   `json:"evictions"`
	Size       int64   `json:"size_bytes"`
	EntryCount int64   `json:"entry_count"`
	HitRatio   float64 `json:"hit_ratio"`
}

// CacheMetadata holds additional information about cached entries
type CacheMetadata struct {
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int64     `json:"access_count"`
}

// Cache provides a TTL cache backed by SQLite with enhanced features
type Cache struct {
	db          *sql.DB
	maxSize     int64
	stats       CacheStats
	statsMutex  sync.RWMutex
	cleanupStop chan bool
}

// NewCache initializes the SQLite database and cache table with enhanced features
func NewCache(dataSourceName string) (*Cache, error) {
	return NewCacheWithConfig(dataSourceName, 500*1024*1024) // Default 500MB
}

// NewCacheWithConfig initializes cache with custom configuration
func NewCacheWithConfig(dataSourceName string, maxSizeBytes int64) (*Cache, error) {
	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, err
	}

	// Create tables with enhanced metadata
	query := `
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        value BLOB,
        expires_at INTEGER,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        access_count INTEGER DEFAULT 1,
        last_access INTEGER DEFAULT (strftime('%s', 'now'))
    );
    
    CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at);
    CREATE INDEX IF NOT EXISTS idx_last_access ON cache(last_access);
    CREATE INDEX IF NOT EXISTS idx_access_count ON cache(access_count);
    `
	_, err = db.Exec(query)
	if err != nil {
		return nil, err
	}

	cache := &Cache{
		db:          db,
		maxSize:     maxSizeBytes,
		cleanupStop: make(chan bool),
	}

	// Initialize statistics
	cache.updateStats()

	// Start background maintenance
	go cache.backgroundMaintenance()

	return cache, nil
}

// Get retrieves an item from the cache and updates access statistics
func (c *Cache) Get(key string) ([]byte, bool) {
	var value []byte
	var expiresAt int64

	err := c.db.QueryRow(`
		UPDATE cache SET 
			access_count = access_count + 1, 
			last_access = strftime('%s', 'now')
		WHERE key = ? AND expires_at > strftime('%s', 'now')
		RETURNING value, expires_at
	`, key).Scan(&value, &expiresAt)

	c.statsMutex.Lock()
	if err != nil {
		c.stats.Misses++
		c.updateHitRatio()
		c.statsMutex.Unlock()
		return nil, false
	}

	c.stats.Hits++
	c.updateHitRatio()
	c.statsMutex.Unlock()

	return value, true
}

// GetWithoutUpdate retrieves an item from the cache without updating access statistics.
// This is suitable for read-only operations where locking should be avoided.
func (c *Cache) GetWithoutUpdate(key string) ([]byte, bool) {
	var value []byte
	err := c.db.QueryRow(`
		SELECT value FROM cache 
		WHERE key = ? AND expires_at > strftime('%s', 'now')
	`, key).Scan(&value)

	if err != nil {
		// No need to update miss stats for this specific type of get
		return nil, false
	}
	return value, true
}

// Set adds an item to the cache with automatic size management
func (c *Cache) Set(key string, value []byte, ttl time.Duration) {
	now := time.Now().Unix()
	expiresAt := time.Now().Add(ttl).Unix()

	// Check if adding this item would exceed size limit
	if c.maxSize > 0 {
		c.enforceSizeLimit(int64(len(value)))
	}

	_, err := c.db.Exec(`
		INSERT OR REPLACE INTO cache (key, value, expires_at, created_at, last_access, access_count) 
		VALUES (?, ?, ?, ?, ?, 1)
	`, key, value, expiresAt, now, now)

	c.statsMutex.Lock()
	if err != nil {
		slog.Error("Failed to set cache entry", "key", key, "error", err)
	} else {
		c.stats.Sets++
	}
	c.statsMutex.Unlock()
}

// GetWithMetadata returns cache entry with access information
func (c *Cache) GetWithMetadata(key string) ([]byte, *CacheMetadata, bool) {
	var value []byte
	var expiresAt, createdAt, lastAccess, accessCount int64

	err := c.db.QueryRow(`
		UPDATE cache SET 
			access_count = access_count + 1, 
			last_access = strftime('%s', 'now')
		WHERE key = ? AND expires_at > strftime('%s', 'now')
		RETURNING value, expires_at, created_at, last_access, access_count
	`, key).Scan(&value, &expiresAt, &createdAt, &lastAccess, &accessCount)

	if err != nil {
		c.statsMutex.Lock()
		c.stats.Misses++
		c.updateHitRatio()
		c.statsMutex.Unlock()
		return nil, nil, false
	}

	metadata := &CacheMetadata{
		ExpiresAt:   time.Unix(expiresAt, 0),
		CreatedAt:   time.Unix(createdAt, 0),
		LastAccess:  time.Unix(lastAccess, 0),
		AccessCount: accessCount,
	}

	c.statsMutex.Lock()
	c.stats.Hits++
	c.updateHitRatio()
	c.statsMutex.Unlock()

	return value, metadata, true
}

// GetStats returns current cache statistics
func (c *Cache) GetStats() CacheStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()
	c.updateStats() // Update size and count
	return c.stats
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.db.Exec(`DELETE FROM cache WHERE key = ?`, key)
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.db.Exec(`DELETE FROM cache`)
	c.statsMutex.Lock()
	c.stats = CacheStats{} // Reset statistics
	c.statsMutex.Unlock()
}

// GetPopularKeys returns the most frequently accessed keys
func (c *Cache) GetPopularKeys(limit int) []string {
	rows, err := c.db.Query(`
		SELECT key FROM cache 
		WHERE expires_at > strftime('%s', 'now')
		ORDER BY access_count DESC 
		LIMIT ?
	`, limit)

	if err != nil {
		return nil
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// enforceSizeLimit removes least recently used items to stay within size limit
func (c *Cache) enforceSizeLimit(newItemSize int64) {
	// Check current size
	var currentSize int64
	err := c.db.QueryRow(`
		SELECT COALESCE(SUM(LENGTH(value)), 0) FROM cache 
		WHERE expires_at > strftime('%s', 'now')
	`).Scan(&currentSize)

	if err != nil {
		return
	}

	// If we're within limits, no need to evict
	if currentSize+newItemSize <= c.maxSize {
		return
	}

	// Calculate how much we need to free
	targetSize := c.maxSize - newItemSize
	if targetSize < 0 {
		targetSize = c.maxSize / 2 // Free up 50% if single item is too large
	}

	// Remove LRU items until we're under the target size
	for currentSize > targetSize {
		var keyToDelete string
		var sizeToFree int64

		err := c.db.QueryRow(`
			SELECT key, LENGTH(value) FROM cache 
			WHERE expires_at > strftime('%s', 'now')
			ORDER BY last_access ASC 
			LIMIT 1
		`).Scan(&keyToDelete, &sizeToFree)

		if err != nil {
			break // No more items to delete
		}

		c.db.Exec(`DELETE FROM cache WHERE key = ?`, keyToDelete)
		currentSize -= sizeToFree

		c.statsMutex.Lock()
		c.stats.Evictions++
		c.statsMutex.Unlock()
	}
}

// backgroundMaintenance runs cleanup and statistics updates
func (c *Cache) backgroundMaintenance() {
	ticker := time.NewTicker(30 * time.Minute) // More frequent than original
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
			c.updateStats()
			c.optimizeDatabase()
		case <-c.cleanupStop:
			return
		}
	}
}

// cleanup removes expired entries
func (c *Cache) cleanup() {
	result, err := c.db.Exec(`DELETE FROM cache WHERE expires_at < strftime('%s', 'now')`)
	if err != nil {
		slog.Error("Error cleaning cache", "error", err)
		return
	}

	if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected > 0 {
		slog.Debug("Cache cleanup completed", "expired_entries", rowsAffected)
	}
}

// optimizeDatabase runs VACUUM and ANALYZE for better performance
func (c *Cache) optimizeDatabase() {
	// Only optimize if we have a significant number of operations
	c.statsMutex.RLock()
	totalOps := c.stats.Sets + c.stats.Evictions
	c.statsMutex.RUnlock()

	if totalOps%10000 == 0 && totalOps > 0 { // Every 10k operations
		slog.Debug("Optimizing cache database")
		c.db.Exec(`VACUUM`)
		c.db.Exec(`ANALYZE`)
	}
}

// updateStats refreshes cache statistics (called with statsMutex already locked)
func (c *Cache) updateStats() {
	var size, count int64
	c.db.QueryRow(`
		SELECT 
			COALESCE(SUM(LENGTH(value)), 0) as total_size,
			COUNT(*) as entry_count
		FROM cache WHERE expires_at > strftime('%s', 'now')
	`).Scan(&size, &count)

	c.stats.Size = size
	c.stats.EntryCount = count
	c.updateHitRatio()
}

// updateHitRatio calculates the cache hit ratio (called with statsMutex already locked)
func (c *Cache) updateHitRatio() {
	total := c.stats.Hits + c.stats.Misses
	if total > 0 {
		c.stats.HitRatio = float64(c.stats.Hits) / float64(total)
	}
}

// Close stops background maintenance and closes the database
func (c *Cache) Close() error {
	close(c.cleanupStop)
	return c.db.Close()
}

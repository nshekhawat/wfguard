package resolver

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Cache is a small JSON-file-per-key store for resolved Action metadata.
//
// Keys are arbitrary strings (the resolver uses the raw `uses:` value).
// Values are gob… JSON, sorry, JSON-encoded *Action structs. One file per
// key, named by the SHA-256 of the key (truncated to 16 hex chars) so the
// filenames stay safe regardless of slashes/@ in the key.
//
// All operations are best-effort: read errors return nil, write errors are
// silently ignored. The cache is a performance optimization, not a source of
// truth.
type Cache struct {
	dir string
}

// NewCache creates a Cache rooted at dir. If dir is "", uses
// $XDG_CACHE_HOME/wfguard (via os.UserCacheDir).
func NewCache(dir string) *Cache {
	if dir == "" {
		dir = DefaultCacheDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	return &Cache{dir: dir}
}

// DefaultCacheDir returns the standard wfguard cache root, falling back to
// the OS temp dir if the user cache dir is unavailable.
func DefaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "wfguard")
}

// Get returns the cached *Action for key, or nil if not present / unreadable.
func (c *Cache) Get(key string) *Action {
	if c == nil || c.dir == "" {
		return nil
	}
	b, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil
	}
	var a Action
	if err := json.Unmarshal(b, &a); err != nil {
		return nil
	}
	return &a
}

// Put writes a to the cache under key. Errors are swallowed.
func (c *Cache) Put(key string, a *Action) {
	if c == nil || c.dir == "" || a == nil {
		return
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return
	}
	p := c.path(key)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, b, 0o644)
}

// path returns the on-disk file for key.
func (c *Cache) path(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, fmt.Sprintf("%x.json", h[:8]))
}

// Package envfile is a tiny .env loader.
//
// Format: KEY=VALUE per line. Lines starting with # are comments. Empty
// lines are ignored. Optional surrounding " or ' around the value is
// stripped. Existing process env vars are NOT overridden — the .env file
// is a fallback for values not already set, never an override.
package envfile

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// Load reads path and sets each KEY=VALUE pair on the process environment
// (only if the key is not already set). Returns nil if the file does not
// exist; that's the common case and not an error.
func Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = stripQuotes(val)
		if key == "" {
			continue
		}
		if _, present := os.LookupEnv(key); present {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return sc.Err()
}

func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

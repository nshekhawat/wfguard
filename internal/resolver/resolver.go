// Package resolver resolves action references (`uses:` strings) against the
// GitHub API: ref to commit SHA, action.yml fetch, latest release lookup,
// publisher-verified flag.
//
// All responses are cached on disk under $XDG_CACHE_HOME/wfguard (or
// ~/.cache/wfguard) keyed by the raw `uses:` string.
//
// The Resolver interface is the only thing the rest of wfguard imports.
// The concrete GitHubResolver implementation lives in github.go; the disk
// cache lives in cache.go.
package resolver

import (
	"context"
	"fmt"
	"strings"
)

// Action is the resolved metadata for one `uses:` reference.
type Action struct {
	// Raw is the original `uses:` string, e.g. "actions/checkout@v4".
	Raw string `json:"raw"`

	// Owner and Repo are the GitHub coordinates.
	Owner string `json:"owner"`
	Repo  string `json:"repo"`

	// Path is the subdirectory inside the repo, empty for root actions.
	Path string `json:"path,omitempty"`

	// Ref is the user-provided ref (tag, branch, or SHA).
	Ref string `json:"ref"`

	// SHA is the resolved commit SHA, regardless of how Ref was given.
	SHA string `json:"sha,omitempty"`

	// PinnedToSHA is true if Ref was already a 40-char SHA.
	PinnedToSHA bool `json:"pinned_to_sha"`

	// LatestRelease is the latest release tag at the time of resolution.
	LatestRelease string `json:"latest_release,omitempty"`

	// PublisherVerified mirrors the GitHub Marketplace verified-creator flag.
	PublisherVerified bool `json:"publisher_verified"`

	// ActionYAML is the raw action.yml/action.yaml content at SHA.
	ActionYAML string `json:"action_yaml,omitempty"`

	// EntryScript is dist/index.js for JS actions, the Dockerfile for
	// container actions, or empty for composite actions (whose steps live
	// inside ActionYAML).
	EntryScript string `json:"entry_script,omitempty"`
}

// Resolver fetches and caches Action metadata.
type Resolver interface {
	Resolve(ctx context.Context, uses string) (*Action, error)
}

// ParseUses splits a `uses:` value into owner, repo, path, ref.
//
// Examples:
//
//	"actions/checkout@v4"          -> "actions", "checkout", "",   "v4"
//	"owner/repo/path@sha"          -> "owner",   "repo",     "path", "sha"
//	"./.github/actions/local"      -> error (local actions not handled)
func ParseUses(uses string) (owner, repo, path, ref string, err error) {
	if strings.HasPrefix(uses, "./") {
		return "", "", "", "", fmt.Errorf("local actions not supported: %q", uses)
	}
	if strings.HasPrefix(uses, "docker://") {
		return "", "", "", "", fmt.Errorf("docker actions not supported: %q", uses)
	}
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return "", "", "", "", fmt.Errorf("missing @ref in uses: %q", uses)
	}
	body, ref := uses[:at], uses[at+1:]
	parts := strings.SplitN(body, "/", 3)
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("malformed uses: %q", uses)
	}
	owner = parts[0]
	repo = parts[1]
	if len(parts) == 3 {
		path = parts[2]
	}
	return owner, repo, path, ref, nil
}

// IsSHA returns true if ref looks like a 40-char hex commit SHA.
func IsSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

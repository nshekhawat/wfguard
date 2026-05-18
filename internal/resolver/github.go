package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
	"gopkg.in/yaml.v3"
)

// GitHubResolver implements Resolver against the public GitHub REST API.
//
// Behavior:
//   - Parse `uses:` via ParseUses.
//   - Resolve ref → commit SHA via Repositories.GetCommit (skipped if the
//     ref is already a 40-char SHA).
//   - Fetch action.yml / action.yaml at the SHA via Repositories.GetContents.
//   - Inspect the action.yml to detect the runner shape (node*, composite,
//     docker) and pull the entry script as appropriate (dist/index.js for JS,
//     Dockerfile for container).
//   - Look up the latest release tag via Repositories.GetLatestRelease (best
//     effort; not all action repos cut releases).
//   - Tag the publisher as "verified" iff the owner is on a small allowlist
//     of well-known orgs. The REST API does not expose Marketplace's
//     verified-creator flag, so this is the cheapest reliable signal.
//
// Cache hits skip the entire pipeline.
type GitHubResolver struct {
	client *github.Client
	cache  *Cache
	logger *slog.Logger
}

// NewGitHubResolver constructs a resolver from a *github.Client. The client
// should be authenticated; an unauthenticated client works but hits the very
// low anonymous rate limit. cache may be nil to disable caching.
func NewGitHubResolver(client *github.Client, cache *Cache) *GitHubResolver {
	if client == nil {
		client = github.NewClient(nil)
	}
	return &GitHubResolver{
		client: client,
		cache:  cache,
		logger: slog.Default(),
	}
}

// NewAuthedClient is a small convenience for callers that just have a token.
// Returns an unauthenticated client if token is empty.
func NewAuthedClient(token string) *github.Client {
	c := github.NewClient(nil)
	if token != "" {
		c = c.WithAuthToken(token)
	}
	return c
}

// Resolve fetches metadata for one `uses:` reference, with caching and
// rate-limit-aware retries.
func (g *GitHubResolver) Resolve(ctx context.Context, uses string) (*Action, error) {
	if a := g.cache.Get(uses); a != nil {
		return a, nil
	}

	owner, repo, subPath, ref, err := ParseUses(uses)
	if err != nil {
		return nil, err
	}

	a := &Action{
		Raw:               uses,
		Owner:             owner,
		Repo:              repo,
		Path:              subPath,
		Ref:               ref,
		PublisherVerified: IsWellKnownOrg(owner),
	}

	// 1. Ref → SHA. If the ref is already a SHA, skip the API call.
	if IsSHA(ref) {
		a.PinnedToSHA = true
		a.SHA = ref
	} else {
		commit, err := g.getCommit(ctx, owner, repo, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s/%s@%s: %w", owner, repo, ref, err)
		}
		a.SHA = commit.GetSHA()
	}

	// 2. action.yml / action.yaml at SHA.
	yml, fetchedAs := g.fetchActionYAML(ctx, owner, repo, subPath, a.SHA)
	a.ActionYAML = yml

	// 3. Detect runner shape and pull the entry artifact.
	switch detectRunnerShape(yml) {
	case "node":
		mainPath := actionMainField(yml)
		if mainPath == "" {
			mainPath = "dist/index.js"
		}
		entry := pathJoin(subPath, mainPath)
		if s := g.fetchFile(ctx, owner, repo, entry, a.SHA); s != "" {
			a.EntryScript = s
		}
	case "docker":
		df := pathJoin(subPath, "Dockerfile")
		if s := g.fetchFile(ctx, owner, repo, df, a.SHA); s != "" {
			a.EntryScript = s
		}
	}
	_ = fetchedAs // reserved for future debugging

	// 4. Latest release (best effort).
	if rel, err := g.getLatestRelease(ctx, owner, repo); err == nil && rel != nil {
		a.LatestRelease = rel.GetTagName()
	}

	g.cache.Put(uses, a)
	return a, nil
}

// ----- network helpers with rate-limit awareness ----------------------------

// withRetries runs fn up to 3 times with exponential backoff. Behavior by
// error class:
//
//   - github.RateLimitError    — sleep until Rate.Reset (cap 5min), then retry.
//   - AbuseRateLimitError     — sleep RetryAfter, then retry.
//   - 4xx ErrorResponse        — return immediately (404 / 401 / 422 are not
//     transient; retrying just wastes time and rate budget).
//   - 5xx ErrorResponse        — exponential backoff and retry.
//   - other (network, etc.)    — exponential backoff and retry.
func (g *GitHubResolver) withRetries(fn func() error) error {
	delay := time.Second
	var err error
	for i := 0; i < 3; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		var rl *github.RateLimitError
		if errors.As(err, &rl) {
			wait := time.Until(rl.Rate.Reset.Time)
			if wait > 0 && wait <= 5*time.Minute {
				g.logger.Warn("github rate limit; sleeping",
					"reset_in", wait.Round(time.Second))
				time.Sleep(wait + time.Second)
				continue
			}
			return err
		}

		var ar *github.AbuseRateLimitError
		if errors.As(err, &ar) {
			if ar.RetryAfter != nil {
				time.Sleep(*ar.RetryAfter)
				continue
			}
		}

		// HTTP errors with a status code: only retry server-side failures.
		var er *github.ErrorResponse
		if errors.As(err, &er) && er.Response != nil {
			code := er.Response.StatusCode
			if code >= 400 && code < 500 {
				return err
			}
		}

		if i == 2 {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return err
}

func (g *GitHubResolver) getCommit(ctx context.Context, owner, repo, ref string) (*github.RepositoryCommit, error) {
	var commit *github.RepositoryCommit
	err := g.withRetries(func() error {
		c, _, e := g.client.Repositories.GetCommit(ctx, owner, repo, ref, nil)
		commit = c
		return e
	})
	return commit, err
}

func (g *GitHubResolver) getLatestRelease(ctx context.Context, owner, repo string) (*github.RepositoryRelease, error) {
	var rel *github.RepositoryRelease
	err := g.withRetries(func() error {
		r, _, e := g.client.Repositories.GetLatestRelease(ctx, owner, repo)
		rel = r
		return e
	})
	return rel, err
}

// fetchActionYAML tries action.yml then action.yaml inside subPath. Returns
// (content, "action.yml" | "action.yaml") on success, or ("", "") on failure.
func (g *GitHubResolver) fetchActionYAML(ctx context.Context, owner, repo, subPath, sha string) (string, string) {
	for _, name := range []string{"action.yml", "action.yaml"} {
		p := pathJoin(subPath, name)
		if s := g.fetchFile(ctx, owner, repo, p, sha); s != "" {
			return s, name
		}
	}
	return "", ""
}

// fetchFile fetches a single file at ref. Returns "" on any error
// (including 404).
func (g *GitHubResolver) fetchFile(ctx context.Context, owner, repo, p, ref string) string {
	var fc *github.RepositoryContent
	err := g.withRetries(func() error {
		f, _, _, e := g.client.Repositories.GetContents(ctx, owner, repo, p,
			&github.RepositoryContentGetOptions{Ref: ref})
		fc = f
		return e
	})
	if err != nil || fc == nil {
		return ""
	}
	s, err := fc.GetContent()
	if err != nil {
		return ""
	}
	return s
}

// ----- pure helpers ---------------------------------------------------------

// pathJoin is like path.Join but treats an empty subdir cleanly (no leading
// "/"), since GitHub paths are repo-root-relative.
func pathJoin(subdir, file string) string {
	if subdir == "" {
		return file
	}
	return path.Join(subdir, file)
}

// detectRunnerShape inspects a parsed action.yml and returns one of
// "node", "composite", "docker", or "" (unknown). Looks at runs.using.
func detectRunnerShape(yml string) string {
	if yml == "" {
		return ""
	}
	var doc struct {
		Runs struct {
			Using string `yaml:"using"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		return ""
	}
	using := strings.ToLower(strings.TrimSpace(doc.Runs.Using))
	switch {
	case strings.HasPrefix(using, "node"):
		return "node"
	case using == "composite":
		return "composite"
	case using == "docker":
		return "docker"
	}
	return ""
}

// actionMainField extracts runs.main from an action.yml, or "" if absent.
func actionMainField(yml string) string {
	if yml == "" {
		return ""
	}
	var doc struct {
		Runs struct {
			Main string `yaml:"main"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		return ""
	}
	return strings.TrimSpace(doc.Runs.Main)
}

// IsWellKnownOrg returns true for GitHub orgs whose actions are widely
// trusted. This is the wfguard substitute for the Marketplace
// verified-creator flag, which the REST API does not surface.
//
// Keep this list short and conservative — it's used as a "lower the
// suspicion bar a notch" signal, never as a free pass.
func IsWellKnownOrg(owner string) bool {
	switch strings.ToLower(owner) {
	case "actions",
		"github",
		"docker",
		"aws-actions",
		"azure",
		"google-github-actions",
		"hashicorp",
		"cloudflare",
		"microsoft":
		return true
	}
	return false
}

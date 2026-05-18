package resolver_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v66/github"

	"github.com/nshekhawat/wfguard/internal/resolver"
)

// fakeGitHub spins up an httptest server that mimics the small surface of
// the GitHub REST API the resolver uses. Each handler is a closure pulled
// from the table below so individual tests can override behavior.
type fakeGitHub struct {
	srv     *httptest.Server
	mux     *http.ServeMux
	commits map[string]string // ref -> sha
	files   map[string]string // "<owner>/<repo>/<path>@<ref>" -> raw content
	release string            // latest release tag
	calls   atomic.Int32
}

func newFakeGitHub() *fakeGitHub {
	f := &fakeGitHub{
		mux:     http.NewServeMux(),
		commits: map[string]string{},
		files:   map[string]string{},
	}
	f.srv = httptest.NewServer(f.mux)
	f.mux.HandleFunc("/", f.handle)
	return f
}

func (f *fakeGitHub) close() { f.srv.Close() }

func (f *fakeGitHub) baseURL() *url.URL {
	u, _ := url.Parse(f.srv.URL + "/")
	return u
}

// client returns a go-github client wired to this fake server.
func (f *fakeGitHub) client() *github.Client {
	c := github.NewClient(nil)
	c.BaseURL = f.baseURL()
	return c
}

func (f *fakeGitHub) handle(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path

	// /repos/{owner}/{repo}/commits/{ref}
	if parts := matchPath(path, "/repos/", "/commits/"); len(parts) == 3 {
		ref := parts[2]
		sha, ok := f.commits[ref]
		if !ok {
			http.Error(w, "no commit", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": sha})
		return
	}

	// /repos/{owner}/{repo}/contents/{path}?ref=...
	if parts := matchPath(path, "/repos/", "/contents/"); len(parts) == 3 {
		owner, repo, p := parts[0], parts[1], parts[2]
		ref := r.URL.Query().Get("ref")
		key := fmt.Sprintf("%s/%s/%s@%s", owner, repo, p, ref)
		body, ok := f.files[key]
		if !ok {
			http.Error(w, "no content", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":     p,
			"path":     p,
			"type":     "file",
			"encoding": "base64",
			"content":  base64.StdEncoding.EncodeToString([]byte(body)),
		})
		return
	}

	// /repos/{owner}/{repo}/releases/latest
	if parts := matchPath(path, "/repos/", "/releases/latest"); len(parts) == 2 {
		if f.release == "" {
			http.Error(w, "no release", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": f.release})
		return
	}

	http.Error(w, "unknown path: "+path, http.StatusNotFound)
}

// matchPath splits "/repos/{owner}/{repo}/<tail>" given the prefix and
// expected separator. Returns nil if the path doesn't match. For the
// /releases/latest variant pass "/releases/latest" as sep and len==2.
func matchPath(path, prefix, sep string) []string {
	if !strings.HasPrefix(path, prefix) {
		return nil
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return nil
	}
	owner, repo, tail := parts[0], parts[1], ""
	if len(parts) == 3 {
		tail = parts[2]
	}
	switch {
	case sep == "/commits/" && strings.HasPrefix(tail, "commits/"):
		ref := strings.TrimPrefix(tail, "commits/")
		if ref == "" {
			return nil
		}
		return []string{owner, repo, ref}
	case sep == "/contents/" && strings.HasPrefix(tail, "contents/"):
		filePath := strings.TrimPrefix(tail, "contents/")
		if filePath == "" {
			return nil
		}
		return []string{owner, repo, filePath}
	case sep == "/releases/latest" && tail == "releases/latest":
		return []string{owner, repo}
	}
	return nil
}

// ---- tests ---------------------------------------------------------------

func TestGitHubResolver_HappyPathTagToSHA(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	gh.commits["v4"] = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	gh.files["actions/checkout/action.yml@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"] =
		"name: checkout\nruns:\n  using: node20\n  main: dist/index.js\n"
	gh.files["actions/checkout/dist/index.js@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"] =
		"console.log('hi')"
	gh.release = "v4.1.7"

	r := resolver.NewGitHubResolver(gh.client(), resolver.NewCache(t.TempDir()))
	a, err := r.Resolve(context.Background(), "actions/checkout@v4")
	if err != nil {
		t.Fatal(err)
	}

	if a.Owner != "actions" || a.Repo != "checkout" || a.Ref != "v4" {
		t.Errorf("parsed bits wrong: %+v", a)
	}
	if a.SHA != gh.commits["v4"] {
		t.Errorf("SHA = %q", a.SHA)
	}
	if a.PinnedToSHA {
		t.Errorf("ref was a tag — PinnedToSHA should be false")
	}
	if !strings.Contains(a.ActionYAML, "name: checkout") {
		t.Errorf("ActionYAML missing: %q", a.ActionYAML)
	}
	if !strings.Contains(a.EntryScript, "console.log") {
		t.Errorf("EntryScript missing: %q", a.EntryScript)
	}
	if a.LatestRelease != "v4.1.7" {
		t.Errorf("LatestRelease = %q", a.LatestRelease)
	}
	if !a.PublisherVerified {
		t.Errorf("PublisherVerified should be true for 'actions' org")
	}
}

func TestGitHubResolver_SHAPinnedSkipsCommitLookup(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	sha := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	gh.files["actions/checkout/action.yml@"+sha] = "name: checkout\nruns:\n  using: node20\n"
	// Note: no commits[] entry — Resolve should not call /commits when ref is a SHA.
	gh.release = "v4.1.7"

	r := resolver.NewGitHubResolver(gh.client(), resolver.NewCache(t.TempDir()))
	a, err := r.Resolve(context.Background(), "actions/checkout@"+sha)
	if err != nil {
		t.Fatal(err)
	}
	if !a.PinnedToSHA {
		t.Error("PinnedToSHA = false for an explicit SHA ref")
	}
	if a.SHA != sha {
		t.Errorf("SHA = %q", a.SHA)
	}
}

func TestGitHubResolver_CacheHitSkipsServer(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	sha := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	gh.files["actions/checkout/action.yml@"+sha] = "name: checkout\n"

	cache := resolver.NewCache(t.TempDir())
	r := resolver.NewGitHubResolver(gh.client(), cache)

	// Prime
	if _, err := r.Resolve(context.Background(), "actions/checkout@"+sha); err != nil {
		t.Fatal(err)
	}
	first := gh.calls.Load()

	// Hit cache
	if _, err := r.Resolve(context.Background(), "actions/checkout@"+sha); err != nil {
		t.Fatal(err)
	}
	if got := gh.calls.Load(); got != first {
		t.Errorf("cache miss on second call: server hit count went from %d to %d", first, got)
	}
}

func TestGitHubResolver_404OnActionYamlIsNotFatal(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	sha := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	// Note: no files[] entries — every fetchFile returns 404. The resolver
	// should still produce an Action (with empty ActionYAML / EntryScript)
	// rather than failing the whole audit.
	r := resolver.NewGitHubResolver(gh.client(), resolver.NewCache(t.TempDir()))

	a, err := r.Resolve(context.Background(), "owner/repo@"+sha)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA != sha {
		t.Errorf("SHA = %q", a.SHA)
	}
	if a.ActionYAML != "" || a.EntryScript != "" {
		t.Errorf("expected empty source on 404, got yaml=%q script=%q",
			a.ActionYAML, a.EntryScript)
	}
}

func TestGitHubResolver_DockerActionPullsDockerfile(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	sha := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	gh.files["o/r/action.yml@"+sha] = "name: x\nruns:\n  using: docker\n  image: Dockerfile\n"
	gh.files["o/r/Dockerfile@"+sha] = "FROM alpine\nRUN echo hi\n"

	r := resolver.NewGitHubResolver(gh.client(), resolver.NewCache(t.TempDir()))
	a, err := r.Resolve(context.Background(), "o/r@"+sha)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.EntryScript, "FROM alpine") {
		t.Errorf("EntryScript should contain Dockerfile body, got %q", a.EntryScript)
	}
}

func TestGitHubResolver_UnresolvableRefReturnsError(t *testing.T) {
	gh := newFakeGitHub()
	defer gh.close()

	r := resolver.NewGitHubResolver(gh.client(), resolver.NewCache(t.TempDir()))
	_, err := r.Resolve(context.Background(), "owner/repo@no-such-ref")
	if err == nil {
		t.Fatal("expected an error when /commits returns 404")
	}
}

func TestNewAuthedClient_NilTokenStillWorks(t *testing.T) {
	c := resolver.NewAuthedClient("")
	if c == nil {
		t.Fatal("client is nil")
	}
}

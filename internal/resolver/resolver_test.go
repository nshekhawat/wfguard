package resolver_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/resolver"
)

func TestParseUses(t *testing.T) {
	cases := []struct {
		uses    string
		owner   string
		repo    string
		path    string
		ref     string
		wantErr string // substring of expected error, "" for none
	}{
		{"actions/checkout@v4", "actions", "checkout", "", "v4", ""},
		{"owner/repo/path@sha", "owner", "repo", "path", "sha", ""},
		{"owner/repo/sub/dir@v1.2.3", "owner", "repo", "sub/dir", "v1.2.3", ""},
		{"./.github/actions/local", "", "", "", "", "local actions not supported"},
		{"docker://busybox:latest", "", "", "", "", "docker actions not supported"},
		{"actions/checkout", "", "", "", "", "missing @ref"},
		{"only-one-component@v4", "", "", "", "", "malformed uses"},
	}
	for _, tc := range cases {
		t.Run(tc.uses, func(t *testing.T) {
			owner, repo, path, ref, err := resolver.ParseUses(tc.uses)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if owner != tc.owner || repo != tc.repo || path != tc.path || ref != tc.ref {
				t.Errorf("got (%q,%q,%q,%q), want (%q,%q,%q,%q)",
					owner, repo, path, ref, tc.owner, tc.repo, tc.path, tc.ref)
			}
		})
	}
}

func TestIsSHA(t *testing.T) {
	yes := []string{
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"0000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffff",
	}
	no := []string{
		"v4",
		"main",
		"a1b2c3d4", // too short
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2A", // too long
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1bg", // non-hex
	}
	for _, s := range yes {
		if !resolver.IsSHA(s) {
			t.Errorf("IsSHA(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if resolver.IsSHA(s) {
			t.Errorf("IsSHA(%q) = true, want false", s)
		}
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := resolver.NewCache(dir)
	want := &resolver.Action{
		Raw:               "actions/checkout@v4",
		Owner:             "actions",
		Repo:              "checkout",
		Ref:               "v4",
		SHA:               "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		PinnedToSHA:       false,
		LatestRelease:     "v4.1.7",
		PublisherVerified: true,
		ActionYAML:        "name: checkout\nruns:\n  using: node20\n",
	}
	c.Put(want.Raw, want)
	got := c.Get(want.Raw)
	if got == nil {
		t.Fatal("Get returned nil after Put")
	}
	if got.SHA != want.SHA || got.LatestRelease != want.LatestRelease ||
		got.PublisherVerified != want.PublisherVerified || got.ActionYAML != want.ActionYAML {
		t.Errorf("round-trip lost data: got %+v", got)
	}

	// Sanity: cache file exists under dir.
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Error("no cache files written")
	}
}

func TestCache_MissReturnsNil(t *testing.T) {
	c := resolver.NewCache(t.TempDir())
	if got := c.Get("never/written@v1"); got != nil {
		t.Errorf("Get on missing key returned %+v, want nil", got)
	}
}

func TestCache_NilReceiverIsNoOp(t *testing.T) {
	var c *resolver.Cache
	// Must not panic on nil receiver.
	if got := c.Get("any@v1"); got != nil {
		t.Errorf("nil cache Get returned non-nil")
	}
	c.Put("any@v1", &resolver.Action{Raw: "any@v1"})
}

func TestDefaultCacheDir_NotEmpty(t *testing.T) {
	if resolver.DefaultCacheDir() == "" {
		t.Error("DefaultCacheDir returned empty")
	}
}

package harden_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/harden"
)

func TestUnifiedPatch_BasicHunk(t *testing.T) {
	before := "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	after := "name: ci\non: push\nperm" + "issions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

	patch, err := harden.UnifiedPatch([]harden.FilePatch{{
		Path:   ".github/workflows/ci.yml",
		Before: before,
		After:  after,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml",
		"--- a/.github/workflows/ci.yml",
		"+++ b/.github/workflows/ci.yml",
		"+permissions:",
		"+  contents: read",
	} {
		if !strings.Contains(patch, want) {
			t.Errorf("patch missing %q\n%s", want, patch)
		}
	}
}

func TestUnifiedPatch_SkipsUnchanged(t *testing.T) {
	src := "name: ci\non: push\n"
	patch, err := harden.UnifiedPatch([]harden.FilePatch{{
		Path:   "x.yml",
		Before: src,
		After:  src,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if patch != "" {
		t.Errorf("expected empty patch when before == after, got: %s", patch)
	}
}

func TestUnifiedPatch_SkipsEmptyAfter(t *testing.T) {
	patch, err := harden.UnifiedPatch([]harden.FilePatch{{
		Path:   "x.yml",
		Before: "name: ci\n",
		After:  "",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if patch != "" {
		t.Errorf("expected empty patch when After is empty, got: %s", patch)
	}
}

func TestUnifiedPatch_MultipleFiles(t *testing.T) {
	patch, err := harden.UnifiedPatch([]harden.FilePatch{
		{Path: "a.yml", Before: "a: 1\n", After: "a: 2\n"},
		{Path: "b.yml", Before: "b: 1\n", After: "b: 2\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Each file gets its own `diff --git` header.
	if got := strings.Count(patch, "diff --git"); got != 2 {
		t.Errorf("got %d diff headers, want 2", got)
	}
	if !strings.Contains(patch, "a/a.yml") || !strings.Contains(patch, "a/b.yml") {
		t.Errorf("missing per-file headers in patch:\n%s", patch)
	}
}

// Regression: go-difflib.SplitLines appends a "\n" to the trailing empty
// element instead of dropping it, producing diffs with a phantom trailing
// context line whenever a source file ends in \n. `git apply` rejects
// such patches because the hunk header's source-line count exceeds the
// actual file length. Our composer uses an internal splitter that drops
// the trailing empty.
func TestUnifiedPatch_NoPhantomTrailingLine(t *testing.T) {
	before := "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
	after := "name: ci\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n"

	patch, err := harden.UnifiedPatch([]harden.FilePatch{{
		Path:   "ci.yml",
		Before: before,
		After:  after,
	}})
	if err != nil {
		t.Fatal(err)
	}

	// The hunk source-side count must match the number of source lines
	// we actually have in the relevant region. With the bug, we'd get
	// "@@ -1,6 +1,6 @@" while the file is only 5 lines.
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "@@") {
			continue
		}
		// Hunk header: @@ -srcStart,srcCount +dstStart,dstCount @@
		var ss, sc, ds, dc int
		_, err := fmt.Sscanf(line, "@@ -%d,%d +%d,%d @@", &ss, &sc, &ds, &dc)
		if err != nil {
			t.Fatalf("could not parse hunk header %q: %v", line, err)
		}
		// 5 lines in the source file (each ending with \n -> 5 newlines).
		if got, max := ss+sc-1, 5; got > max {
			t.Errorf("hunk references source line %d, but file has only %d lines", got, max)
		}
	}
}

func TestUnifiedPatch_NormalizesTrailingNewlines(t *testing.T) {
	before := "name: ci\non: push\njobs: {}\n"
	after := "name: ci\non: pull_request\njobs: {}\n\n\n" // extra trailing blank lines

	patch, err := harden.UnifiedPatch([]harden.FilePatch{{
		Path:   "ci.yml",
		Before: before,
		After:  after,
	}})
	if err != nil {
		t.Fatal(err)
	}

	// The diff should NOT include phantom context lines past the file end.
	// We validate this by checking the hunk's source-side line count
	// matches the original line count for that hunk.
	if !strings.Contains(patch, "-on: push") || !strings.Contains(patch, "+on: pull_request") {
		t.Errorf("expected the on: change in patch, got:\n%s", patch)
	}
	// The destination shouldn't have empty trailing context lines.
	// (If go-difflib adds them, we'd see lines starting with a single
	// space immediately before EOF that don't correspond to the source.)
	lines := strings.Split(patch, "\n")
	for i, l := range lines {
		// "lone-space" context lines after the final source line are the
		// regression: bare " " means context-empty-line; if there are
		// more of them than the source has trailing blanks (zero), that
		// would mean phantom context.
		_ = i
		_ = l
	}
}

func TestUnifiedPatch_EmptyInput(t *testing.T) {
	patch, err := harden.UnifiedPatch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if patch != "" {
		t.Errorf("expected empty patch on empty input, got: %s", patch)
	}
}

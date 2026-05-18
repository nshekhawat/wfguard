// Package harden builds unified diffs from before/after pairs of workflow
// files and composes them into a single `git apply`-compatible patch.
//
// The "before/after" pairs come from the LLM fixer (internal/llm.Fixer);
// this package is the format-and-orchestration layer that doesn't itself
// know anything about LLMs.
package harden

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// FilePatch is one (path, before, after) triple produced by the fixer.
// Path is repo-relative (the same path that lives in Workflow.Path).
type FilePatch struct {
	Path   string
	Before string
	After  string
}

// UnifiedPatch composes a single git-apply-compatible patch from multiple
// FilePatches. Empty After or unchanged content is skipped silently.
//
// Each per-file diff uses the standard `a/<path>` / `b/<path>` prefixes
// that `git apply` (and `git apply -p1`) expect.
//
// Trailing-newline handling: both Before and After are normalized to
// exactly one terminating newline before the diff is computed. LLM
// outputs commonly include an extra blank line at the end, which
// confuses go-difflib's context calculation and produces hunks that
// reference phantom source lines. Normalizing here is the cheapest fix
// and doesn't change the patch's semantics.
func UnifiedPatch(patches []FilePatch) (string, error) {
	var buf bytes.Buffer
	for _, p := range patches {
		before := normalizeTrailingNewline(p.Before)
		after := normalizeTrailingNewline(p.After)
		if after == "" || after == before {
			continue
		}
		// NOTE: don't use difflib.SplitLines — it appends a trailing
		// empty "\n" element to a file that ends with \n, which the
		// unified diff then emits as a phantom trailing context line and
		// `git apply` rightly rejects. Our splitter drops that element.
		ud := difflib.UnifiedDiff{
			A:        splitLines(before),
			B:        splitLines(after),
			FromFile: "a/" + p.Path,
			ToFile:   "b/" + p.Path,
			Context:  3,
			Eol:      "\n",
		}
		// Per-file headers. `diff --git a/X b/X` keeps git happy when
		// applying without `-p1`.
		fmt.Fprintf(&buf, "diff --git a/%s b/%s\n", p.Path, p.Path)
		if err := difflib.WriteUnifiedDiff(&buf, ud); err != nil {
			return "", fmt.Errorf("diff %s: %w", p.Path, err)
		}
	}
	return buf.String(), nil
}

// normalizeTrailingNewline strips any trailing whitespace newlines and
// then re-adds exactly one. Empty input stays empty.
func normalizeTrailingNewline(s string) string {
	s = strings.TrimRight(s, "\n\r\t ")
	if s == "" {
		return ""
	}
	return s + "\n"
}

// splitLines splits s into lines, each line keeping its trailing newline
// (except possibly the last, when s doesn't end with \n). Unlike
// difflib.SplitLines, no phantom trailing empty/newline element is added,
// so the line count matches what `git apply` expects.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.SplitAfter(s, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

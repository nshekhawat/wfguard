package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// ---- surfaceTriggers --------------------------------------------------------

func TestSurfaceTriggers(t *testing.T) {
	cases := []struct {
		name string
		on   any
		want []string
	}{
		{"single string", "push", []string{"push"}},
		{"list", []any{"push", "pull_request"}, []string{"push", "pull_request"}},
		{"map (sorted)", map[string]any{"push": nil, "pull_request_target": nil}, []string{"pull_request_target", "push"}},
		{"nil", nil, []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := surfaceTriggers(&workflow.Workflow{On: tc.on})
			// Map case: order matters (sorted). For list case, preserve input order.
			if !equalStrings(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- groupByWorkflowPath ----------------------------------------------------

func TestGroupByWorkflowPath(t *testing.T) {
	fs := []findings.Finding{
		{Severity: findings.High, Kind: "k", Location: ".github/workflows/ci.yml:job:step[0]"},
		{Severity: findings.Low, Kind: "k", Location: ".github/workflows/ci.yml:permissions"},
		{Severity: findings.Medium, Kind: "k", Location: ".github/workflows/release.yml:deploy:step[1]"},
		{Severity: findings.Low, Kind: "k", Location: "no-colon-just-a-path"}, // edge: no colon
	}
	got := groupByWorkflowPath(fs)

	if n := len(got[".github/workflows/ci.yml"]); n != 2 {
		t.Errorf("ci.yml bucket = %d, want 2", n)
	}
	if n := len(got[".github/workflows/release.yml"]); n != 1 {
		t.Errorf("release.yml bucket = %d, want 1", n)
	}
	if _, ok := got["no-colon-just-a-path"]; !ok {
		t.Errorf("colonless location should still bucket under itself")
	}
}

// ---- writeReport ------------------------------------------------------------

func TestWriteReport_MarkdownToStdoutPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.md")
	fs := []findings.Finding{{Severity: findings.High, Kind: "x", Location: "f.yml:1", Evidence: "e", Fix: "f", Source: "rules"}}
	if err := writeReport("markdown", path, fs); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, "# wfguard report") {
		t.Errorf("expected markdown header, got: %s", body)
	}
}

func TestWriteReport_SARIFDefaultsFilename(t *testing.T) {
	// Use a working dir we can write to and clean up.
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	fs := []findings.Finding{{Severity: findings.High, Kind: "x", Location: "f.yml:1", Evidence: "e", Fix: "f", Source: "rules"}}
	if err := writeReport("sarif", "", fs); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, filepath.Join(dir, "report.sarif"))
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("default report.sarif not valid JSON: %v", err)
	}
}

func TestWriteReport_BothWritesTwoFiles(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "report")
	fs := []findings.Finding{{Severity: findings.Low, Kind: "y", Location: "f.yml:1", Evidence: "e", Fix: "f", Source: "rules"}}
	if err := writeReport("both", prefix, fs); err != nil {
		t.Fatal(err)
	}
	if !exists(prefix + ".md") {
		t.Error("expected report.md")
	}
	if !exists(prefix + ".sarif") {
		t.Error("expected report.sarif")
	}
}

func TestWriteReport_UnknownFormat(t *testing.T) {
	if err := writeReport("xml", "", nil); err == nil {
		t.Error("expected error for unknown format")
	}
}

// ---- writeOne ---------------------------------------------------------------

func TestWriteOne_StdoutPathIsEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeOne("", "", func(w io.Writer) error {
		_, err := w.Write([]byte("x"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Buffer is unused (the function writes to os.Stdout). We can't capture
	// stdout here without invasive plumbing — just ensure no error path.
	_ = buf
}

func TestWriteOne_BubblesUpOpenError(t *testing.T) {
	// Path inside a non-existent directory.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "file.txt")
	err := writeOne(bad, bad, func(w io.Writer) error { return nil })
	if err == nil {
		t.Error("expected open error")
	}
}

// ---- envOr ------------------------------------------------------------------

func TestEnvOr(t *testing.T) {
	t.Setenv("WFG_TEST_X", "from-env")
	if got := envOr("WFG_TEST_X", "fallback"); got != "from-env" {
		t.Errorf("envOr with set env = %q", got)
	}
	if got := envOr("WFG_TEST_NEVER_SET_x", "fallback"); got != "fallback" {
		t.Errorf("envOr with unset env = %q", got)
	}
}

// ---- runScan end-to-end -----------------------------------------------------

func TestRunScan_VulnerableTestdata_FindsCritical(t *testing.T) {
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("..", "..", "testdata", "vulnerable", "pwn_request.yml")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "pwn_request.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture markdown to a file so we can assert on it.
	out := filepath.Join(t.TempDir(), "report.md")

	// runScan calls os.Exit(1) on blocking findings — use --soft-fail to avoid that.
	err = runScan(context.Background(), repo, scanFlags{
		reportFmt: "markdown",
		output:    out,
		softFail:  true,
	})
	if err != nil {
		t.Fatalf("runScan() = %v", err)
	}
	body = []byte(readFile(t, out))
	if !strings.Contains(string(body), "pwn-request") {
		t.Errorf("report missing pwn-request finding:\n%s", body)
	}
}

func TestRunScan_SafeTestdata_NoFindings(t *testing.T) {
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("..", "..", "testdata", "safe", "safe.yml")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "safe.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "report.md")
	if err := runScan(context.Background(), repo, scanFlags{
		reportFmt: "markdown",
		output:    out,
	}); err != nil {
		t.Fatalf("runScan = %v", err)
	}
	body = []byte(readFile(t, out))
	if !strings.Contains(string(body), "No findings.") {
		t.Errorf("safe scan should report 'No findings.', got:\n%s", body)
	}
}

func TestRunScan_MinSeverity_HidesBelowThreshold(t *testing.T) {
	// unpinned.yml only produces Medium-severity findings. Default
	// --min-severity high should hide all of them; --min-severity low
	// should surface them.
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("..", "..", "testdata", "vulnerable", "unpinned.yml")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "unpinned.yml"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	// Default threshold = high → nothing should render.
	out := filepath.Join(t.TempDir(), "report.md")
	if err := runScan(context.Background(), repo, scanFlags{
		reportFmt:   "markdown",
		output:      out,
		minSeverity: "high",
		softFail:    true,
	}); err != nil {
		t.Fatalf("runScan(high) = %v", err)
	}
	hi := readFile(t, out)
	if !strings.Contains(hi, "No findings.") {
		t.Errorf("expected 'No findings.' at --min-severity=high, got:\n%s", hi)
	}

	// Threshold = low → both unpinned-action findings should appear.
	out = filepath.Join(t.TempDir(), "report.md")
	if err := runScan(context.Background(), repo, scanFlags{
		reportFmt:   "markdown",
		output:      out,
		minSeverity: "low",
		softFail:    true,
	}); err != nil {
		t.Fatalf("runScan(low) = %v", err)
	}
	lo := readFile(t, out)
	if !strings.Contains(lo, "unpinned-action") {
		t.Errorf("expected unpinned-action visible at --min-severity=low, got:\n%s", lo)
	}
}

func TestRunScan_BadMinSeverityErrors(t *testing.T) {
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	_ = os.MkdirAll(wfDir, 0o755)
	if err := os.WriteFile(filepath.Join(wfDir, "x.yml"), []byte("name: x\non: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runScan(context.Background(), repo, scanFlags{
		reportFmt:   "markdown",
		minSeverity: "spicy",
		softFail:    true,
	})
	if err == nil || !strings.Contains(err.Error(), "min-severity") {
		t.Errorf("expected --min-severity error, got %v", err)
	}
}

func TestRunScan_NoWorkflowsDir_ReturnsError(t *testing.T) {
	repo := t.TempDir()
	err := runScan(context.Background(), repo, scanFlags{reportFmt: "markdown", softFail: true})
	if err == nil {
		t.Error("expected error when target has no .github/workflows")
	}
}

// ---- helpers ---------------------------------------------------------------

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// surfaceTriggers + groupByWorkflowPath get exercised again here against
// real workflow data, just to sanity-check the integration with the rest
// of the package.
func TestSurfaceTriggers_FromYAMLishOnValue(t *testing.T) {
	wf := &workflow.Workflow{On: map[string]any{"push": map[string]any{"branches": []string{"main"}}}}
	got := surfaceTriggers(wf)
	want := []string{"push"}
	if !equalStrings(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Diagnostic helper: dump scan flags for failing tests.
func (f scanFlags) String() string {
	parts := []string{
		"reportFmt=" + f.reportFmt,
		"output=" + f.output,
		"backend=" + f.backend,
		fmt.Sprintf("llm=%v", f.useLLM),
		fmt.Sprintf("softFail=%v", f.softFail),
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

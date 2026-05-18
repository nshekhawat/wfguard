package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/report"
)

func sampleFindings() []findings.Finding {
	return []findings.Finding{
		{
			Severity: findings.Critical,
			Kind:     "pwn-request",
			Location: ".github/workflows/ci.yml:test:step[0]",
			Evidence: "uses: actions/checkout@v4\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}",
			Fix:      "Switch the trigger to pull_request, or remove the explicit checkout of the PR HEAD.",
			Source:   "rules",
		},
		{
			Severity: findings.Medium,
			Kind:     "unpinned-action",
			Location: ".github/workflows/ci.yml:test:step[0]",
			Evidence: "uses: actions/checkout@v4",
			Fix:      "Pin to a commit SHA.",
			Source:   "rules",
		},
	}
}

func TestWriteMarkdown_RendersBucketsAndContent(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, sampleFindings()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"# wfguard report",
		"## critical (1)",
		"## medium (1)",
		"pwn-request",
		"unpinned-action",
		"actions/checkout@v4",
		"Pin to a commit SHA.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n----\n%s", want, out)
		}
	}
}

func TestWriteMarkdown_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("expected 'No findings.' in empty markdown, got %q", buf.String())
	}
}

func TestWriteSARIF_ProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, sampleFindings()); err != nil {
		t.Fatal(err)
	}

	// Top-level structural check via generic JSON unmarshal — confirms it
	// parsed and has the expected SARIF shape without depending on the SARIF
	// library here.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if v, _ := doc["version"].(string); v != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want 1 run", doc["runs"])
	}
	run := runs[0].(map[string]any)

	results, ok := run["results"].([]any)
	if !ok || len(results) != len(sampleFindings()) {
		t.Errorf("results count = %v, want %d", len(results), len(sampleFindings()))
	}

	// Tool driver name is "wfguard".
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["name"] != "wfguard" {
		t.Errorf("driver.name = %v", driver["name"])
	}

	// At least one rule descriptor exists; ids are wfguard.<kind>.
	rules, _ := driver["rules"].([]any)
	if len(rules) == 0 {
		t.Error("no rule descriptors emitted")
	}
	for _, r := range rules {
		id := r.(map[string]any)["id"].(string)
		if !strings.HasPrefix(id, "wfguard.") {
			t.Errorf("rule id %q not prefixed with wfguard.", id)
		}
	}
}

func TestWriteSARIF_LevelMapping(t *testing.T) {
	cases := []struct {
		sev   findings.Severity
		level string
	}{
		{findings.Critical, "error"},
		{findings.High, "error"},
		{findings.Medium, "warning"},
		{findings.Low, "note"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		f := findings.Finding{Severity: tc.sev, Kind: "x", Location: "f.yml:1", Evidence: "e", Fix: "f", Source: "rules"}
		if err := report.WriteSARIF(&buf, []findings.Finding{f}); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		runs := doc["runs"].([]any)
		results := runs[0].(map[string]any)["results"].([]any)
		got := results[0].(map[string]any)["level"]
		if got != tc.level {
			t.Errorf("severity %s -> level %v, want %s", tc.sev, got, tc.level)
		}
	}
}

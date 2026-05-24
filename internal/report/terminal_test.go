package report_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/report"
)

func sampleTerminalFindings() []findings.Finding {
	return []findings.Finding{
		{
			Severity: findings.Critical,
			Kind:     "expression-injection",
			Location: ".github/workflows/expression_injection.yml:triage:step[2]",
			Evidence: "run: echo \"PR title: ${{ github.event.pull_request.title }}\"\n# expression: ${{ github.event.pull_request.title }}",
			Fix:      "Move attacker-controlled values out of the run body. Bind the value to an `env:` var on the step (`env: TITLE: ${{ ... }}`) and reference `$TITLE` (with hard quoting) inside the run.",
			Source:   "rules",
		},
		{
			Severity: findings.Critical,
			Kind:     "pwn-request",
			Location: ".github/workflows/pwn_request.yml:test:step[0]",
			Evidence: "on: pull_request_target\nuses: actions/checkout@v4\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}",
			Fix:      "Switch the trigger to pull_request, or remove the explicit checkout of the PR HEAD.",
			Source:   "rules",
		},
		{
			Severity: findings.High,
			Kind:     "compromised-action",
			Location: ".github/workflows/known_bad.yml:diff:step[1]",
			Evidence: "uses: tj-actions/changed-files@v44\n# Compromised in March 2025: malicious commit force-pushed across all tagged versions.",
			Fix:      "Audit which version is in use. Rotate secrets if in the incident window and pin to a known-good post-incident SHA.",
			Source:   "rules",
		},
		{
			Severity: findings.High,
			Kind:     "expression-injection",
			Location: ".github/workflows/expression_injection.yml:triage:step[3]",
			Evidence: "env:\n  BODY: ${{ github.event.issue.body }}\nrun: ... $BODY ...",
			Fix:      "Even via env-var indirection, attacker-controlled values are exploitable through $(...), backticks, and unquoted expansion. Validate the value before use or quote it with single-quotes.",
			Source:   "agent",
		},
	}
}

func TestWriteTerminal_NoColor_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteTerminal(&buf, nil, report.TerminalOptions{
		Workflows: 3, Hidden: 2, Threshold: "high",
	}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"3 workflows scanned",
		"no findings",
		"2 findings hidden below --min-severity high",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("expected no ANSI escapes when Color=false, got:\n%s", out)
	}
}

func TestWriteTerminal_NoColor_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteTerminal(&buf, sampleTerminalFindings(), report.TerminalOptions{
		Workflows: 3, Hidden: 2, Threshold: "high", ExitOnFindings: true, Width: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"4 findings",
		"2 critical",
		"2 high",
		"CRITICAL",
		"HIGH",
		"expression-injection",
		"pwn-request",
		"compromised-action",
		".github/workflows/pwn_request.yml:test:step[0]",
		"[agent]",     // the one agent-source finding gets a tag
		"exit 1",      // footer mentions exit
		"--soft-fail", // footer mentions the bypass
		"--min-severity high",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("expected no ANSI escapes when Color=false")
	}
}

func TestWriteTerminal_Color_EmitsANSI(t *testing.T) {
	var buf bytes.Buffer
	err := report.WriteTerminal(&buf, sampleTerminalFindings(), report.TerminalOptions{
		Color: true, Workflows: 3, Hidden: 0, Threshold: "high", ExitOnFindings: false, Width: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI escapes when Color=true, got plain text")
	}
}

func TestIsTerminal_PipedStdinIsFalse(t *testing.T) {
	// os.Stdin during `go test` is usually a pipe; this checks the
	// negative path and our nil-safety.
	if report.IsTerminal(nil) {
		t.Error("IsTerminal(nil) returned true")
	}
	// A regular file isn't a TTY either.
	f, err := os.CreateTemp("", "wfg-tty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if report.IsTerminal(f) {
		t.Error("IsTerminal(<regular file>) returned true")
	}
}

func TestIsTerminal_NoColorEnvDisables(t *testing.T) {
	// Even on a real TTY, NO_COLOR should force IsTerminal to false.
	t.Setenv("NO_COLOR", "1")
	// We can't easily construct a real TTY for the *os.File here, but a
	// stat-able regular file is enough to confirm the NO_COLOR guard runs
	// before the stat.
	f, _ := os.CreateTemp("", "wfg-tty-*")
	if f != nil {
		defer os.Remove(f.Name())
		defer f.Close()
	}
	if report.IsTerminal(f) {
		t.Error("IsTerminal should respect NO_COLOR")
	}
}

// TestWriteTerminal_Demo dumps a representative rendering to stderr so it's
// easy to eyeball during development with `go test -run Demo -v`.
func TestWriteTerminal_Demo(t *testing.T) {
	if testing.Short() {
		t.Skip("demo render skipped in short mode")
	}
	report.WriteTerminal(os.Stderr, sampleTerminalFindings(), report.TerminalOptions{
		Color: true, Workflows: 3, Hidden: 2, Threshold: "high", ExitOnFindings: true, Width: 80,
	})
}

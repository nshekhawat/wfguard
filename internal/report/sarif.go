// Package report renders findings to SARIF and Markdown.
//
// SARIF is the schema GitHub's code-scanning UI consumes — emitting it lets
// wfguard plug straight into the Security tab of any repo it audits.
// Markdown is for human review and the demo recording.
package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/nshekhawat/wfguard/internal/findings"
)

// toolName + toolURI are baked into every SARIF run we emit.
const (
	toolName = "wfguard"
	toolURI  = "https://github.com/nshekhawat/wfguard"
	toolVer  = "0.0.1"
)

// WriteMarkdown renders findings as a human-readable Markdown report.
func WriteMarkdown(w io.Writer, fs []findings.Finding) error {
	if len(fs) == 0 {
		_, err := fmt.Fprintln(w, "# wfguard report\n\nNo findings.")
		return err
	}
	if _, err := fmt.Fprintf(w, "# wfguard report\n\n%d findings.\n\n", len(fs)); err != nil {
		return err
	}
	bySev := map[findings.Severity][]findings.Finding{}
	for _, f := range fs {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	for _, sev := range []findings.Severity{findings.Critical, findings.High, findings.Medium, findings.Low} {
		bucket := bySev[sev]
		if len(bucket) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s (%d)\n\n", sev, len(bucket))
		for _, f := range bucket {
			fmt.Fprintf(w, "### %s — `%s`\n\n", f.Kind, f.Location)
			fmt.Fprintf(w, "**Source:** %s\n\n", f.Source)
			fmt.Fprintf(w, "**Evidence:**\n\n```\n%s\n```\n\n", f.Evidence)
			fmt.Fprintf(w, "**Fix:** %s\n\n---\n\n", f.Fix)
		}
	}
	return nil
}

// WriteSARIF renders findings as SARIF v2.1.0 to w.
//
// One Run per call. Each unique finding kind becomes a ReportingDescriptor
// (rule) with id "wfguard.<kind>". Each finding becomes a Result whose level
// is mapped from severity:
//
//	critical, high -> "error"
//	medium         -> "warning"
//	low            -> "note"
//
// When a Location string is parseable as "path:job:step[N]" or "path:line",
// the physicalLocation gets an artifactLocation + a best-effort region. We
// don't currently track real line numbers, so the region defaults to line 1
// — the file is correct, the line is approximate.
func WriteSARIF(w io.Writer, fs []findings.Finding) error {
	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		return fmt.Errorf("new sarif report: %w", err)
	}

	run := sarif.NewRunWithInformationURI(toolName, toolURI)
	run.Tool.Driver.WithVersion(toolVer)
	run.Tool.Driver.WithSemanticVersion(toolVer)

	// Add a rule descriptor per unique kind, once.
	seenRules := map[string]bool{}
	for _, f := range fs {
		ruleID := "wfguard." + f.Kind
		if seenRules[ruleID] {
			continue
		}
		seenRules[ruleID] = true
		desc := ruleDescription(f.Kind)
		run.AddRule(ruleID).
			WithName(toCamel(f.Kind)).
			WithDescription(desc).
			WithFullDescription(sarif.NewMultiformatMessageString(desc)).
			WithHelpURI(toolURI)
	}

	for _, f := range fs {
		ruleID := "wfguard." + f.Kind
		result := sarif.NewRuleResult(ruleID).
			WithLevel(severityToLevel(f.Severity)).
			WithMessage(sarif.NewTextMessage(messageFor(f)))
		if loc := buildLocation(f.Location); loc != nil {
			result.AddLocation(loc)
		}
		run.AddResult(result)
	}

	report.AddRun(run)
	return report.PrettyWrite(w)
}

// severityToLevel maps wfguard's 4-tier severity onto SARIF's 3-tier level.
func severityToLevel(s findings.Severity) string {
	switch s {
	case findings.Critical, findings.High:
		return "error"
	case findings.Medium:
		return "warning"
	case findings.Low:
		return "note"
	}
	return "none"
}

// buildLocation turns a wfguard Location string into a SARIF Location.
//
// Supported shapes:
//
//	"path/to/wf.yml:job-id:step[3]" -> file=path/to/wf.yml, line=1
//	"path/to/wf.yml:permissions"    -> file=path/to/wf.yml, line=1
//	"path/to/wf.yml:42"             -> file=path/to/wf.yml, line=42
//	"path/to/wf.yml"                -> file=path/to/wf.yml, no region
//
// If we can't extract a path at all, returns nil and the result is emitted
// without a location (still legal SARIF).
func buildLocation(s string) *sarif.Location {
	if s == "" {
		return nil
	}
	path, line := s, 0
	if i := strings.Index(s, ":"); i > 0 {
		path = s[:i]
		// If the rest is a single integer, treat it as a line number.
		if n, err := strconv.Atoi(s[i+1:]); err == nil && n > 0 {
			line = n
		}
	}
	if path == "" {
		return nil
	}
	pl := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(path))
	if line == 0 {
		line = 1
	}
	pl.WithRegion(sarif.NewSimpleRegion(line, line))
	return sarif.NewLocationWithPhysicalLocation(pl)
}

// messageFor builds the SARIF result message: short evidence + fix on
// separate lines so the GitHub UI shows both.
func messageFor(f findings.Finding) string {
	var sb strings.Builder
	sb.WriteString(strings.TrimSpace(f.Evidence))
	if f.Fix != "" {
		sb.WriteString("\n\nFix: ")
		sb.WriteString(strings.TrimSpace(f.Fix))
	}
	return sb.String()
}

// toCamel turns "expression-injection" into "ExpressionInjection".
func toCamel(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// ruleDescription is the long-form text that appears on the rule definition
// in SARIF. Keep these aligned with internal/rules/* and the system prompt.
func ruleDescription(kind string) string {
	switch kind {
	case "unpinned-action":
		return "Action `uses:` reference points to a mutable tag or branch instead of a commit SHA. The reference can change without notice."
	case "pwn-request":
		return "Workflow triggered by `pull_request_target` checks out the PR HEAD ref. Untrusted code from the PR runs with the repo's secrets in scope."
	case "compromised-action":
		return "Action is on the known-compromised list. Audit which version is in use and rotate any secrets that were in scope during the incident window."
	case "broad-permissions":
		return "Workflow grants `permissions: write-all` or has no `permissions:` block at all. The job's GITHUB_TOKEN is broader than necessary."
	case "expression-injection":
		return "Attacker-controlled GitHub expression (e.g. PR title, commit message, comment body) flows into a `run:` script. Even via env-var indirection, the value can be exploited through `$()` and backticks."
	case "secrets-exposure":
		return "Repository secret is passed to an action that is not pinned to a commit SHA. A malicious tag move would silently exfiltrate the secret."
	case "self-hosted-runner-pr":
		return "Self-hosted runner used by a workflow that can run code from forks. PR code runs with persistent runner state and host network access."
	case "reusable-workflow-input-injection":
		return "`workflow_call` workflow interpolates `${{ inputs.* }}` directly into a `run:` body. Any caller can inject shell commands."
	}
	return "wfguard finding: " + kind
}

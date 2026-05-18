package llm

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nshekhawat/wfguard/internal/findings"
)

// fixerSystemPrompt is the system instruction sent to the LLM when asking
// it to harden one workflow file. Strict output discipline: ONLY YAML, no
// prose, no markdown fences. The agent loop's audit prompt is a different
// thing entirely — this one is purely a code-edit task.
const fixerSystemPrompt = `You are a GitHub Actions security hardening expert.

Given a workflow YAML file and a list of confirmed security findings on it,
produce a corrected version of the file that addresses the findings while
preserving all unrelated content, comments, and indentation.

OUTPUT RULES (non-negotiable):
- Output ONLY the corrected YAML. No prose. No explanations.
- Do NOT wrap the YAML in markdown fences.
- Preserve the original indentation and comments exactly where unchanged.
- Make the smallest changes necessary to fix the listed findings.
- If you cannot confidently fix a finding, leave that part of the file
  alone — partial fixes are fine.

STANDARD MITIGATIONS:
- pwn-request: switch the trigger from "pull_request_target" to
  "pull_request" (drops secrets from scope), OR remove the explicit
  checkout of the PR HEAD ref. If both untrusted code and secrets are
  genuinely needed, gate the workflow behind a manual approval via
  "environment:" with required reviewers.
- expression-injection (direct, ${{ ... }} inside a run body): bind the
  value to an env: var on the step, then reference "$VAR" with hard
  quoting in the run body.
- expression-injection (env-indirect): if the value comes from a tainted
  source like ${{ github.event.* }}, validate it before use (e.g. shell
  glob check against an allowlist) and always quote with double quotes.
- secrets-exposure: pin the action's "uses:" to a 40-char commit SHA
  instead of a tag. Add a comment with the original tag for human
  reference.
- self-hosted-runner-pr: switch "runs-on:" to "ubuntu-latest", OR add
  "if: github.event.pull_request.head.repo.full_name == github.repository"
  to the job so forks don't run on the self-hosted runner.
- reusable-workflow-input-injection: bind the input to an env: var on
  the step and reference it as "$VAR" in the run body.
`

// FixRequest packages everything the file-level fixer needs.
type FixRequest struct {
	Path     string             // workflow path, e.g. ".github/workflows/ci.yml"
	Source   string             // current file contents
	Findings []findings.Finding // visible findings on this file
}

// FixResult is the fixer's output for one file. Fixed is empty when the
// LLM declined or produced something we couldn't validate; callers should
// treat that as "no fix available, skip this file".
type FixResult struct {
	Path  string
	Fixed string // empty when no usable fix was produced
	Note  string // human-readable explanation (e.g. "yaml parse failed")
}

// Fixer wraps a Generator with the prompt + validation logic for hardening.
// One Fixer instance is reused across all files in a scan.
type Fixer struct {
	Generator   Generator
	ModelID     string
	Temperature float32 // default 0.0 — we want deterministic edits, not creativity
}

// NewFixer constructs a Fixer with sane defaults.
func NewFixer(gen Generator, modelID string) *Fixer {
	if modelID == "" {
		modelID = DefaultModel
	}
	return &Fixer{Generator: gen, ModelID: modelID, Temperature: 0.0}
}

// Propose asks the LLM to harden one workflow file. Returns a FixResult
// where Fixed is the corrected source, or empty if no usable fix was
// produced (with Note explaining why).
//
// The fixer never errors out for content reasons — a failure on one file
// shouldn't kill the whole hardening pass. Real errors (network,
// generator bugs) DO propagate so callers can surface them.
func (f *Fixer) Propose(ctx context.Context, req FixRequest) (FixResult, error) {
	if strings.TrimSpace(req.Source) == "" {
		return FixResult{Path: req.Path, Note: "empty source"}, nil
	}
	if len(req.Findings) == 0 {
		return FixResult{Path: req.Path, Note: "no findings to fix"}, nil
	}

	user := buildFixerUserPrompt(req)
	resp, err := f.Generator.Generate(ctx, GenerateRequest{
		System:      fixerSystemPrompt,
		History:     []Turn{{Role: RoleUser, Text: user}},
		Temperature: f.Temperature,
		Model:       f.ModelID,
	})
	if err != nil {
		return FixResult{}, fmt.Errorf("propose fix for %s: %w", req.Path, err)
	}

	fixed := stripCodeFence(resp.Text)
	fixed = strings.TrimSpace(fixed)
	if fixed == "" {
		return FixResult{Path: req.Path, Note: "model returned empty"}, nil
	}

	// Validate: must parse as YAML. We don't compare semantics; we just
	// need confidence that `git apply` won't produce a broken workflow.
	var probe any
	if err := yaml.Unmarshal([]byte(fixed), &probe); err != nil {
		return FixResult{Path: req.Path, Note: "model output failed YAML parse: " + err.Error()}, nil
	}

	// Ensure the fix actually changes something — otherwise no patch hunk
	// to emit. (Comparison is byte-level after a trailing-newline normalize.)
	if normalizeForCompare(fixed) == normalizeForCompare(req.Source) {
		return FixResult{Path: req.Path, Note: "model returned the file unchanged"}, nil
	}

	return FixResult{Path: req.Path, Fixed: ensureTrailingNewline(fixed)}, nil
}

// buildFixerUserPrompt formats one FixRequest into the user message.
func buildFixerUserPrompt(req FixRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "File: %s\n\n", req.Path)
	sb.WriteString("Findings on this file:\n")
	for _, f := range req.Findings {
		fmt.Fprintf(&sb, "- [%s] %s @ %s\n  evidence: %s\n  recommended fix: %s\n",
			f.Severity, f.Kind, f.Location,
			oneLineFix(f.Evidence, 200), oneLineFix(f.Fix, 240))
	}
	sb.WriteString("\nOriginal YAML (preserve everything you don't touch):\n")
	sb.WriteString(req.Source)
	if !strings.HasSuffix(req.Source, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("\nReturn the corrected YAML now, and nothing else.\n")
	return sb.String()
}

// stripCodeFence drops a ```yaml / ```yml / ``` fence wrapping if present.
// Models trained on markdown often reach for fences even when told not to.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop opening fence (```yaml, ```yml, or just ```)
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return s
	}
	body := s[nl+1:]
	// Drop closing fence
	if i := strings.LastIndex(body, "```"); i >= 0 {
		body = body[:i]
	}
	return strings.TrimSpace(body)
}

func ensureTrailingNewline(s string) string {
	if !strings.HasSuffix(s, "\n") {
		return s + "\n"
	}
	return s
}

func normalizeForCompare(s string) string {
	return strings.TrimRight(s, "\n\r \t")
}

func oneLineFix(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

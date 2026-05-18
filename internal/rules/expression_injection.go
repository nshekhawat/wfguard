package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// dangerousExpressions are GitHub expression paths whose values come from
// trigger payload fields an attacker controls (PR title, commit message, etc).
// If any of these appears inside a `run:` body — directly or via env-var
// indirection — it's a shell injection sink.
//
// The list is intentionally a substring set rather than a strict path
// grammar: GitHub expressions allow whitespace, formatting calls, and array
// indexing inside `${{ ... }}`, so a substring match is both simpler and
// catches odd-but-legal forms like `${{ format('{0}', github.event.pull_request.title) }}`.
var dangerousExpressions = []string{
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.description",
	"github.event.pull_request.head.repo.homepage",
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.release.body",
	"github.event.head_commit.message",
	"github.event.head_commit.author.name",
	"github.event.head_commit.author.email",
	"github.event.commits", // catches commits[*].message / .author.*
	"github.head_ref",
}

// ExpressionInjectionRule flags attacker-controlled GitHub expressions
// flowing into shell sinks. Two paths:
//
//  1. Direct: `${{ github.event.pull_request.title }}` literally inside a
//     `run:` body. The expression is interpolated *before* the shell sees the
//     string, so quoting in the YAML doesn't help.
//
//  2. Indirect via env: `env: TITLE: ${{ github.event.pull_request.title }}`
//     and the run body references `$TITLE`. This is widely recommended as
//     the mitigation for (1), but it's still exploitable: `$()` and
//     backticks inside the env value are evaluated by the shell unless every
//     consumer hard-quotes the variable. A cautious auditor flags it; a
//     reviewer can mark it accepted with rationale.
type ExpressionInjectionRule struct{}

func (ExpressionInjectionRule) Name() string { return "expression-injection" }

func (ExpressionInjectionRule) Check(wf *workflow.Workflow) []findings.Finding {
	var out []findings.Finding

	// Workflow-level env that's tainted (env name -> matched expression).
	wfTainted := taintedEnvs(wf.Env)

	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		jobTainted := taintedEnvs(job.Env)

		for _, st := range job.Steps {
			if st == nil || !st.IsRun() {
				continue
			}

			// Direct: dangerous expression appears in the run body.
			if expr := matchDangerousExpr(st.Run); expr != "" {
				out = append(out, findings.Finding{
					Severity: findings.Critical,
					Kind:     "expression-injection",
					Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
					Evidence: fmt.Sprintf("run: %s\n# expression: ${{ %s }}", runExcerpt(st.Run, 200), expr),
					Fix: "Move attacker-controlled values out of the run body. Bind the value to an `env:` var on the step (`env: TITLE: ${{ ... }}`) and reference `$TITLE` (with hard quoting) inside the run.",
					Source: "rules",
				})
				continue
			}

			// Indirect: a tainted env var is in scope and the run references
			// it. Step-level env wins over job-level wins over workflow-level.
			tainted := mergeTainted(wfTainted, jobTainted, taintedEnvs(st.Env))
			for envName, expr := range tainted {
				if !runReferencesEnv(st.Run, envName) {
					continue
				}
				out = append(out, findings.Finding{
					Severity: findings.High,
					Kind:     "expression-injection",
					Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
					Evidence: fmt.Sprintf("env:\n  %s: ${{ %s }}\nrun: ... $%s ...", envName, expr, envName),
					Fix: "Even via env-var indirection, attacker-controlled values are exploitable through `$(...)`, backticks, and unquoted expansion. Validate the value (e.g. reject anything outside a safe charset) or quote with single-quotes for any consumer that doesn't itself shell out.",
					Source: "rules",
				})
				break // one finding per step is enough
			}
		}
	}
	return out
}

// taintedEnvs returns the subset of an env map whose values contain a
// dangerous expression. Returned map is keyed by env-var name.
func taintedEnvs(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	var out map[string]string
	for k, v := range env {
		if expr := matchDangerousExpr(v); expr != "" {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = expr
		}
	}
	return out
}

// matchDangerousExpr returns the first dangerous expression substring in s,
// or "" if none.
func matchDangerousExpr(s string) string {
	if s == "" {
		return ""
	}
	for _, expr := range dangerousExpressions {
		if strings.Contains(s, expr) {
			return expr
		}
	}
	return ""
}

// mergeTainted merges any number of tainted-env maps with later maps winning.
func mergeTainted(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// runReferencesEnv reports whether a run body references an env variable by
// name. Covers the common shells: bash/sh ($NAME, ${NAME}, ${NAME:-…}) and
// PowerShell ($env:NAME, ${env:NAME}).
func runReferencesEnv(run, name string) bool {
	if name == "" {
		return false
	}
	candidates := []string{
		"$" + name,
		"${" + name,
		"$env:" + name,
		"${env:" + name,
	}
	for _, c := range candidates {
		if hasWordOccurrence(run, c) {
			return true
		}
	}
	return false
}

// hasWordOccurrence reports whether s contains substr ending at a non-word
// boundary, i.e. "$FOO" matches "$FOO " but not "$FOOBAR".
func hasWordOccurrence(s, substr string) bool {
	idx := 0
	for {
		i := strings.Index(s[idx:], substr)
		if i < 0 {
			return false
		}
		end := idx + i + len(substr)
		if end >= len(s) || !isWordChar(s[end]) {
			return true
		}
		idx = idx + i + 1
	}
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// runExcerpt collapses a multiline run body to a one-line preview suitable
// for SARIF/Markdown evidence. Truncates to maxLen.
func runExcerpt(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

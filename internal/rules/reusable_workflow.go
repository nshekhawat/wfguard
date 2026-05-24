package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// ReusableWorkflowInputRule flags reusable workflows (`on: workflow_call`)
// that interpolate `${{ inputs.* }}` directly into a `run:` body.
//
// Severity is `medium` by default. Inputs come from the caller, not directly
// from an attacker, so the real risk only crystallises when a caller forwards
// attacker-controlled data (e.g. `github.event.pull_request.title`) into the
// input. wfguard does not yet build a cross-workflow call graph, so it cannot
// make that escalation automatically. Treat findings here as "audit the
// callers"; once a chain to an untrusted trigger (`pull_request_target`,
// `issue_comment`, fork PR) exists, it is a real high-severity injection.
type ReusableWorkflowInputRule struct{}

func (ReusableWorkflowInputRule) Name() string { return "reusable-workflow-input-injection" }

func (ReusableWorkflowInputRule) Check(wf *workflow.Workflow) []findings.Finding {
	if !triggersInclude(wf.On, "workflow_call") {
		return nil
	}
	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for _, st := range job.Steps {
			if st == nil || !st.IsRun() {
				continue
			}
			if !mentionsInputsExpr(st.Run) {
				continue
			}
			out = append(out, findings.Finding{
				Severity: findings.Medium,
				Kind:     "reusable-workflow-input-injection",
				Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
				Evidence: fmt.Sprintf("on: workflow_call\nrun: %s", runExcerpt(st.Run, 200)),
				Fix: "Pass the input through `env:` on the step (`env: FOO: ${{ inputs.foo }}`) and reference `\"$FOO\"` (quoted) inside the run. This is `medium` because the actual risk depends on the caller: any caller that forwards `github.event.*` (PR title, issue body, comment, fork ref) into this input should be treated as `high`.",
				Source: "rules",
			})
		}
	}
	return out
}

// mentionsInputsExpr reports whether a run body contains a literal
// `${{ inputs.X }}` interpolation. Tolerates whitespace variants.
func mentionsInputsExpr(run string) bool {
	// fast path
	if !strings.Contains(run, "inputs.") {
		return false
	}
	for _, prefix := range []string{"${{ inputs.", "${{inputs."} {
		if strings.Contains(run, prefix) {
			return true
		}
	}
	return false
}

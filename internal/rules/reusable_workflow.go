package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// ReusableWorkflowInputRule flags reusable workflows (`on: workflow_call`)
// that interpolate `${{ inputs.* }}` directly into a `run:` body. Reusable
// workflows accept arbitrary caller input and the contract gives no shell
// safety; the standard mitigation is to bind the input to an `env:` var on
// the step and reference `$VAR` from the run.
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
				Severity: findings.High,
				Kind:     "reusable-workflow-input-injection",
				Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
				Evidence: fmt.Sprintf("on: workflow_call\nrun: %s", runExcerpt(st.Run, 200)),
				Fix: "Don't interpolate `${{ inputs.* }}` directly into a `run:` body. Pass the input through `env:` on the step (`env: FOO: ${{ inputs.foo }}`) and reference `\"$FOO\"` (quoted) inside the run.",
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

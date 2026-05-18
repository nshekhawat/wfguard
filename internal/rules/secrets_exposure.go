package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/resolver"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// SecretsExposureRule flags `${{ secrets.* }}` values being passed as a
// `with:` input to a step that is not pinned to a commit SHA. An unpinned
// action whose tag is later moved to a malicious commit will silently start
// receiving any secrets the workflow handed to it.
//
// The rule deliberately ignores `secrets.GITHUB_TOKEN` on its own — it's
// auto-managed by the runner and rotates per-job, so the blast radius is
// bounded. Any other secret in the same `with:` value still triggers.
type SecretsExposureRule struct{}

func (SecretsExposureRule) Name() string { return "secrets-exposure" }

func (SecretsExposureRule) Check(wf *workflow.Workflow) []findings.Finding {
	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for _, st := range job.Steps {
			if st == nil || !st.IsUses() {
				continue
			}
			_, _, _, ref, err := resolver.ParseUses(st.Uses)
			if err != nil || resolver.IsSHA(ref) {
				continue
			}
			// Action is unpinned. Look for non-trivial secret refs in `with:`.
			for k, v := range st.With {
				vs, ok := v.(string)
				if !ok || !containsSecretRef(vs) {
					continue
				}
				out = append(out, findings.Finding{
					Severity: findings.High,
					Kind:     "secrets-exposure",
					Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
					Evidence: fmt.Sprintf("uses: %s\n  with:\n    %s: %s", st.Uses, k, vs),
					Fix: fmt.Sprintf("Pin %s to a commit SHA before passing secrets through it. An unpinned action's tag can be moved to a malicious commit at any time, which would then receive the secret.", st.Uses),
					Source: "rules",
				})
				break // one finding per step
			}
		}
	}
	return out
}

// containsSecretRef reports whether s mentions a non-trivial secret. The
// magic GITHUB_TOKEN is excluded because it's runtime-scoped and not a
// long-lived credential.
func containsSecretRef(s string) bool {
	if !strings.Contains(s, "secrets.") {
		return false
	}
	stripped := strings.ReplaceAll(s, "secrets.GITHUB_TOKEN", "")
	stripped = strings.ReplaceAll(stripped, "secrets.github_token", "")
	return strings.Contains(stripped, "secrets.")
}

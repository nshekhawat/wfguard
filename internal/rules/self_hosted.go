package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// SelfHostedRunnerRule flags self-hosted runners on workflows whose triggers
// can run code from forks. A forked PR running on a persistent self-hosted
// machine can read previous build artifacts, leak persistent state, or
// escape the runner sandbox onto the host network.
//
// Trigger surface: any workflow with `pull_request` or `pull_request_target`
// in `on:` qualifies as PR-from-fork-reachable.
type SelfHostedRunnerRule struct{}

func (SelfHostedRunnerRule) Name() string { return "self-hosted-runner-pr" }

func (SelfHostedRunnerRule) Check(wf *workflow.Workflow) []findings.Finding {
	var triggers []string
	if triggersInclude(wf.On, "pull_request") {
		triggers = append(triggers, "pull_request")
	}
	if triggersInclude(wf.On, "pull_request_target") {
		triggers = append(triggers, "pull_request_target")
	}
	if len(triggers) == 0 {
		return nil
	}

	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil || !runsOnSelfHosted(job.RunsOn) {
			continue
		}
		out = append(out, findings.Finding{
			Severity: findings.High,
			Kind:     "self-hosted-runner-pr",
			Location: fmt.Sprintf("%s:%s", wf.Path, job.ID),
			Evidence: fmt.Sprintf("on: %s\njobs.%s.runs-on: %v", strings.Join(triggers, ", "), job.ID, job.RunsOn),
			Fix: "Don't run fork PRs on self-hosted runners. Either switch to GitHub-hosted (`runs-on: ubuntu-latest`), gate the workflow behind a `workflow_dispatch` or label trigger maintainers control, or restrict the runner with `if: github.event.pull_request.head.repo.full_name == github.repository`.",
			Source: "rules",
		})
	}
	return out
}

// runsOnSelfHosted reports whether a runs-on value mentions self-hosted.
// Accepts a string ("self-hosted", "[self-hosted, linux]") or a list.
func runsOnSelfHosted(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, "self-hosted")
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.Contains(s, "self-hosted") {
				return true
			}
		}
	}
	return false
}

// Package rules implements the deterministic checks that run before the
// LLM agent. These are the cheap wins: no API cost, no model latency,
// table-testable. They produce findings AND a "suspicions" list that
// seeds the agent's prompt.
package rules

import (
	"fmt"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/resolver"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// Rule is one deterministic check.
type Rule interface {
	Name() string
	Check(*workflow.Workflow) []findings.Finding
}

// Default returns the standard rule set.
func Default() []Rule {
	return []Rule{
		UnpinnedRule{},
		PullRequestTargetCheckoutRule{},
		KnownBadActionRule{KnownBad: DefaultKnownBad()},
		BroadPermissionsRule{},
		ExpressionInjectionRule{},
		SecretsExposureRule{},
		SelfHostedRunnerRule{},
		ReusableWorkflowInputRule{},
	}
}

// Run executes all rules against the workflow and returns the union of
// their findings.
func Run(rs []Rule, wf *workflow.Workflow) []findings.Finding {
	var out []findings.Finding
	for _, r := range rs {
		out = append(out, r.Check(wf)...)
	}
	return out
}

// ---- UnpinnedRule ----------------------------------------------------------

// UnpinnedRule flags `uses:` references on a mutable ref (tag or branch) —
// but only when the publisher isn't on the well-known-orgs allowlist, OR
// the action has been compromised before. Pinning SHAs everywhere is the
// OpenSSF recommendation; in practice it produces overwhelming noise on
// real repos because most `actions/*` and similarly trusted refs are fine.
// We focus on the cases where pinning actually buys you something.
type UnpinnedRule struct{}

func (UnpinnedRule) Name() string { return "unpinned-action" }

func (UnpinnedRule) Check(wf *workflow.Workflow) []findings.Finding {
	knownBad := DefaultKnownBad()
	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for _, st := range job.Steps {
			if st == nil || !st.IsUses() {
				continue
			}
			owner, repo, _, ref, err := resolver.ParseUses(st.Uses)
			if err != nil {
				continue // malformed uses; not our concern here
			}
			if resolver.IsSHA(ref) {
				continue
			}

			full := owner + "/" + repo
			_, isCompromisedHistory := knownBad[full]
			if resolver.IsWellKnownOrg(owner) && !isCompromisedHistory {
				// Trusted publisher with no incident history — silence the
				// hygiene noise. Users who want it can lower --min-severity.
				continue
			}

			fix := fmt.Sprintf("Action is from an unverified publisher (%s); pin to a commit SHA so a tag mutation can't silently swap in malicious code. Replace @%s with the 40-char SHA of the desired release.", full, ref)
			if isCompromisedHistory {
				fix = fmt.Sprintf("%s has been compromised in the past — pin to a known-good post-incident SHA, not a tag. Replace @%s.", full, ref)
			}

			out = append(out, findings.Finding{
				Severity: findings.Medium,
				Kind:     "unpinned-action",
				Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
				Evidence: fmt.Sprintf("uses: %s", st.Uses),
				Fix:      fix,
				Source:   "rules",
			})
		}
	}
	return out
}

// ---- PullRequestTargetCheckoutRule ----------------------------------------

// PullRequestTargetCheckoutRule flags the pwn-request pattern: a workflow
// triggered by `pull_request_target` that also checks out the PR's HEAD ref.
type PullRequestTargetCheckoutRule struct{}

func (PullRequestTargetCheckoutRule) Name() string { return "pwn-request" }

func (PullRequestTargetCheckoutRule) Check(wf *workflow.Workflow) []findings.Finding {
	if !triggersInclude(wf.On, "pull_request_target") {
		return nil
	}
	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for _, st := range job.Steps {
			if st == nil || !st.IsUses() {
				continue
			}
			if !strings.HasPrefix(st.Uses, "actions/checkout@") {
				continue
			}
			withRef, _ := st.With["ref"].(string)
			if withRef == "" {
				continue
			}
			if strings.Contains(withRef, "github.event.pull_request.head") ||
				strings.Contains(withRef, "github.event.pull_request.head.sha") ||
				strings.Contains(withRef, "github.event.pull_request.head.ref") ||
				strings.Contains(withRef, "github.head_ref") {
				out = append(out, findings.Finding{
					Severity: findings.Critical,
					Kind:     "pwn-request",
					Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
					Evidence: fmt.Sprintf("on: pull_request_target\n%s\n  with:\n    ref: %s",
						"uses: "+st.Uses, withRef),
					Fix: "Either switch the trigger to `pull_request` (which sandboxes secrets) " +
						"or remove the explicit checkout of the PR HEAD. If you need both untrusted " +
						"code AND secrets, run the privileged step in a separate workflow gated by a " +
						"label or approval.",
					Source: "rules",
				})
			}
		}
	}
	return out
}

// ---- KnownBadActionRule ---------------------------------------------------

// KnownBadActionRule flags references to actions known to have been
// compromised at some point in their history.
type KnownBadActionRule struct {
	// KnownBad maps "owner/repo" to a human-readable advisory note.
	KnownBad map[string]string
}

func (KnownBadActionRule) Name() string { return "compromised-action" }

func (r KnownBadActionRule) Check(wf *workflow.Workflow) []findings.Finding {
	var out []findings.Finding
	for _, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for _, st := range job.Steps {
			if st == nil || !st.IsUses() {
				continue
			}
			owner, repo, _, _, err := resolver.ParseUses(st.Uses)
			if err != nil {
				continue
			}
			full := owner + "/" + repo
			note, ok := r.KnownBad[full]
			if !ok {
				continue
			}
			out = append(out, findings.Finding{
				Severity: findings.High,
				Kind:     "compromised-action",
				Location: fmt.Sprintf("%s:%s:step[%d]", wf.Path, job.ID, st.Index),
				Evidence: fmt.Sprintf("uses: %s\n# %s", st.Uses, note),
				Fix: "Audit which version is in use. If it falls within the compromised " +
					"window, rotate any secrets that were in scope and pin to a known-good SHA " +
					"published after the incident was resolved.",
				Source: "rules",
			})
		}
	}
	return out
}

// ---- BroadPermissionsRule -------------------------------------------------

// BroadPermissionsRule flags workflows with permissions: write-all or no
// permissions block at all.
type BroadPermissionsRule struct{}

func (BroadPermissionsRule) Name() string { return "broad-permissions" }

func (BroadPermissionsRule) Check(wf *workflow.Workflow) []findings.Finding {
	var sev findings.Severity
	var note string
	switch v := wf.Permissions.(type) {
	case nil:
		sev = findings.Low
		note = "no `permissions:` block; defaults grant write to GITHUB_TOKEN on push events"
	case string:
		if v == "write-all" {
			sev = findings.Medium
			note = "`permissions: write-all` grants the full set of token permissions"
		} else {
			return nil
		}
	default:
		return nil
	}
	return []findings.Finding{{
		Severity: sev,
		Kind:     "broad-permissions",
		Location: fmt.Sprintf("%s:permissions", wf.Path),
		Evidence: note,
		Fix: "Declare a minimal top-level `permissions:` block; grant only the scopes the " +
			"workflow actually needs (e.g. `contents: read`).",
		Source: "rules",
	}}
}

// ---- helpers --------------------------------------------------------------

// triggersInclude reports whether the parsed `on:` value mentions the
// given trigger name.
func triggersInclude(on any, trigger string) bool {
	switch v := on.(type) {
	case string:
		return v == trigger
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == trigger {
				return true
			}
		}
	case map[string]any:
		_, ok := v[trigger]
		return ok
	}
	return false
}

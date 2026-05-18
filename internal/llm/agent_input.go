package llm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// SurfaceInput describes the audit work for one trigger surface.
//
// A trigger surface is the (workflow, trigger) pair the agent reasons about
// in a single Agent.Run session. Suspicions are the deterministic findings
// the rules pass produced for this surface — they're seeded into the prompt
// so the agent can confirm them, expand on them, or rule them out.
type SurfaceInput struct {
	Workflow   *workflow.Workflow
	Trigger    string
	Suspicions []findings.Finding
}

// BuildSurfaceInput renders s into the user message the Agent.Run loop sends
// alongside the system prompt. Format:
//
//   - graph summary (jobs, steps, what each step does)
//   - pre-flagged suspicions list (deterministic findings on this surface)
//   - the explicit task framing
//
// Kept as a plain string so it's trivial to log / diff / vendor in tests.
func BuildSurfaceInput(s SurfaceInput) string {
	if s.Workflow == nil {
		return "(empty surface — no workflow attached)"
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "# Trigger surface: %s on %s\n\n", s.Workflow.Path, s.Trigger)
	if s.Workflow.Name != "" && s.Workflow.Name != s.Workflow.Path {
		fmt.Fprintf(&sb, "Workflow name: %s\n\n", s.Workflow.Name)
	}

	// Permissions block context — the agent often needs this for severity calls.
	if s.Workflow.Permissions != nil {
		fmt.Fprintf(&sb, "Workflow-level permissions: %v\n\n", s.Workflow.Permissions)
	} else {
		sb.WriteString("Workflow-level permissions: (not declared — defaults grant write to GITHUB_TOKEN on push events)\n\n")
	}

	sb.WriteString("## Workflow graph\n\n")
	if len(s.Workflow.Jobs) == 0 {
		sb.WriteString("(no jobs)\n")
	} else {
		// Stable iteration for reproducibility in tests/logs.
		ids := make([]string, 0, len(s.Workflow.Jobs))
		for id := range s.Workflow.Jobs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			job := s.Workflow.Jobs[id]
			if job == nil {
				continue
			}
			fmt.Fprintf(&sb, "### job `%s`\n", id)
			fmt.Fprintf(&sb, "- runs-on: %v\n", job.RunsOn)
			if job.Permissions != nil {
				fmt.Fprintf(&sb, "- permissions: %v\n", job.Permissions)
			}
			if job.If != "" {
				fmt.Fprintf(&sb, "- if: %s\n", job.If)
			}
			for _, st := range job.Steps {
				if st == nil {
					continue
				}
				switch {
				case st.IsUses():
					fmt.Fprintf(&sb, "- step[%d] uses: `%s`", st.Index, st.Uses)
					if st.Name != "" {
						fmt.Fprintf(&sb, "  (%q)", st.Name)
					}
					sb.WriteString("\n")
					if len(st.With) > 0 {
						for k, v := range st.With {
							fmt.Fprintf(&sb, "    with %s: %v\n", k, v)
						}
					}
					if len(st.Env) > 0 {
						for k, v := range st.Env {
							fmt.Fprintf(&sb, "    env %s: %s\n", k, v)
						}
					}
				case st.IsRun():
					fmt.Fprintf(&sb, "- step[%d] run: %s\n", st.Index, oneLine(st.Run, 200))
					if len(st.Env) > 0 {
						for k, v := range st.Env {
							fmt.Fprintf(&sb, "    env %s: %s\n", k, v)
						}
					}
				}
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("## Pre-flagged suspicions from the deterministic pass\n\n")
	if len(s.Suspicions) == 0 {
		sb.WriteString("(none — the rules pass had nothing to say about this surface)\n\n")
	} else {
		for _, f := range s.Suspicions {
			fmt.Fprintf(&sb, "- **[%s] %s** at `%s`\n  evidence: %s\n", f.Severity, f.Kind, f.Location, oneLine(f.Evidence, 240))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Your task\n\n")
	sb.WriteString("Investigate this trigger surface for supply-chain risk. Use the available tools to confirm, extend, or rule out the suspicions above; investigate anything else the graph suggests. Each issue you confirm becomes a `submit_finding` call. When you have nothing more worth investigating, return a turn with no tool calls and the loop will terminate.\n")

	return sb.String()
}

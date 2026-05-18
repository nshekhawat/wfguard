package llm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-github/v66/github"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/resolver"
	"github.com/nshekhawat/wfguard/internal/rules"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// AuditDispatcher backs the seven agent tools with concrete Go functions.
//
// It is constructed once per scan and reused across every trigger surface;
// the only mutable state during an Agent.Run is the Accumulator (via
// submit_finding) and CurrentWorkflow (set by the scan loop before each
// surface so the agent's tool calls can default to the surface in scope).
type AuditDispatcher struct {
	// Workflows keyed by basename (e.g. "ci.yml"). The agent identifies
	// workflows by basename in tool args.
	Workflows map[string]*workflow.Workflow

	// Resolver fetches action source + metadata. Required for
	// get_action_source / resolve_reference.
	Resolver resolver.Resolver

	// GitHub is the API client used for lookup_advisories. Optional; if nil,
	// only the static known-bad list is consulted.
	GitHub *github.Client

	// Acc receives every submit_finding call.
	Acc *findings.Accumulator

	// CurrentWorkflow is the basename the agent is currently auditing. Set
	// by the scan loop. Used to give the agent a sensible default when its
	// tool args don't specify a workflow.
	CurrentWorkflow string
}

// Dispatch implements Dispatcher.
func (d *AuditDispatcher) Dispatch(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case "list_workflows":
		return d.listWorkflows(), nil
	case "get_workflow":
		return d.getWorkflow(args)
	case "get_action_source":
		return d.getActionSource(ctx, args)
	case "resolve_reference":
		return d.resolveReference(ctx, args)
	case "lookup_advisories":
		return d.lookupAdvisories(ctx, args)
	case "trace_expression_flow":
		return d.traceExpressionFlow(args)
	case "submit_finding":
		return d.submitFinding(args)
	}
	return nil, fmt.Errorf("unknown tool: %q", name)
}

// ----- list_workflows -------------------------------------------------------

func (d *AuditDispatcher) listWorkflows() any {
	out := make([]map[string]any, 0, len(d.Workflows))
	names := make([]string, 0, len(d.Workflows))
	for k := range d.Workflows {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		wf := d.Workflows[name]
		out = append(out, map[string]any{
			"name":     name,
			"path":     wf.Path,
			"triggers": triggerNames(wf.On),
		})
	}
	return map[string]any{"workflows": out}
}

// ----- get_workflow ---------------------------------------------------------

func (d *AuditDispatcher) getWorkflow(args map[string]any) (any, error) {
	name, err := String(args, "name")
	if err != nil {
		return nil, err
	}
	wf, ok := d.Workflows[name]
	if !ok {
		// Tolerate paths and basenames; the agent can confuse them.
		for k, v := range d.Workflows {
			if v.Path == name || strings.HasSuffix(v.Path, "/"+name) {
				wf = v
				name = k
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("unknown workflow: %q", name)
	}
	return summarizeWorkflow(wf), nil
}

// ----- get_action_source ----------------------------------------------------

func (d *AuditDispatcher) getActionSource(ctx context.Context, args map[string]any) (any, error) {
	uses, err := String(args, "uses")
	if err != nil {
		return nil, err
	}
	if d.Resolver == nil {
		return nil, fmt.Errorf("resolver not configured; cannot fetch action source")
	}
	a, err := d.Resolver.Resolve(ctx, uses)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"uses":         a.Raw,
		"owner":        a.Owner,
		"repo":         a.Repo,
		"sha":          a.SHA,
		"action_yaml":  truncate(a.ActionYAML, 16_000),
		"entry_script": truncate(a.EntryScript, 32_000),
	}, nil
}

// ----- resolve_reference ----------------------------------------------------

func (d *AuditDispatcher) resolveReference(ctx context.Context, args map[string]any) (any, error) {
	uses, err := String(args, "uses")
	if err != nil {
		return nil, err
	}
	if d.Resolver == nil {
		return nil, fmt.Errorf("resolver not configured")
	}
	a, err := d.Resolver.Resolve(ctx, uses)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"raw":                a.Raw,
		"owner":              a.Owner,
		"repo":               a.Repo,
		"ref":                a.Ref,
		"sha":                a.SHA,
		"pinned_to_sha":      a.PinnedToSHA,
		"latest_release":     a.LatestRelease,
		"publisher_verified": a.PublisherVerified,
	}, nil
}

// ----- lookup_advisories ----------------------------------------------------

func (d *AuditDispatcher) lookupAdvisories(ctx context.Context, args map[string]any) (any, error) {
	a, err := String(args, "action")
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(a, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected 'owner/repo', got %q", a)
	}
	owner, repo := parts[0], parts[1]

	out := map[string]any{
		"action":     a,
		"known_bad":  false,
		"advisories": []any{},
	}

	if note, ok := rules.DefaultKnownBad()[a]; ok {
		out["known_bad"] = true
		out["known_bad_note"] = note
	}

	if d.GitHub == nil {
		return out, nil
	}
	advs, _, err := d.GitHub.SecurityAdvisories.ListRepositorySecurityAdvisories(ctx, owner, repo, nil)
	if err != nil {
		// Non-fatal: surface the error to the model so it can move on.
		out["advisories_error"] = err.Error()
		return out, nil
	}
	list := make([]map[string]any, 0, len(advs))
	for _, x := range advs {
		list = append(list, map[string]any{
			"ghsa_id":  x.GetGHSAID(),
			"summary":  x.GetSummary(),
			"severity": x.GetSeverity(),
			"url":      x.GetHTMLURL(),
			"state":    x.GetState(),
		})
	}
	out["advisories"] = list
	return out, nil
}

// ----- trace_expression_flow ------------------------------------------------

func (d *AuditDispatcher) traceExpressionFlow(args map[string]any) (any, error) {
	wfName, err := String(args, "workflow")
	if err != nil {
		// Tolerate the agent omitting `workflow` when CurrentWorkflow is set.
		if d.CurrentWorkflow == "" {
			return nil, err
		}
		wfName = d.CurrentWorkflow
	}
	expr, err := String(args, "expr")
	if err != nil {
		return nil, err
	}
	wf, ok := d.Workflows[wfName]
	if !ok {
		return nil, fmt.Errorf("unknown workflow: %q", wfName)
	}

	var hits []map[string]any
	add := func(where, ctxStr string) {
		hits = append(hits, map[string]any{"where": where, "context": ctxStr})
	}

	for k, v := range wf.Env {
		if strings.Contains(v, expr) {
			add(fmt.Sprintf("%s:env.%s", wf.Path, k), v)
		}
	}
	for jobID, job := range wf.Jobs {
		if job == nil {
			continue
		}
		for k, v := range job.Env {
			if strings.Contains(v, expr) {
				add(fmt.Sprintf("%s:%s:env.%s", wf.Path, jobID, k), v)
			}
		}
		for _, st := range job.Steps {
			if st == nil {
				continue
			}
			for k, v := range st.Env {
				if strings.Contains(v, expr) {
					add(fmt.Sprintf("%s:%s:step[%d]:env.%s", wf.Path, jobID, st.Index, k), v)
				}
			}
			if strings.Contains(st.Run, expr) {
				add(fmt.Sprintf("%s:%s:step[%d]:run", wf.Path, jobID, st.Index), oneLine(st.Run, 200))
			}
			for k, v := range st.With {
				if vs, ok := v.(string); ok && strings.Contains(vs, expr) {
					add(fmt.Sprintf("%s:%s:step[%d]:with.%s", wf.Path, jobID, st.Index, k), vs)
				}
			}
		}
	}
	return map[string]any{"flow": hits, "count": len(hits)}, nil
}

// ----- submit_finding -------------------------------------------------------

func (d *AuditDispatcher) submitFinding(args map[string]any) (any, error) {
	sev, err := String(args, "severity")
	if err != nil {
		return nil, err
	}
	kind, err := String(args, "kind")
	if err != nil {
		return nil, err
	}
	loc, err := String(args, "location")
	if err != nil {
		return nil, err
	}
	ev, err := String(args, "evidence")
	if err != nil {
		return nil, err
	}
	fix, err := String(args, "fix")
	if err != nil {
		return nil, err
	}

	severity := findings.Severity(strings.ToLower(strings.TrimSpace(sev)))
	if severity.Order() == 0 {
		return nil, fmt.Errorf("invalid severity %q (use low|medium|high|critical)", sev)
	}
	if d.Acc == nil {
		return nil, fmt.Errorf("accumulator not configured")
	}
	added := d.Acc.Add(findings.Finding{
		Severity: severity,
		Kind:     strings.TrimSpace(kind),
		Location: strings.TrimSpace(loc),
		Evidence: strings.TrimSpace(ev),
		Fix:      strings.TrimSpace(fix),
		Source:   "agent",
	})
	if added {
		return map[string]any{"recorded": true}, nil
	}
	return map[string]any{"recorded": false, "reason": "duplicate of an earlier finding"}, nil
}

// ----- helpers --------------------------------------------------------------

// triggerNames extracts the list of trigger names from a parsed `on:` value.
func triggerNames(on any) []string {
	switch v := on.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// summarizeWorkflow reduces a *workflow.Workflow to the JSON-friendly shape
// the agent actually needs. Drops Extra fields and inlines step/job IDs.
func summarizeWorkflow(wf *workflow.Workflow) map[string]any {
	if wf == nil {
		return nil
	}
	jobs := map[string]any{}
	for jobID, job := range wf.Jobs {
		if job == nil {
			continue
		}
		var steps []map[string]any
		for _, st := range job.Steps {
			if st == nil {
				continue
			}
			s := map[string]any{
				"index": st.Index,
				"name":  st.Name,
				"if":    st.If,
			}
			if st.Uses != "" {
				s["uses"] = st.Uses
				if len(st.With) > 0 {
					s["with"] = st.With
				}
			}
			if st.Run != "" {
				s["run"] = oneLine(st.Run, 600)
			}
			if len(st.Env) > 0 {
				s["env"] = st.Env
			}
			steps = append(steps, s)
		}
		jobs[jobID] = map[string]any{
			"runs_on":     job.RunsOn,
			"if":          job.If,
			"permissions": job.Permissions,
			"env":         job.Env,
			"steps":       steps,
		}
	}
	return map[string]any{
		"path":        wf.Path,
		"name":        wf.Name,
		"on":          wf.On,
		"permissions": wf.Permissions,
		"env":         wf.Env,
		"jobs":        jobs,
	}
}

// oneLine collapses newlines in s and truncates to maxLen, returning "..." on
// truncation.
func oneLine(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// truncate returns s, possibly with a tail elided. Preserves newlines (unlike
// oneLine) — useful for source-code blobs the agent will read.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}

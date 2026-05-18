package llm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/llm"
	"github.com/nshekhawat/wfguard/internal/resolver"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// stubResolver is a minimal Resolver for tests that doesn't touch the
// network. Returns a canned Action regardless of input.
type stubResolver struct {
	action *resolver.Action
	err    error
	calls  int
}

func (s *stubResolver) Resolve(_ context.Context, uses string) (*resolver.Action, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	a := *s.action
	a.Raw = uses
	return &a, nil
}

func sampleWorkflow() *workflow.Workflow {
	return &workflow.Workflow{
		Path: ".github/workflows/ci.yml",
		Name: "ci",
		On:   "pull_request_target",
		Jobs: map[string]*workflow.Job{
			"build": {
				ID:     "build",
				RunsOn: "ubuntu-latest",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "actions/checkout@v4"},
					{Index: 1, Run: "echo $TITLE", Env: map[string]string{"TITLE": "${{ github.event.pull_request.title }}"}},
				},
			},
		},
	}
}

func newDispatcher(t *testing.T) (*llm.AuditDispatcher, *findings.Accumulator, *stubResolver) {
	t.Helper()
	wf := sampleWorkflow()
	acc := findings.NewAccumulator()
	res := &stubResolver{action: &resolver.Action{
		Raw:               "actions/checkout@v4",
		Owner:             "actions",
		Repo:              "checkout",
		Ref:               "v4",
		SHA:               "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		LatestRelease:     "v4.1.7",
		PublisherVerified: true,
		ActionYAML:        "name: checkout\nruns:\n  using: node20\n",
	}}
	d := &llm.AuditDispatcher{
		Workflows:       map[string]*workflow.Workflow{"ci.yml": wf},
		Resolver:        res,
		Acc:             acc,
		CurrentWorkflow: "ci.yml",
	}
	return d, acc, res
}

func TestDispatch_ListWorkflows(t *testing.T) {
	d, _, _ := newDispatcher(t)
	got, err := d.Dispatch(context.Background(), "list_workflows", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	wfs := m["workflows"].([]map[string]any)
	if len(wfs) != 1 {
		t.Fatalf("got %d workflows, want 1", len(wfs))
	}
	if wfs[0]["name"] != "ci.yml" {
		t.Errorf("name = %v", wfs[0]["name"])
	}
}

func TestDispatch_GetWorkflow(t *testing.T) {
	d, _, _ := newDispatcher(t)
	got, err := d.Dispatch(context.Background(), "get_workflow", map[string]any{"name": "ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["path"] != ".github/workflows/ci.yml" {
		t.Errorf("path = %v", m["path"])
	}
	if _, ok := m["jobs"]; !ok {
		t.Error("missing jobs in summary")
	}
}

func TestDispatch_GetWorkflow_Unknown(t *testing.T) {
	d, _, _ := newDispatcher(t)
	if _, err := d.Dispatch(context.Background(), "get_workflow", map[string]any{"name": "missing.yml"}); err == nil {
		t.Error("expected error for unknown workflow")
	}
}

func TestDispatch_ResolveReference(t *testing.T) {
	d, _, res := newDispatcher(t)
	got, err := d.Dispatch(context.Background(), "resolve_reference", map[string]any{"uses": "actions/checkout@v4"})
	if err != nil {
		t.Fatal(err)
	}
	if res.calls != 1 {
		t.Errorf("resolver called %d times, want 1", res.calls)
	}
	m := got.(map[string]any)
	if m["sha"] != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" {
		t.Errorf("sha = %v", m["sha"])
	}
	if m["publisher_verified"] != true {
		t.Errorf("publisher_verified = %v", m["publisher_verified"])
	}
}

func TestDispatch_GetActionSource_TruncatesLargeBlobs(t *testing.T) {
	d, _, res := newDispatcher(t)
	huge := make([]byte, 50_000)
	for i := range huge {
		huge[i] = 'x'
	}
	res.action.EntryScript = string(huge)
	got, err := d.Dispatch(context.Background(), "get_action_source", map[string]any{"uses": "actions/checkout@v4"})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	es := m["entry_script"].(string)
	if len(es) > 33_000 {
		t.Errorf("entry_script not truncated: len=%d", len(es))
	}
}

func TestDispatch_TraceExpressionFlow(t *testing.T) {
	d, _, _ := newDispatcher(t)
	got, err := d.Dispatch(context.Background(), "trace_expression_flow", map[string]any{
		"workflow": "ci.yml",
		"expr":     "github.event.pull_request.title",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	count := m["count"].(int)
	if count != 1 {
		t.Errorf("count = %d, want 1 (the env var binding)", count)
	}
}

func TestDispatch_SubmitFinding_RecordsToAccumulator(t *testing.T) {
	d, acc, _ := newDispatcher(t)
	args := map[string]any{
		"severity": "high",
		"kind":     "expression-injection",
		"location": ".github/workflows/ci.yml:build:step[1]",
		"evidence": "env TITLE: ${{ github.event.pull_request.title }}\nrun: echo $TITLE",
		"fix":      "Validate the value before passing it to a shell.",
	}
	got, err := d.Dispatch(context.Background(), "submit_finding", args)
	if err != nil {
		t.Fatal(err)
	}
	if got.(map[string]any)["recorded"] != true {
		t.Errorf("recorded = %v", got)
	}
	if acc.Len() != 1 {
		t.Errorf("acc.Len() = %d, want 1", acc.Len())
	}
	all := acc.All()
	if all[0].Severity != findings.High || all[0].Kind != "expression-injection" {
		t.Errorf("recorded the wrong thing: %+v", all[0])
	}
	if all[0].Source != "agent" {
		t.Errorf("Source = %q, want agent", all[0].Source)
	}
}

func TestDispatch_SubmitFinding_Dedupes(t *testing.T) {
	d, acc, _ := newDispatcher(t)
	args := map[string]any{
		"severity": "low",
		"kind":     "unpinned-action",
		"location": "ci.yml:job:step[0]",
		"evidence": "uses: actions/checkout@v4",
		"fix":      "Pin to SHA.",
	}
	_, _ = d.Dispatch(context.Background(), "submit_finding", args)
	got, err := d.Dispatch(context.Background(), "submit_finding", args)
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["recorded"] != false {
		t.Errorf("expected dedupe to report recorded=false, got %v", m)
	}
	if acc.Len() != 1 {
		t.Errorf("dedupe failed, acc.Len() = %d", acc.Len())
	}
}

func TestDispatch_SubmitFinding_RejectsBadSeverity(t *testing.T) {
	d, _, _ := newDispatcher(t)
	args := map[string]any{
		"severity": "spicy",
		"kind":     "x",
		"location": "y.yml",
		"evidence": "z",
		"fix":      "f",
	}
	if _, err := d.Dispatch(context.Background(), "submit_finding", args); err == nil {
		t.Error("expected error on invalid severity")
	}
}

func TestDispatch_UnknownTool(t *testing.T) {
	d, _, _ := newDispatcher(t)
	if _, err := d.Dispatch(context.Background(), "no_such_tool", nil); err == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestDispatch_ResolveReference_ResolverError(t *testing.T) {
	d, _, res := newDispatcher(t)
	res.err = errors.New("rate limited")
	if _, err := d.Dispatch(context.Background(), "resolve_reference", map[string]any{"uses": "x/y@v1"}); err == nil {
		t.Error("expected propagated resolver error")
	}
}

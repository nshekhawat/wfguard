package llm_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nshekhawat/wfguard/internal/llm"
)

// fakeGenerator returns scripted responses, captures requests, and records
// how many times Generate was called. Set responses (or errors) per call;
// once exhausted Generate returns an error.
type fakeGenerator struct {
	responses []*llm.GenerateResponse
	errors    []error
	requests  []llm.GenerateRequest
	idx       int
}

func (f *fakeGenerator) Generate(_ context.Context, req llm.GenerateRequest) (*llm.GenerateResponse, error) {
	f.requests = append(f.requests, req)
	i := f.idx
	f.idx++
	if i < len(f.errors) && f.errors[i] != nil {
		return nil, f.errors[i]
	}
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return nil, fmt.Errorf("fake generator: no scripted response for call %d", i)
}

// stubDispatcher records dispatch calls. The result and error are uniform
// across calls; tests that need varied behavior should wire their own.
type stubDispatcher struct {
	calls  []stubCall
	output any
	err    error
}

type stubCall struct {
	name string
	args map[string]any
}

func (s *stubDispatcher) Dispatch(_ context.Context, name string, args map[string]any) (any, error) {
	s.calls = append(s.calls, stubCall{name: name, args: args})
	return s.output, s.err
}

// helper to construct a tool-call response.
func tcResp(calls ...llm.ToolCall) *llm.GenerateResponse {
	return &llm.GenerateResponse{ToolCalls: calls}
}
func textResp(s string) *llm.GenerateResponse { return &llm.GenerateResponse{Text: s} }

// ---- tests -----------------------------------------------------------------

func TestAgent_Run_TerminatesWhenNoToolCalls(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{textResp("nothing to add")},
	}
	disp := &stubDispatcher{}
	a := llm.NewAgent(gen, disp, "m1", "system prompt")

	if err := a.Run(context.Background(), "go audit"); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if len(disp.calls) != 0 {
		t.Errorf("dispatcher called %d times, want 0", len(disp.calls))
	}
	if gen.idx != 1 {
		t.Errorf("generator called %d times, want 1", gen.idx)
	}
}

func TestAgent_Run_MultipleStepsToolThenTerminate(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{
			tcResp(llm.ToolCall{ID: "1", Name: "list_workflows", Args: map[string]any{}}),
			tcResp(llm.ToolCall{ID: "2", Name: "get_workflow", Args: map[string]any{"name": "ci.yml"}}),
			textResp("done"),
		},
	}
	disp := &stubDispatcher{output: map[string]any{"ok": true}}
	a := llm.NewAgent(gen, disp, "m1", "system")

	if err := a.Run(context.Background(), "audit"); err != nil {
		t.Fatal(err)
	}
	if got, want := len(disp.calls), 2; got != want {
		t.Errorf("dispatcher calls = %d, want %d", got, want)
	}
	if disp.calls[0].name != "list_workflows" {
		t.Errorf("first dispatch = %q", disp.calls[0].name)
	}
	if disp.calls[1].name != "get_workflow" || disp.calls[1].args["name"] != "ci.yml" {
		t.Errorf("second dispatch = %+v", disp.calls[1])
	}
}

func TestAgent_Run_HistoryGrowsWithEachStep(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{
			tcResp(llm.ToolCall{ID: "1", Name: "list_workflows"}),
			textResp("done"),
		},
	}
	disp := &stubDispatcher{output: map[string]any{"workflows": []string{"ci.yml"}}}
	a := llm.NewAgent(gen, disp, "m1", "sys")

	if err := a.Run(context.Background(), "audit"); err != nil {
		t.Fatal(err)
	}
	// Two requests: first carries [user]; second carries [user, assistant(toolcall), tool(result)].
	if len(gen.requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(gen.requests))
	}
	r1 := gen.requests[1]
	if got := len(r1.History); got != 3 {
		t.Errorf("second-request history = %d turns, want 3", got)
	}
	if r1.History[0].Role != llm.RoleUser {
		t.Errorf("history[0].Role = %q, want user", r1.History[0].Role)
	}
	if r1.History[1].Role != llm.RoleAssistant || len(r1.History[1].ToolCalls) != 1 {
		t.Errorf("history[1] = %+v", r1.History[1])
	}
	if r1.History[2].Role != llm.RoleTool || len(r1.History[2].ToolResults) != 1 {
		t.Errorf("history[2] = %+v", r1.History[2])
	}
}

func TestAgent_Run_PassesSystemAndTools(t *testing.T) {
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{textResp("done")}}
	a := llm.NewAgent(gen, &stubDispatcher{}, "m1", "you are an auditor")
	_ = a.Run(context.Background(), "audit")

	if got := gen.requests[0].System; got != "you are an auditor" {
		t.Errorf("System = %q", got)
	}
	if got := len(gen.requests[0].Tools); got != 7 {
		t.Errorf("Tools = %d, want 7 (per ToolDecls)", got)
	}
	if gen.requests[0].Model != "m1" {
		t.Errorf("Model = %q", gen.requests[0].Model)
	}
}

func TestAgent_Run_MaxStepsExceeded(t *testing.T) {
	// Always return a tool call → loop never terminates on its own.
	infinite := tcResp(llm.ToolCall{ID: "x", Name: "list_workflows"})
	gen := &fakeGenerator{}
	for i := 0; i < 100; i++ {
		gen.responses = append(gen.responses, infinite)
	}
	disp := &stubDispatcher{output: map[string]any{}}
	a := llm.NewAgent(gen, disp, "m1", "sys")
	a.MaxSteps = 3

	err := a.Run(context.Background(), "audit")
	if err == nil {
		t.Fatal("expected MaxSteps error")
	}
	if got := gen.idx; got != 3 {
		t.Errorf("generator called %d times, want exactly MaxSteps=3", got)
	}
}

func TestAgent_Run_PropagatesGeneratorError(t *testing.T) {
	want := errors.New("network blew up")
	gen := &fakeGenerator{errors: []error{want}}
	a := llm.NewAgent(gen, &stubDispatcher{}, "m1", "sys")

	err := a.Run(context.Background(), "audit")
	if err == nil || !errors.Is(err, want) {
		t.Errorf("Run() = %v, want wrapping %v", err, want)
	}
}

func TestAgent_Run_DispatchErrorBecomesToolResult(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{
			tcResp(llm.ToolCall{ID: "1", Name: "broken_tool"}),
			textResp("ok then"),
		},
	}
	disp := &stubDispatcher{err: errors.New("kaboom")}
	a := llm.NewAgent(gen, disp, "m1", "sys")

	if err := a.Run(context.Background(), "audit"); err != nil {
		t.Fatal(err)
	}
	// Inspect the tool turn fed back to the generator.
	if len(gen.requests) < 2 {
		t.Fatal("expected at least 2 generator calls")
	}
	toolTurn := gen.requests[1].History[len(gen.requests[1].History)-1]
	if toolTurn.Role != llm.RoleTool || len(toolTurn.ToolResults) != 1 {
		t.Fatalf("expected tool turn with one result, got %+v", toolTurn)
	}
	out, _ := toolTurn.ToolResults[0].Output.(map[string]any)
	if out["error"] != "kaboom" {
		t.Errorf("dispatch error not propagated to tool result: %v", out)
	}
}

func TestAgent_Run_PropagatesContextCancel(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{tcResp(llm.ToolCall{Name: "list_workflows"})},
	}
	disp := &stubDispatcher{output: map[string]any{}}
	a := llm.NewAgent(gen, disp, "m1", "sys")
	a.MaxSteps = 5

	// Build a context that's already cancelled — first Generate succeeds via
	// fake (it doesn't check ctx), but on the next iteration the loop again
	// calls Generate which ignores the cancelled context — so this test
	// instead asserts that a generator returning ctx.Err propagates.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gen.errors = []error{ctx.Err()}
	gen.responses = nil

	err := a.Run(ctx, "audit")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run() = %v, want wrapping context.Canceled", err)
	}
}

func TestAgent_Run_MultipleToolCallsInOneTurn(t *testing.T) {
	gen := &fakeGenerator{
		responses: []*llm.GenerateResponse{
			tcResp(
				llm.ToolCall{ID: "a", Name: "list_workflows"},
				llm.ToolCall{ID: "b", Name: "get_workflow", Args: map[string]any{"name": "ci.yml"}},
			),
			textResp("done"),
		},
	}
	disp := &stubDispatcher{output: map[string]any{"ok": true}}
	a := llm.NewAgent(gen, disp, "m1", "sys")

	if err := a.Run(context.Background(), "audit"); err != nil {
		t.Fatal(err)
	}
	if len(disp.calls) != 2 {
		t.Errorf("dispatcher calls = %d, want 2 (parallel calls in one turn)", len(disp.calls))
	}
	// Second request's last history entry should hold both tool results.
	results := gen.requests[1].History[len(gen.requests[1].History)-1].ToolResults
	if len(results) != 2 {
		t.Errorf("tool results in single tool turn = %d, want 2", len(results))
	}
	if results[0].CallID != "a" || results[1].CallID != "b" {
		t.Errorf("call IDs not preserved in result turn: %+v", results)
	}
}

func TestAgent_NewAgent_DefaultModel(t *testing.T) {
	a := llm.NewAgent(&fakeGenerator{}, &stubDispatcher{}, "", "sys")
	if a.ModelID != llm.DefaultModel {
		t.Errorf("default ModelID = %q, want %q", a.ModelID, llm.DefaultModel)
	}
}

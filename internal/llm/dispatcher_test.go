package llm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nshekhawat/wfguard/internal/llm"
)

func TestRegistry_DispatchRoutesToHandler(t *testing.T) {
	r := llm.NewRegistry()
	called := false
	r.Register("ping", func(_ context.Context, _ map[string]any) (any, error) {
		called = true
		return map[string]any{"ok": true}, nil
	})

	got, err := r.Dispatch(context.Background(), "ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("handler not invoked")
	}
	if m := got.(map[string]any); m["ok"] != true {
		t.Errorf("wrong result: %v", got)
	}
}

func TestRegistry_DispatchUnknownToolErrors(t *testing.T) {
	r := llm.NewRegistry()
	_, err := r.Dispatch(context.Background(), "nope", nil)
	if err == nil {
		t.Fatal("expected error on unknown tool")
	}
	if !errors.Is(err, llm.ErrUnknownTool) {
		t.Errorf("err = %v, want wrapping ErrUnknownTool", err)
	}
	if !llm.IsModelToolError(err) {
		t.Error("unknown-tool should classify as a model-side error")
	}
}

func TestRegistry_RegisterOverwrites(t *testing.T) {
	r := llm.NewRegistry()
	r.Register("k", func(_ context.Context, _ map[string]any) (any, error) {
		return "first", nil
	})
	r.Register("k", func(_ context.Context, _ map[string]any) (any, error) {
		return "second", nil
	})
	got, _ := r.Dispatch(context.Background(), "k", nil)
	if got != "second" {
		t.Errorf("Register should overwrite, got %v", got)
	}
}

func TestRegistry_HandlerErrorPropagates(t *testing.T) {
	r := llm.NewRegistry()
	want := errors.New("boom")
	r.Register("k", func(_ context.Context, _ map[string]any) (any, error) {
		return nil, want
	})
	if _, err := r.Dispatch(context.Background(), "k", nil); !errors.Is(err, want) {
		t.Errorf("err = %v, want wrapping %v", err, want)
	}
}

func TestString_RequiredArg(t *testing.T) {
	args := map[string]any{"x": "value"}
	got, err := llm.String(args, "x")
	if err != nil || got != "value" {
		t.Errorf("String OK case: got=%q err=%v", got, err)
	}

	_, err = llm.String(args, "missing")
	if err == nil {
		t.Fatal("missing required arg should error")
	}
	if !errors.Is(err, llm.ErrMissingArg) {
		t.Errorf("err = %v, want wrapping ErrMissingArg", err)
	}

	_, err = llm.String(map[string]any{"x": 7}, "x")
	if err == nil {
		t.Fatal("non-string value should error")
	}
	if !errors.Is(err, llm.ErrBadArg) {
		t.Errorf("err = %v, want wrapping ErrBadArg", err)
	}
}

func TestIsModelToolError(t *testing.T) {
	if !llm.IsModelToolError(llm.ErrMissingArg) {
		t.Error("ErrMissingArg should be model error")
	}
	if !llm.IsModelToolError(llm.ErrBadArg) {
		t.Error("ErrBadArg should be model error")
	}
	if !llm.IsModelToolError(llm.ErrUnknownTool) {
		t.Error("ErrUnknownTool should be model error")
	}
	// Wrapped form still classifies correctly.
	wrapped := errors.New("github 403: rate limit")
	if llm.IsModelToolError(wrapped) {
		t.Error("runtime errors must not classify as model errors")
	}
	if llm.IsModelToolError(nil) {
		t.Error("nil must not classify as a model error")
	}
}

func TestOptString(t *testing.T) {
	if got := llm.OptString(map[string]any{"x": "v"}, "x"); got != "v" {
		t.Errorf("OptString hit = %q", got)
	}
	if got := llm.OptString(map[string]any{}, "x"); got != "" {
		t.Errorf("OptString miss = %q, want empty", got)
	}
	if got := llm.OptString(map[string]any{"x": 7}, "x"); got != "" {
		t.Errorf("OptString wrong type = %q, want empty", got)
	}
}

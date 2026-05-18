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
	if _, err := r.Dispatch(context.Background(), "nope", nil); err == nil {
		t.Error("expected error on unknown tool")
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
	if _, err := llm.String(args, "missing"); err == nil {
		t.Error("missing required arg should error")
	}
	if _, err := llm.String(map[string]any{"x": 7}, "x"); err == nil {
		t.Error("non-string value should error")
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

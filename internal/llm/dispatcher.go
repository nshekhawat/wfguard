package llm

import (
	"context"
	"fmt"
)

// Dispatcher is the bridge between tool-call names emitted by Gemma 4 and
// the Go functions that actually do the work. The Agent calls Dispatch
// for each tool the model invokes; the dispatcher returns a result that is
// JSON-marshalled and fed back into the model's context.
//
// Implementations must be safe for sequential use within one Agent.Run.
type Dispatcher interface {
	Dispatch(ctx context.Context, name string, args map[string]any) (any, error)
}

// Handler is a single tool implementation.
type Handler func(ctx context.Context, args map[string]any) (any, error)

// Registry is a map-based Dispatcher. Wire one up at scan startup with the
// concrete Go implementations of each tool.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry returns an empty Registry. Use Register to add handlers.
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Register binds a tool name to a handler. Overwrites any existing binding.
func (r *Registry) Register(name string, h Handler) {
	r.handlers[name] = h
}

// Dispatch satisfies the Dispatcher interface.
func (r *Registry) Dispatch(ctx context.Context, name string, args map[string]any) (any, error) {
	h, ok := r.handlers[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %q", name)
	}
	return h(ctx, args)
}

// ---- helpers for handlers --------------------------------------------------

// String pulls a required string arg from the model's args map.
func String(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required arg %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("arg %q: expected string, got %T", key, v)
	}
	return s, nil
}

// OptString returns an optional string arg, or "" if absent.
func OptString(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

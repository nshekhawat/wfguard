package llm

import (
	"context"
	"errors"
	"fmt"
)

// Tool-call error sentinels. These distinguish "the model emitted a
// malformed tool call" (ErrMissingArg, ErrBadArg, ErrUnknownTool) from
// "the tool ran and failed for an external reason" (any other error). The
// agent loop classifies on these via errors.Is to label the WARN log.
var (
	ErrMissingArg  = errors.New("missing required arg")
	ErrBadArg      = errors.New("bad arg")
	ErrUnknownTool = errors.New("unknown tool")
)

// IsModelToolError reports whether err is a model-side tool-call mistake
// (bad/missing argument, unknown tool name) rather than a runtime failure
// inside the tool implementation. Used by the agent loop for log
// categorisation; callers shouldn't branch on it for control flow.
func IsModelToolError(err error) bool {
	return errors.Is(err, ErrMissingArg) ||
		errors.Is(err, ErrBadArg) ||
		errors.Is(err, ErrUnknownTool)
}

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
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}
	return h(ctx, args)
}

// ---- helpers for handlers --------------------------------------------------

// String pulls a required string arg from the model's args map. Returns an
// error wrapping ErrMissingArg / ErrBadArg when the arg is absent or the
// wrong type, so the agent loop can classify the failure as a model mistake.
func String(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrMissingArg, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q expected string, got %T", ErrBadArg, key, v)
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

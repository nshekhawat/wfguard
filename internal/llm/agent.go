package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Agent runs one audit session against a Generator (Gemini or OpenAI) for a
// given trigger surface. It is plan-and-execute: the model proposes tool
// calls, the dispatcher executes them, results are appended to history, and
// the loop continues until the model emits a turn with no tool calls or
// MaxSteps is reached.
//
// All output is recorded via the submit_finding tool side-effect in the
// dispatcher; whatever else the model says is discarded by design.
type Agent struct {
	Generator  Generator
	Dispatcher Dispatcher
	ModelID    string
	System     string
	MaxSteps   int

	// Temperature controls sampling. 0.2 is a reasonable default for
	// auditing — low enough for stable findings, high enough to allow some
	// exploration of suspicious patterns.
	Temperature float32

	logger *slog.Logger
}

// NewAgent constructs an Agent with sane defaults.
func NewAgent(gen Generator, dispatcher Dispatcher, modelID, system string) *Agent {
	if modelID == "" {
		modelID = DefaultModel
	}
	return &Agent{
		Generator:   gen,
		Dispatcher:  dispatcher,
		ModelID:     modelID,
		MaxSteps:    15,
		System:      system,
		Temperature: 0.2,
		logger:      slog.Default(),
	}
}

// Run executes one audit session. The userMsg should contain the
// pre-built graph summary for the trigger surface plus any deterministic
// suspicions to investigate.
//
// Findings are accumulated through the dispatcher's submit_finding side
// effect; this method returns nil on a clean termination, or an error if
// the API call fails or MaxSteps is hit.
func (a *Agent) Run(ctx context.Context, userMsg string) error {
	logger := a.logger
	if logger == nil {
		logger = slog.Default()
	}

	history := []Turn{{Role: RoleUser, Text: userMsg}}
	tools := ToolDecls()

	// Per-surface counters for the end-of-run summary. Model errors mean
	// the LLM emitted a malformed tool call (bad/missing arg, unknown tool);
	// runtime errors mean the tool ran and failed (resolver, GitHub API, etc.).
	var modelErrs, runtimeErrs int

	for step := 0; step < a.MaxSteps; step++ {
		req := GenerateRequest{
			System:      a.System,
			History:     history,
			Tools:       tools,
			Temperature: a.Temperature,
			Model:       a.ModelID,
		}
		resp, err := a.Generator.Generate(ctx, req)
		if err != nil {
			return fmt.Errorf("step %d: generate: %w", step, err)
		}

		// Append the assistant turn to history (text + tool calls, if any).
		assistant := Turn{
			Role:      RoleAssistant,
			Text:      resp.Text,
			ToolCalls: resp.ToolCalls,
		}
		history = append(history, assistant)

		if len(resp.ToolCalls) == 0 {
			logger.Debug("agent terminated cleanly", "steps", step,
				"model_errors", modelErrs, "runtime_errors", runtimeErrs)
			if modelErrs > 0 || runtimeErrs > 0 {
				logger.Info("agent surface complete",
					"steps", step,
					"model_errors", modelErrs,
					"runtime_errors", runtimeErrs,
					"terminated", "clean")
			}
			return nil
		}

		// Dispatch every tool call this turn produced; collect results in
		// one tool-role turn that goes back into history.
		results := make([]ToolResult, 0, len(resp.ToolCalls))
		for _, fc := range resp.ToolCalls {
			logger.Debug("tool call", "name", fc.Name, "args", fc.Args)
			out, err := a.Dispatcher.Dispatch(ctx, fc.Name, fc.Args)
			if err != nil {
				category := classifyToolErr(err)
				if category == "model" {
					modelErrs++
				} else {
					runtimeErrs++
				}
				logger.Warn("tool call rejected",
					"name", fc.Name,
					"category", category,
					"err", err)
				out = map[string]any{"error": err.Error()}
			}
			results = append(results, ToolResult{
				CallID: fc.ID,
				Name:   fc.Name,
				Output: out,
			})
		}
		history = append(history, Turn{Role: RoleTool, ToolResults: results})
	}

	logger.Info("agent surface complete",
		"steps", a.MaxSteps,
		"model_errors", modelErrs,
		"runtime_errors", runtimeErrs,
		"terminated", "max_steps")
	return fmt.Errorf("max steps (%d) reached without termination", a.MaxSteps)
}

// classifyToolErr labels a dispatcher error as "model" (the LLM emitted a
// malformed tool call — bad/missing arg, unknown tool, unrecognised value)
// or "runtime" (the tool ran and the underlying op failed: resolver fetch,
// GitHub 403, advisory lookup, etc.). Used purely for log categorisation.
func classifyToolErr(err error) string {
	switch {
	case errors.Is(err, ErrMissingArg),
		errors.Is(err, ErrBadArg),
		errors.Is(err, ErrUnknownTool):
		return "model"
	default:
		return "runtime"
	}
}

// Package llm contains the agent loop, the backend-neutral Generator
// interface, and concrete generators for Gemini and OpenAI-compatible
// servers (LM Studio, vLLM, llama.cpp's openai server).
package llm

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/genai"
)

// DefaultModel is the canonical Gemini model id used by wfguard. Override
// at runtime with WFGUARD_MODEL or --model.
const DefaultModel = "gemma-4-31b-it"

// NewClient creates a Gemini-API-backed genai client. Used by the smoke
// command to verify connectivity directly; the agent loop goes through
// NewGenerator instead.
//
// API key resolution: explicit arg wins, else GEMINI_API_KEY env var.
func NewClient(ctx context.Context, apiKey string) (*genai.Client, error) {
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("no API key: set GEMINI_API_KEY or pass apiKey arg")
	}
	return genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
}

// NewGenerator builds a Generator from spec. Returns an error if required
// configuration is missing for the chosen backend.
func NewGenerator(ctx context.Context, spec GeneratorSpec) (Generator, error) {
	switch spec.Backend {
	case BackendOpenAI:
		baseURL := spec.OpenAIBaseURL
		if baseURL == "" {
			baseURL = DefaultOpenAIBaseURL
		}
		return NewOpenAIGenerator(baseURL, spec.OpenAIAPIKey), nil
	case BackendGemini, "":
		return NewGeminiGenerator(ctx, spec.GeminiAPIKey)
	default:
		return nil, fmt.Errorf("unknown backend: %q (want %q or %q)",
			spec.Backend, BackendGemini, BackendOpenAI)
	}
}

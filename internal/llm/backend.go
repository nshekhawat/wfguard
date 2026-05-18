package llm

import "context"

// Backend identifies which provider an Agent talks to.
type Backend string

const (
	BackendGemini Backend = "gemini" // Google Gemini API (gemma-4-* models)
	BackendOpenAI Backend = "openai" // OpenAI Chat Completions API or any compatible
	// surface (LM Studio, vLLM, llama.cpp's openai server, etc.)
)

// ChatRole is the speaker of one Turn.
type ChatRole string

const (
	RoleUser      ChatRole = "user"
	RoleAssistant ChatRole = "assistant"
	RoleTool      ChatRole = "tool"
)

// Turn is one entry in the chat history. Exactly one of Text, ToolCalls, or
// ToolResults will be populated for any given turn:
//
//   - {Role: RoleUser,      Text: "..."}
//     plain user message.
//   - {Role: RoleAssistant, Text: "..."}
//     model text-only reply.
//   - {Role: RoleAssistant, ToolCalls: [...]}
//     model is invoking one or more tools (Text may also be set).
//   - {Role: RoleTool,      ToolResults: [...]}
//     dispatcher's response to the previous assistant turn's tool calls.
//
// The neutral shape lets us translate to/from each backend's native format.
type Turn struct {
	Role        ChatRole
	Text        string
	ToolCalls   []ToolCall
	ToolResults []ToolResult
}

// ToolCall is the model's request to invoke a function. ID is the
// backend-issued identifier; preserve it verbatim so that the tool result
// can be correlated (OpenAI requires this; Gemini ignores it).
type ToolCall struct {
	ID   string
	Name string
	Args map[string]any
}

// ToolResult is the dispatcher's reply to one ToolCall.
type ToolResult struct {
	CallID string
	Name   string
	Output any // arbitrary; backends marshal to JSON
}

// ToolDecl declares one tool the model may call. Parameters uses
// JSONSchema-shaped data (e.g. {"type":"object","properties":{...},"required":[...]}).
// Each backend translates this to its own schema format.
type ToolDecl struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// GenerateRequest is one round-trip to a Generator. History should NOT
// include the system instruction; pass that via System.
type GenerateRequest struct {
	System      string
	History     []Turn
	Tools       []ToolDecl
	Temperature float32
	Model       string // backend-specific id, e.g. "gemma-4-31b-it" or whatever LM Studio exposes
}

// GenerateResponse is the model's reply for one round. Empty ToolCalls means
// "I am done" and the agent loop should terminate.
type GenerateResponse struct {
	Text      string
	ToolCalls []ToolCall
}

// Generator is the backend-neutral interface for chat-with-tools generation.
// Implementations: GeminiGenerator (gemini.go), OpenAIGenerator (openai.go).
//
// Implementations are responsible for any backend-specific retry policy.
// The Agent loop treats every error as fatal for the current surface.
type Generator interface {
	Generate(ctx context.Context, req GenerateRequest) (*GenerateResponse, error)
}

// GeneratorSpec describes which backend to construct. Filled in from CLI
// flags / env in the scan command and handed to NewGenerator.
type GeneratorSpec struct {
	Backend Backend

	// Gemini: read from GEMINI_API_KEY env if empty.
	GeminiAPIKey string

	// OpenAI / OpenAI-compatible:
	OpenAIBaseURL string // e.g. "http://localhost:1234/v1"
	OpenAIAPIKey  string // optional; LM Studio doesn't require one
}

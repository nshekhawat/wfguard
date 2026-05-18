package llm

import (
	"testing"

	"google.golang.org/genai"
)

// Translation tests don't need a real *genai.Client — these helpers are
// pure functions on the request/response data structures.

func TestTurnsToGeminiContents_RolesAndParts(t *testing.T) {
	history := []Turn{
		{Role: RoleUser, Text: "go audit"},
		{Role: RoleAssistant, Text: "thinking", ToolCalls: []ToolCall{
			{ID: "x", Name: "list_workflows", Args: map[string]any{}},
		}},
		{Role: RoleTool, ToolResults: []ToolResult{
			{CallID: "x", Name: "list_workflows", Output: map[string]any{"workflows": []string{"ci.yml"}}},
		}},
	}
	got, err := turnsToGeminiContents(history)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d contents, want 3", len(got))
	}

	if got[0].Role != "user" || got[0].Parts[0].Text != "go audit" {
		t.Errorf("user turn: %+v", got[0])
	}
	if got[1].Role != "model" {
		t.Errorf("assistant turn role = %q, want 'model'", got[1].Role)
	}
	// Assistant has both text and a function call.
	hasText, hasCall := false, false
	for _, p := range got[1].Parts {
		if p.Text == "thinking" {
			hasText = true
		}
		if p.FunctionCall != nil && p.FunctionCall.Name == "list_workflows" {
			hasCall = true
		}
	}
	if !hasText || !hasCall {
		t.Errorf("assistant parts missing text or function call: %+v", got[1])
	}
	// Tool result lives in a "user"-role turn per Gemini's protocol.
	if got[2].Role != "user" || got[2].Parts[0].FunctionResponse == nil {
		t.Errorf("tool turn: %+v", got[2])
	}
	if got[2].Parts[0].FunctionResponse.Name != "list_workflows" {
		t.Errorf("function response name = %q", got[2].Parts[0].FunctionResponse.Name)
	}
}

func TestTurnsToGeminiContents_EmptyAssistantStillEmitsAPart(t *testing.T) {
	got, err := turnsToGeminiContents([]Turn{{Role: RoleAssistant}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0].Parts) == 0 {
		t.Error("assistant turn must have at least one Part to satisfy genai")
	}
}

func TestTurnsToGeminiContents_UnknownRoleIsError(t *testing.T) {
	if _, err := turnsToGeminiContents([]Turn{{Role: "weird"}}); err == nil {
		t.Error("unknown role should error")
	}
}

func TestGeminiResponseToNeutral_TextAndToolCalls(t *testing.T) {
	resp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{{
			Content: &genai.Content{
				Parts: []*genai.Part{
					{Text: "hi "},
					{Text: "there"},
					{FunctionCall: &genai.FunctionCall{Name: "list_workflows", Args: map[string]any{}}},
					{FunctionCall: &genai.FunctionCall{Name: "get_workflow", Args: map[string]any{"name": "ci.yml"}}},
				},
			},
		}},
	}
	out := geminiResponseToNeutral(resp)
	if out.Text != "hi there" {
		t.Errorf("Text concat = %q", out.Text)
	}
	if len(out.ToolCalls) != 2 {
		t.Fatalf("ToolCalls = %d", len(out.ToolCalls))
	}
	if out.ToolCalls[0].Name != "list_workflows" || out.ToolCalls[1].Name != "get_workflow" {
		t.Errorf("tool call order: %+v", out.ToolCalls)
	}
	if out.ToolCalls[1].Args["name"] != "ci.yml" {
		t.Errorf("tool call args dropped: %v", out.ToolCalls[1].Args)
	}
}

func TestGeminiResponseToNeutral_NilSafe(t *testing.T) {
	if out := geminiResponseToNeutral(nil); out == nil || out.Text != "" || len(out.ToolCalls) != 0 {
		t.Errorf("nil resp should produce zero-value response, got %+v", out)
	}
	empty := &genai.GenerateContentResponse{}
	if out := geminiResponseToNeutral(empty); len(out.ToolCalls) != 0 {
		t.Errorf("empty candidates should produce no tool calls")
	}
}

func TestJSONSchemaToGemini_AllSubsetTypes(t *testing.T) {
	cases := []struct {
		typ  string
		want genai.Type
	}{
		{"object", genai.TypeObject},
		{"string", genai.TypeString},
		{"integer", genai.TypeInteger},
		{"number", genai.TypeNumber},
		{"boolean", genai.TypeBoolean},
		{"array", genai.TypeArray},
	}
	for _, tc := range cases {
		s := jsonSchemaToGemini(map[string]any{"type": tc.typ})
		if s.Type != tc.want {
			t.Errorf("type %q -> %v, want %v", tc.typ, s.Type, tc.want)
		}
	}
}

func TestJSONSchemaToGemini_NilSafe(t *testing.T) {
	if got := jsonSchemaToGemini(nil); got != nil {
		t.Errorf("nil -> %+v, want nil", got)
	}
}

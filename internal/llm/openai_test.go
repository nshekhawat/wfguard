package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readChatRequest decodes a chat completions POST body for assertions.
func readChatRequest(t *testing.T, r *http.Request) openaiChatRequest {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	var req openaiChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request body: %v\nbody: %s", err, body)
	}
	return req
}

func TestOpenAIGenerator_HappyPath_TextOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = readChatRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{
				"index": 0,
				"message": {"role": "assistant", "content": "wfguard smoke OK"},
				"finish_reason": "stop"
			}]
		}`))
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	resp, err := g.Generate(context.Background(), GenerateRequest{
		Model:   "local-model",
		History: []Turn{{Role: RoleUser, Text: "Reply with exactly: 'wfguard smoke OK'"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "wfguard smoke OK" {
		t.Errorf("Text = %q", resp.Text)
	}
	if len(resp.ToolCalls) != 0 {
		t.Errorf("expected no tool calls, got %d", len(resp.ToolCalls))
	}
}

func TestOpenAIGenerator_ToolCallsParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = readChatRequest(t, r)
		_, _ = w.Write([]byte(`{
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": null,
					"tool_calls": [
						{
							"id": "call_abc",
							"type": "function",
							"function": {"name": "list_workflows", "arguments": "{}"}
						},
						{
							"id": "call_def",
							"type": "function",
							"function": {"name": "get_workflow", "arguments": "{\"name\":\"ci.yml\"}"}
						}
					]
				},
				"finish_reason": "tool_calls"
			}]
		}`))
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	resp, err := g.Generate(context.Background(), GenerateRequest{
		Model:   "local",
		History: []Turn{{Role: RoleUser, Text: "go"}},
		Tools:   ToolDecls(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.ToolCalls) != 2 {
		t.Fatalf("ToolCalls = %d, want 2", len(resp.ToolCalls))
	}
	if resp.ToolCalls[0].ID != "call_abc" || resp.ToolCalls[0].Name != "list_workflows" {
		t.Errorf("first call = %+v", resp.ToolCalls[0])
	}
	if resp.ToolCalls[1].Args["name"] != "ci.yml" {
		t.Errorf("second call args = %v", resp.ToolCalls[1].Args)
	}
}

func TestOpenAIGenerator_RequestShape(t *testing.T) {
	var captured openaiChatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = readChatRequest(t, r)
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "secret-key")
	_, err := g.Generate(context.Background(), GenerateRequest{
		Model:       "m1",
		System:      "you are an auditor",
		Temperature: 0.3,
		History: []Turn{
			{Role: RoleUser, Text: "hi"},
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "x", Name: "list_workflows", Args: map[string]any{}}}},
			{Role: RoleTool, ToolResults: []ToolResult{{CallID: "x", Name: "list_workflows", Output: map[string]any{"workflows": []string{"ci.yml"}}}}},
		},
		Tools: ToolDecls(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if captured.Model != "m1" {
		t.Errorf("model = %q", captured.Model)
	}
	if captured.Temperature == nil || *captured.Temperature != 0.3 {
		t.Errorf("temperature = %v", captured.Temperature)
	}
	if len(captured.Tools) != 7 {
		t.Errorf("tools = %d, want 7", len(captured.Tools))
	}
	if captured.ToolChoice != "auto" {
		t.Errorf("tool_choice = %q", captured.ToolChoice)
	}

	// Messages: system, user, assistant(tool_calls), tool
	if len(captured.Messages) != 4 {
		t.Fatalf("messages = %d, want 4", len(captured.Messages))
	}
	if captured.Messages[0].Role != "system" {
		t.Errorf("first msg role = %q", captured.Messages[0].Role)
	}
	if captured.Messages[2].Role != "assistant" || len(captured.Messages[2].ToolCalls) != 1 {
		t.Errorf("assistant msg = %+v", captured.Messages[2])
	}
	if captured.Messages[3].Role != "tool" || captured.Messages[3].ToolCallID != "x" {
		t.Errorf("tool msg = %+v", captured.Messages[3])
	}
	// Tool result content is JSON-encoded.
	if !strings.Contains(captured.Messages[3].Content, `"workflows"`) {
		t.Errorf("tool content missing JSON-encoded result: %q", captured.Messages[3].Content)
	}
}

func TestOpenAIGenerator_AuthHeaderSentOnlyWhenKeyPresent(t *testing.T) {
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	// No key
	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	_, _ = g.Generate(context.Background(), GenerateRequest{Model: "m", History: []Turn{{Role: RoleUser, Text: "hi"}}})
	if sawAuth.Load() {
		t.Error("Authorization header sent despite empty API key")
	}

	// With key
	g = NewOpenAIGenerator(srv.URL+"/v1", "k")
	_, _ = g.Generate(context.Background(), GenerateRequest{Model: "m", History: []Turn{{Role: RoleUser, Text: "hi"}}})
	if !sawAuth.Load() {
		t.Error("Authorization header missing despite non-empty API key")
	}
}

func TestOpenAIGenerator_RetryOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":{"message":"rate limit"}}`, http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	g.sleep = func(time.Duration) {} // skip the wall-clock wait in tests

	resp, err := g.Generate(context.Background(), GenerateRequest{
		Model: "m", History: []Turn{{Role: RoleUser, Text: "hi"}},
	})
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("Text = %q", resp.Text)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one 429 + one success)", calls.Load())
	}
}

func TestOpenAIGenerator_NonRetryableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"bad request"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	_, err := g.Generate(context.Background(), GenerateRequest{
		Model: "m", History: []Turn{{Role: RoleUser, Text: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention HTTP 400: %v", err)
	}
}

func TestOpenAIGenerator_RetryAfterCappedExceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "999999")
		http.Error(w, "{}", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	g := NewOpenAIGenerator(srv.URL+"/v1", "")
	g.MaxRetryDelay = 5 * time.Second
	g.sleep = func(time.Duration) {}

	_, err := g.Generate(context.Background(), GenerateRequest{
		Model: "m", History: []Turn{{Role: RoleUser, Text: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error when Retry-After exceeds cap")
	}
	if !strings.Contains(err.Error(), "exceeds cap") {
		t.Errorf("error should mention cap: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantPos bool // expected to be > 0
	}{
		{"", 0, false},
		{"30", 30 * time.Second, true},
		{"  3 ", 3 * time.Second, true},
		{"-1", 0, false},
		{"junk", 0, false},
	}
	for _, tc := range cases {
		got := parseRetryAfter(tc.in)
		if (got > 0) != tc.wantPos {
			t.Errorf("parseRetryAfter(%q) = %v, wantPos=%v", tc.in, got, tc.wantPos)
		}
		if tc.wantPos && got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestOpenAIGenerator_DefaultsBaseURL(t *testing.T) {
	g := NewOpenAIGenerator("", "")
	if g.BaseURL != strings.TrimRight(DefaultOpenAIBaseURL, "/") {
		t.Errorf("BaseURL = %q, want %q", g.BaseURL, DefaultOpenAIBaseURL)
	}
}

func TestToolCallID_FillsMissingFromName(t *testing.T) {
	if got := toolCallID(ToolCall{Name: "x"}); got != "call_x" {
		t.Errorf("toolCallID without ID = %q, want call_x", got)
	}
	if got := toolCallID(ToolCall{ID: "abc", Name: "x"}); got != "abc" {
		t.Errorf("toolCallID with ID = %q, want abc (unchanged)", got)
	}
}

func TestOpenAIResponseToNeutral_BadArgsFallsBack(t *testing.T) {
	resp := &openaiChatResponse{
		Choices: []openaiChoice{{
			Message: openaiMessage{
				Role: "assistant",
				ToolCalls: []openaiToolCall{{
					ID:       "x",
					Type:     "function",
					Function: openaiFunctionCall{Name: "submit_finding", Arguments: "not json {{"},
				}},
			},
		}},
	}
	out := openaiResponseToNeutral(resp)
	if len(out.ToolCalls) != 1 {
		t.Fatalf("want 1 tool call")
	}
	if _, ok := out.ToolCalls[0].Args["_raw_arguments"]; !ok {
		t.Errorf("expected _raw_arguments fallback when args don't parse, got %v", out.ToolCalls[0].Args)
	}
}

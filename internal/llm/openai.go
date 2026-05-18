package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultOpenAIBaseURL is LM Studio's default OpenAI-compatible endpoint.
// Override with --openai-base-url for vLLM, llama.cpp, or hosted OpenAI.
const DefaultOpenAIBaseURL = "http://localhost:1234/v1"

// OpenAIGenerator implements Generator against the OpenAI Chat Completions
// API or any compatible surface (LM Studio, vLLM, llama-cpp's openai server).
//
// Why no SDK: the request/response surface we use is small (chat
// completions + tools), the OpenAI Go SDK pulls in significant transitive
// dependencies, and supporting "OpenAI-compatible but slightly nonstandard"
// servers (LM Studio, etc.) is easier when we control the wire format.
type OpenAIGenerator struct {
	BaseURL    string // e.g. "http://localhost:1234/v1"
	APIKey     string // optional; empty is fine for LM Studio
	HTTPClient *http.Client

	MaxRetries    int
	MaxRetryDelay time.Duration

	// sleep is overridable in tests; nil falls back to time.Sleep.
	sleep  func(time.Duration)
	logger *slog.Logger
}

// NewOpenAIGenerator constructs a generator pointing at baseURL. apiKey
// is sent in the Authorization header when non-empty; LM Studio ignores it.
func NewOpenAIGenerator(baseURL, apiKey string) *OpenAIGenerator {
	if baseURL == "" {
		baseURL = DefaultOpenAIBaseURL
	}
	return &OpenAIGenerator{
		BaseURL:       strings.TrimRight(baseURL, "/"),
		APIKey:        apiKey,
		HTTPClient:    &http.Client{Timeout: 5 * time.Minute},
		MaxRetries:    DefaultMaxRetries,
		MaxRetryDelay: DefaultMaxRetryDelay,
		logger:        slog.Default(),
	}
}

// Generate satisfies Generator.
func (o *OpenAIGenerator) Generate(ctx context.Context, req GenerateRequest) (*GenerateResponse, error) {
	body, err := buildOpenAIRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("build openai request: %w", err)
	}
	raw, err := o.callWithRetry(ctx, body)
	if err != nil {
		return nil, err
	}
	var apiResp openaiChatResponse
	if err := json.Unmarshal(raw, &apiResp); err != nil {
		return nil, fmt.Errorf("openai decode: %w. body: %s", err, truncForErr(raw, 400))
	}
	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty choices")
	}
	return openaiResponseToNeutral(&apiResp), nil
}

// callWithRetry posts body and returns the raw response bytes. Transparently
// retries on HTTP 429 with a Retry-After header (or default 30s) up to
// MaxRetries times, capped at MaxRetryDelay per wait.
func (o *OpenAIGenerator) callWithRetry(ctx context.Context, body []byte) ([]byte, error) {
	maxRetries := o.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	maxDelay := o.MaxRetryDelay
	if maxDelay <= 0 {
		maxDelay = DefaultMaxRetryDelay
	}
	sleep := o.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}

	url := o.BaseURL + "/chat/completions"
	for attempt := 0; attempt <= maxRetries; attempt++ {
		raw, status, retryAfter, err := o.doOnce(ctx, url, body)
		if err != nil {
			return nil, err
		}
		if status >= 200 && status < 300 {
			return raw, nil
		}
		if status == 429 && attempt < maxRetries {
			delay := retryAfter
			if delay <= 0 {
				delay = 30 * time.Second
			}
			if delay > maxDelay {
				return nil, fmt.Errorf("openai: HTTP 429, Retry-After %v exceeds cap %v: %s",
					delay, maxDelay, truncForErr(raw, 200))
			}
			logger.Info("openai rate limited, sleeping before retry",
				"attempt", attempt+1, "wait", delay)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sleep(delay)
			continue
		}
		return nil, fmt.Errorf("openai: HTTP %d: %s", status, truncForErr(raw, 400))
	}
	return nil, fmt.Errorf("openai: retries exhausted")
}

// doOnce performs one HTTP round-trip and returns body, status, Retry-After.
func (o *OpenAIGenerator) doOnce(ctx context.Context, url string, body []byte) ([]byte, int, time.Duration, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if o.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)
	}
	resp, err := o.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("openai http: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, 0, fmt.Errorf("openai read body: %w", err)
	}
	return raw, resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// parseRetryAfter accepts the Retry-After header as either delta-seconds
// or HTTP-date. Returns 0 when unparseable.
func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func truncForErr(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// ----- request / response wire types ---------------------------------------

type openaiChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openaiMessage `json:"messages"`
	Tools       []openaiTool    `json:"tools,omitempty"`
	ToolChoice  string          `json:"tool_choice,omitempty"`
	Temperature *float32        `json:"temperature,omitempty"`
}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	Name       string           `json:"name,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
}

type openaiToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openaiFunctionCall `json:"function"`
}

type openaiFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON-encoded string per OpenAI spec
}

type openaiTool struct {
	Type     string                `json:"type"`
	Function openaiFunctionDeclSch `json:"function"`
}

type openaiFunctionDeclSch struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

type openaiChatResponse struct {
	Choices []openaiChoice `json:"choices"`
	Error   *openaiError   `json:"error,omitempty"`
}

type openaiChoice struct {
	Index        int           `json:"index"`
	Message      openaiMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openaiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    any    `json:"code"`
}

// ----- translations: neutral ↔ OpenAI --------------------------------------

func buildOpenAIRequestBody(req GenerateRequest) ([]byte, error) {
	msgs, err := turnsToOpenAIMessages(req.System, req.History)
	if err != nil {
		return nil, err
	}
	out := openaiChatRequest{
		Model:    req.Model,
		Messages: msgs,
		Tools:    toolsToOpenAI(req.Tools),
	}
	if len(out.Tools) > 0 {
		out.ToolChoice = "auto"
	}
	if req.Temperature != 0 {
		t := req.Temperature
		out.Temperature = &t
	}
	return json.Marshal(out)
}

// turnsToOpenAIMessages prepends the system message (if any) and translates
// each Turn into one or more OpenAI messages. Tool-result turns expand into
// one openai message per ToolResult.
func turnsToOpenAIMessages(system string, history []Turn) ([]openaiMessage, error) {
	out := []openaiMessage{}
	if system != "" {
		out = append(out, openaiMessage{Role: "system", Content: system})
	}
	for _, t := range history {
		switch t.Role {
		case RoleUser:
			out = append(out, openaiMessage{Role: "user", Content: t.Text})
		case RoleAssistant:
			m := openaiMessage{Role: "assistant", Content: t.Text}
			for _, c := range t.ToolCalls {
				args, err := json.Marshal(c.Args)
				if err != nil {
					return nil, fmt.Errorf("marshal tool args for %q: %w", c.Name, err)
				}
				m.ToolCalls = append(m.ToolCalls, openaiToolCall{
					ID:       toolCallID(c),
					Type:     "function",
					Function: openaiFunctionCall{Name: c.Name, Arguments: string(args)},
				})
			}
			out = append(out, m)
		case RoleTool:
			for _, r := range t.ToolResults {
				body, err := json.Marshal(r.Output)
				if err != nil {
					return nil, fmt.Errorf("marshal tool result for %q: %w", r.Name, err)
				}
				out = append(out, openaiMessage{
					Role:       "tool",
					ToolCallID: r.CallID,
					Name:       r.Name,
					Content:    string(body),
				})
			}
		default:
			return nil, fmt.Errorf("unknown role: %q", t.Role)
		}
	}
	return out, nil
}

// toolCallID returns the persistent ID for a ToolCall when echoed back to
// OpenAI. If the original call carried no ID (e.g. cross-backend translation
// from Gemini), synthesize a stable one from the name.
func toolCallID(c ToolCall) string {
	if c.ID != "" {
		return c.ID
	}
	return "call_" + c.Name
}

func toolsToOpenAI(decls []ToolDecl) []openaiTool {
	if len(decls) == 0 {
		return nil
	}
	out := make([]openaiTool, 0, len(decls))
	for _, d := range decls {
		out = append(out, openaiTool{
			Type: "function",
			Function: openaiFunctionDeclSch{
				Name:        d.Name,
				Description: d.Description,
				Parameters:  d.Parameters,
			},
		})
	}
	return out
}

// openaiResponseToNeutral pulls the first choice and returns its Text +
// ToolCalls in neutral form. arguments JSON strings are decoded to
// map[string]any so the dispatcher can use them directly.
func openaiResponseToNeutral(resp *openaiChatResponse) *GenerateResponse {
	out := &GenerateResponse{}
	if resp == nil || len(resp.Choices) == 0 {
		return out
	}
	msg := resp.Choices[0].Message
	out.Text = msg.Content
	for _, tc := range msg.ToolCalls {
		var args map[string]any
		if tc.Function.Arguments != "" {
			if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
				// Fall through with empty args; better than dropping the call.
				args = map[string]any{"_raw_arguments": tc.Function.Arguments}
			}
		}
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID:   tc.ID,
			Name: tc.Function.Name,
			Args: args,
		})
	}
	return out
}

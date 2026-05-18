package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/genai"
)

// Default retry policy for Gemini requests.
//
// MaxRetries is small on purpose: a 429 from Gemma includes a precise
// retryDelay; if the model keeps tripping it after three waits, something is
// genuinely wrong and we should surface the error rather than busy-loop.
//
// MaxRetryDelay caps any one wait. Gemma free tier delays are typically
// 30-60s; anything beyond a couple of minutes likely means the daily quota
// is exhausted, which the agent can't fix by waiting.
const (
	DefaultMaxRetries    = 3
	DefaultMaxRetryDelay = 90 * time.Second
)

// GeminiGenerator implements Generator against the Google Gemini API
// (the same surface that hosts the gemma-4-* models).
//
// Encapsulates the SDK client, the rate-limit retry policy, and the
// translations from neutral types to genai-native types.
type GeminiGenerator struct {
	Client        *genai.Client
	MaxRetries    int           // 0 → DefaultMaxRetries
	MaxRetryDelay time.Duration // 0 → DefaultMaxRetryDelay

	// sleep is overridable in tests; nil falls back to time.Sleep.
	sleep  func(time.Duration)
	logger *slog.Logger
}

// NewGeminiGenerator constructs a Gemini-backed Generator. apiKey may be
// empty to fall back to the GEMINI_API_KEY environment variable.
func NewGeminiGenerator(ctx context.Context, apiKey string) (*GeminiGenerator, error) {
	c, err := NewClient(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	return &GeminiGenerator{
		Client:        c,
		MaxRetries:    DefaultMaxRetries,
		MaxRetryDelay: DefaultMaxRetryDelay,
		logger:        slog.Default(),
	}, nil
}

// Generate satisfies Generator.
func (g *GeminiGenerator) Generate(ctx context.Context, req GenerateRequest) (*GenerateResponse, error) {
	contents, err := turnsToGeminiContents(req.History)
	if err != nil {
		return nil, fmt.Errorf("translate history: %w", err)
	}
	cfg := &genai.GenerateContentConfig{
		Tools: toolsToGemini(req.Tools),
	}
	if req.System != "" {
		cfg.SystemInstruction = &genai.Content{Parts: []*genai.Part{{Text: req.System}}}
	}
	if req.Temperature != 0 {
		t := req.Temperature
		cfg.Temperature = &t
	}

	resp, err := g.callWithRetry(ctx, req.Model, contents, cfg)
	if err != nil {
		return nil, err
	}
	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return nil, fmt.Errorf("no candidates in response")
	}
	return geminiResponseToNeutral(resp), nil
}

// callWithRetry wraps Models.GenerateContent with rate-limit-aware retry.
// On a 429 / RESOURCE_EXHAUSTED with a parseable RetryInfo, it sleeps the
// suggested delay and retries up to MaxRetries times. Any other error is
// returned to the caller untouched.
func (g *GeminiGenerator) callWithRetry(ctx context.Context, model string, contents []*genai.Content, cfg *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	maxRetries := g.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	maxDelay := g.MaxRetryDelay
	if maxDelay <= 0 {
		maxDelay = DefaultMaxRetryDelay
	}
	sleep := g.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	logger := g.logger
	if logger == nil {
		logger = slog.Default()
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := g.Client.Models.GenerateContent(ctx, model, contents, cfg)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		delay := retryDelayFor(err)
		if delay <= 0 {
			return nil, err
		}
		if delay > maxDelay {
			logger.Warn("rate-limit delay exceeds cap; giving up",
				"attempt", attempt, "delay", delay, "cap", maxDelay)
			return nil, err
		}
		if attempt >= maxRetries {
			logger.Warn("rate-limit retries exhausted",
				"attempts", attempt, "max", maxRetries)
			return nil, err
		}

		wait := delay + time.Second // small slack for clock skew
		logger.Info("rate limited, sleeping before retry",
			"attempt", attempt+1, "wait", wait)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sleep(wait)
	}
	return nil, lastErr
}

// retryDelayFor inspects err and returns a non-zero duration if the error
// is a 429/RESOURCE_EXHAUSTED with a parseable RetryInfo.retryDelay in its
// google.rpc Details payload. Returns 0 for any other error.
func retryDelayFor(err error) time.Duration {
	if err == nil {
		return 0
	}
	var apiErr genai.APIError
	if !errors.As(err, &apiErr) {
		var apiErrPtr *genai.APIError
		if !errors.As(err, &apiErrPtr) || apiErrPtr == nil {
			return 0
		}
		apiErr = *apiErrPtr
	}
	if apiErr.Code != 429 && apiErr.Status != "RESOURCE_EXHAUSTED" {
		return 0
	}
	for _, d := range apiErr.Details {
		t, _ := d["@type"].(string)
		if !strings.HasSuffix(t, ".RetryInfo") {
			continue
		}
		rd, _ := d["retryDelay"].(string)
		if rd == "" {
			continue
		}
		if dur, err := time.ParseDuration(rd); err == nil && dur > 0 {
			return dur
		}
	}
	return 0
}

// ----- translations: neutral ↔ genai ----------------------------------------

// turnsToGeminiContents converts the agent's history into genai.Content list.
// Gemini uses "user" / "model" roles (not "assistant" / "tool"); function
// responses live in "user"-role turns by Google's protocol.
func turnsToGeminiContents(history []Turn) ([]*genai.Content, error) {
	var out []*genai.Content
	for _, t := range history {
		switch t.Role {
		case RoleUser:
			out = append(out, &genai.Content{
				Role:  "user",
				Parts: []*genai.Part{{Text: t.Text}},
			})
		case RoleAssistant:
			parts := []*genai.Part{}
			if t.Text != "" {
				parts = append(parts, &genai.Part{Text: t.Text})
			}
			for _, c := range t.ToolCalls {
				parts = append(parts, &genai.Part{
					FunctionCall: &genai.FunctionCall{
						Name: c.Name,
						Args: c.Args,
					},
				})
			}
			if len(parts) == 0 {
				parts = append(parts, &genai.Part{Text: ""})
			}
			out = append(out, &genai.Content{Role: "model", Parts: parts})
		case RoleTool:
			parts := make([]*genai.Part, 0, len(t.ToolResults))
			for _, r := range t.ToolResults {
				parts = append(parts, &genai.Part{
					FunctionResponse: &genai.FunctionResponse{
						Name:     r.Name,
						Response: toMap(r.Output),
					},
				})
			}
			out = append(out, &genai.Content{Role: "user", Parts: parts})
		default:
			return nil, fmt.Errorf("unknown role: %q", t.Role)
		}
	}
	return out, nil
}

// geminiResponseToNeutral maps a Gemini response into the neutral
// GenerateResponse. Multiple parts are concatenated; tool calls preserve
// their order. Gemini doesn't issue stable IDs for tool calls — leave ID
// empty (the Gemini path doesn't need it for tool-result correlation).
func geminiResponseToNeutral(resp *genai.GenerateContentResponse) *GenerateResponse {
	out := &GenerateResponse{}
	if resp == nil || len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return out
	}
	var sb strings.Builder
	for _, p := range resp.Candidates[0].Content.Parts {
		if p == nil {
			continue
		}
		if p.Text != "" {
			sb.WriteString(p.Text)
		}
		if p.FunctionCall != nil {
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				Name: p.FunctionCall.Name,
				Args: p.FunctionCall.Args,
			})
		}
	}
	out.Text = sb.String()
	return out
}

// toolsToGemini translates ToolDecl into genai's tool / schema shape.
func toolsToGemini(decls []ToolDecl) []*genai.Tool {
	if len(decls) == 0 {
		return nil
	}
	fns := make([]*genai.FunctionDeclaration, 0, len(decls))
	for _, d := range decls {
		fns = append(fns, &genai.FunctionDeclaration{
			Name:        d.Name,
			Description: d.Description,
			Parameters:  jsonSchemaToGemini(d.Parameters),
		})
	}
	return []*genai.Tool{{FunctionDeclarations: fns}}
}

// jsonSchemaToGemini recursively walks a JSONSchema-shaped map and produces
// a *genai.Schema. Unknown JSONSchema fields are ignored — we cover the
// subset wfguard's tool decls actually use.
func jsonSchemaToGemini(m map[string]any) *genai.Schema {
	if m == nil {
		return nil
	}
	s := &genai.Schema{}
	if t, ok := m["type"].(string); ok {
		switch t {
		case "object":
			s.Type = genai.TypeObject
		case "string":
			s.Type = genai.TypeString
		case "integer":
			s.Type = genai.TypeInteger
		case "number":
			s.Type = genai.TypeNumber
		case "boolean":
			s.Type = genai.TypeBoolean
		case "array":
			s.Type = genai.TypeArray
		}
	}
	if d, ok := m["description"].(string); ok {
		s.Description = d
	}
	if props, ok := m["properties"].(map[string]any); ok && len(props) > 0 {
		s.Properties = make(map[string]*genai.Schema, len(props))
		for k, v := range props {
			if vm, ok := v.(map[string]any); ok {
				s.Properties[k] = jsonSchemaToGemini(vm)
			}
		}
	}
	s.Required = stringSliceFromAny(m["required"])
	s.Enum = stringSliceFromAny(m["enum"])
	if items, ok := m["items"].(map[string]any); ok {
		s.Items = jsonSchemaToGemini(items)
	}
	return s
}

// stringSliceFromAny accepts []string or []any (where each element is a
// string) and returns a []string. nil for anything else.
func stringSliceFromAny(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// toMap normalizes any tool-result value into a map[string]any suitable for
// genai.FunctionResponse.Response. Values that don't unmarshal to an object
// are wrapped under "value".
func toMap(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"value": fmt.Sprintf("%v", v)}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err == nil {
		return m
	}
	return map[string]any{"value": json.RawMessage(b)}
}

package llm

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/genai"
)

func TestRetryDelayFor_NilAndUnrelatedErrors(t *testing.T) {
	if got := retryDelayFor(nil); got != 0 {
		t.Errorf("nil err -> %v, want 0", got)
	}
	if got := retryDelayFor(errors.New("network blew up")); got != 0 {
		t.Errorf("plain err -> %v, want 0", got)
	}
	notRateLimit := genai.APIError{Code: 500, Status: "INTERNAL", Message: "boom"}
	if got := retryDelayFor(notRateLimit); got != 0 {
		t.Errorf("500 -> %v, want 0", got)
	}
}

func TestRetryDelayFor_429WithRetryInfo(t *testing.T) {
	err := genai.APIError{
		Code:   429,
		Status: "RESOURCE_EXHAUSTED",
		Details: []map[string]any{
			{"@type": "type.googleapis.com/google.rpc.Help"},
			{"@type": "type.googleapis.com/google.rpc.QuotaFailure"},
			{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "27s"},
		},
	}
	got := retryDelayFor(err)
	if got != 27*time.Second {
		t.Errorf("retryDelay 27s -> %v, want 27s", got)
	}
}

func TestRetryDelayFor_FractionalDelay(t *testing.T) {
	err := genai.APIError{
		Code:   429,
		Status: "RESOURCE_EXHAUSTED",
		Details: []map[string]any{
			{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "44.541946063s"},
		},
	}
	got := retryDelayFor(err)
	if got < 44*time.Second || got > 45*time.Second {
		t.Errorf("retryDelay 44.5s -> %v, out of expected band", got)
	}
}

func TestRetryDelayFor_429ButNoRetryInfo(t *testing.T) {
	err := genai.APIError{
		Code:    429,
		Status:  "RESOURCE_EXHAUSTED",
		Details: []map[string]any{{"@type": "type.googleapis.com/google.rpc.Help"}},
	}
	if got := retryDelayFor(err); got != 0 {
		t.Errorf("429 with no RetryInfo -> %v, want 0 (caller treats as fatal)", got)
	}
}

func TestRetryDelayFor_PointerWrappedErr(t *testing.T) {
	apiErr := &genai.APIError{
		Code:   429,
		Status: "RESOURCE_EXHAUSTED",
		Details: []map[string]any{
			{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "10s"},
		},
	}
	wrapped := fmt.Errorf("step 4: generate: %w", apiErr)
	if got := retryDelayFor(wrapped); got != 10*time.Second {
		t.Errorf("wrapped pointer-APIError -> %v, want 10s", got)
	}
}

func TestRetryDelayFor_StatusOnlyTriggers(t *testing.T) {
	// Some surfaces of the SDK may set Status without Code. The code OR the
	// status string should suffice.
	err := genai.APIError{
		Status: "RESOURCE_EXHAUSTED",
		Details: []map[string]any{
			{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "5s"},
		},
	}
	if got := retryDelayFor(err); got != 5*time.Second {
		t.Errorf("status-only RESOURCE_EXHAUSTED -> %v, want 5s", got)
	}
}

func TestRetryDelayFor_GarbageDelayIgnored(t *testing.T) {
	err := genai.APIError{
		Code:   429,
		Status: "RESOURCE_EXHAUSTED",
		Details: []map[string]any{
			{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "soon"},
		},
	}
	if got := retryDelayFor(err); got != 0 {
		t.Errorf("unparseable retryDelay -> %v, want 0", got)
	}
}

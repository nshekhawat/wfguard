package llm_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/llm"
)

const sampleSrc = `name: ci
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`

func sampleFix() string {
	return `name: ci
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
}

func sampleFinding() findings.Finding {
	return findings.Finding{
		Severity: findings.Critical,
		Kind:     "pwn-request",
		Location: ".github/workflows/ci.yml:test:step[0]",
		Evidence: "checkout of PR HEAD with pull_request_target trigger",
		Fix:      "switch trigger to pull_request",
		Source:   "rules",
	}
}

func TestFixer_Propose_Success(t *testing.T) {
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: sampleFix()}}}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "ci.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed == "" {
		t.Fatalf("expected non-empty Fixed, got Note=%q", got.Note)
	}
	if !strings.Contains(got.Fixed, "on: pull_request\n") {
		t.Errorf("Fixed missing the trigger swap:\n%s", got.Fixed)
	}
	if !strings.HasSuffix(got.Fixed, "\n") {
		t.Errorf("Fixed should end with newline")
	}
}

func TestFixer_Propose_StripsMarkdownFence(t *testing.T) {
	wrapped := "```yaml\n" + sampleFix() + "```\n"
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: wrapped}}}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "ci.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed == "" {
		t.Fatalf("expected non-empty Fixed (fence should have been stripped); Note=%q", got.Note)
	}
	if strings.Contains(got.Fixed, "```") {
		t.Errorf("Fixed still contains fence markers: %q", got.Fixed)
	}
}

func TestFixer_Propose_RejectsInvalidYAML(t *testing.T) {
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: "not: yaml: at all: :: ::"}}}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "ci.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "" {
		t.Errorf("expected empty Fixed on invalid YAML, got: %q", got.Fixed)
	}
	if !strings.Contains(got.Note, "YAML parse") {
		t.Errorf("expected Note to mention YAML parse failure, got %q", got.Note)
	}
}

func TestFixer_Propose_DetectsUnchangedOutput(t *testing.T) {
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: sampleSrc}}}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "ci.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "" {
		t.Errorf("expected empty Fixed when model returned input verbatim, got: %s", got.Fixed)
	}
	if !strings.Contains(got.Note, "unchanged") {
		t.Errorf("expected Note to mention 'unchanged', got %q", got.Note)
	}
}

func TestFixer_Propose_EmptySourceIsNoop(t *testing.T) {
	gen := &fakeGenerator{}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "x.yml",
		Source:   "",
		Findings: []findings.Finding{sampleFinding()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "" {
		t.Error("expected empty Fixed for empty source")
	}
	if gen.idx != 0 {
		t.Error("Generator should not be called for empty source")
	}
}

func TestFixer_Propose_NoFindingsIsNoop(t *testing.T) {
	gen := &fakeGenerator{}
	f := llm.NewFixer(gen, "m1")
	got, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "x.yml",
		Source:   sampleSrc,
		Findings: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Fixed != "" {
		t.Error("expected empty Fixed when no findings to fix")
	}
	if gen.idx != 0 {
		t.Error("Generator should not be called when findings is empty")
	}
}

func TestFixer_Propose_GeneratorErrorPropagates(t *testing.T) {
	want := errors.New("network blew up")
	gen := &fakeGenerator{errors: []error{want}}
	f := llm.NewFixer(gen, "m1")
	_, err := f.Propose(context.Background(), llm.FixRequest{
		Path:     "x.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if err == nil || !errors.Is(err, want) {
		t.Errorf("err = %v, want wrapping %v", err, want)
	}
}

func TestFixer_Propose_PassesFindingsAndSourceInPrompt(t *testing.T) {
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: sampleFix()}}}
	f := llm.NewFixer(gen, "m1")
	_, _ = f.Propose(context.Background(), llm.FixRequest{
		Path:     ".github/workflows/ci.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if len(gen.requests) != 1 {
		t.Fatalf("expected 1 generator request, got %d", len(gen.requests))
	}
	user := gen.requests[0].History[0].Text
	for _, want := range []string{
		"File: .github/workflows/ci.yml",
		"pwn-request",
		"on: pull_request_target", // raw source must be present
	} {
		if !strings.Contains(user, want) {
			t.Errorf("user prompt missing %q", want)
		}
	}
	// System prompt should be the fixer's, not the audit one.
	if !strings.Contains(gen.requests[0].System, "OUTPUT RULES") {
		t.Error("system prompt should be the fixer instructions")
	}
}

func TestNewFixer_DefaultsModel(t *testing.T) {
	f := llm.NewFixer(&fakeGenerator{}, "")
	// Indirect check: send a dummy request and inspect what model was set.
	gen := &fakeGenerator{responses: []*llm.GenerateResponse{{Text: sampleFix()}}}
	f = llm.NewFixer(gen, "")
	_, _ = f.Propose(context.Background(), llm.FixRequest{
		Path:     "x.yml",
		Source:   sampleSrc,
		Findings: []findings.Finding{sampleFinding()},
	})
	if gen.requests[0].Model != llm.DefaultModel {
		t.Errorf("Model = %q, want %q", gen.requests[0].Model, llm.DefaultModel)
	}
}

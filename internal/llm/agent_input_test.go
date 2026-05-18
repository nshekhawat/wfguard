package llm_test

import (
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/llm"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

func TestBuildSurfaceInput_IncludesGraphAndSuspicions(t *testing.T) {
	wf := &workflow.Workflow{
		Path: ".github/workflows/ci.yml",
		Name: "ci",
		On:   "pull_request_target",
		Jobs: map[string]*workflow.Job{
			"build": {
				ID:     "build",
				RunsOn: "ubuntu-latest",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}},
					{Index: 1, Run: "npm ci"},
				},
			},
		},
	}
	susp := []findings.Finding{
		{
			Severity: findings.Critical,
			Kind:     "pwn-request",
			Location: ".github/workflows/ci.yml:build:step[0]",
			Evidence: "uses: actions/checkout@v4 with ref ${{ github.event.pull_request.head.sha }}",
			Fix:      "Switch trigger to pull_request.",
			Source:   "rules",
		},
	}
	got := llm.BuildSurfaceInput(llm.SurfaceInput{Workflow: wf, Trigger: "pull_request_target", Suspicions: susp})

	for _, want := range []string{
		"Trigger surface:",
		"pull_request_target",
		"## Workflow graph",
		"job `build`",
		"actions/checkout@v4",
		"## Pre-flagged suspicions",
		"pwn-request",
		"## Your task",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("input missing %q", want)
		}
	}
}

func TestBuildSurfaceInput_NoSuspicions(t *testing.T) {
	wf := &workflow.Workflow{
		Path: ".github/workflows/ci.yml",
		On:   "push",
		Jobs: map[string]*workflow.Job{},
	}
	got := llm.BuildSurfaceInput(llm.SurfaceInput{Workflow: wf, Trigger: "push"})
	if !strings.Contains(got, "(none — the rules pass had nothing to say about this surface)") {
		t.Errorf("expected the empty-suspicions sentence, got:\n%s", got)
	}
}

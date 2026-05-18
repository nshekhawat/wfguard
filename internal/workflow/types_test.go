package workflow_test

import (
	"testing"

	"github.com/nshekhawat/wfguard/internal/workflow"
)

func TestStep_IsUses_IsRun(t *testing.T) {
	cases := []struct {
		name        string
		step        workflow.Step
		wantIsUses  bool
		wantIsRun   bool
	}{
		{"uses-only", workflow.Step{Uses: "actions/checkout@v4"}, true, false},
		{"run-only", workflow.Step{Run: "echo hi"}, false, true},
		{"empty", workflow.Step{}, false, false},
		{"both-set-but-yaml-shouldnt-allow", workflow.Step{Uses: "x@v1", Run: "echo"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.step.IsUses() != tc.wantIsUses {
				t.Errorf("IsUses() = %v, want %v", tc.step.IsUses(), tc.wantIsUses)
			}
			if tc.step.IsRun() != tc.wantIsRun {
				t.Errorf("IsRun() = %v, want %v", tc.step.IsRun(), tc.wantIsRun)
			}
		})
	}
}

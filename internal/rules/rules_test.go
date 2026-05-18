package rules_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/ingest"
	"github.com/nshekhawat/wfguard/internal/rules"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

// Each case asserts that the rule pass against the given testdata file
// produces *at least* the expected unique kinds, and produces *none* of the
// listed unexpected kinds. We don't pin counts because rule rewording can
// merge findings; we do pin the expected highest severity per kind.
type ruleCase struct {
	name             string
	fixture          string
	expectKinds      map[string]findings.Severity
	mustNotEmitKinds []string
}

func TestRules_OnTestdata(t *testing.T) {
	cases := []ruleCase{
		{
			name:    "pwn_request",
			fixture: "pwn_request.yml",
			expectKinds: map[string]findings.Severity{
				"pwn-request":       findings.Critical,
				"broad-permissions": findings.Low,
			},
			// pwn_request.yml uses actions/checkout@v4 and actions/setup-node@v4
			// — both trusted publishers — so UnpinnedRule must NOT fire on them.
			mustNotEmitKinds: []string{"unpinned-action"},
		},
		{
			name:    "expression_injection",
			fixture: "expression_injection.yml",
			expectKinds: map[string]findings.Severity{
				"expression-injection": findings.Critical, // direct case
			},
		},
		{
			name:    "secrets_leak",
			fixture: "secrets_leak.yml",
			expectKinds: map[string]findings.Severity{
				"secrets-exposure": findings.High,
				"unpinned-action":  findings.Medium,
			},
		},
		{
			name:    "unpinned",
			fixture: "unpinned.yml",
			expectKinds: map[string]findings.Severity{
				"unpinned-action": findings.Medium,
			},
			// This file is pinned-permissions and uses no compromised actions:
			mustNotEmitKinds: []string{"pwn-request", "compromised-action", "broad-permissions", "expression-injection"},
		},
		{
			name:    "broad_permissions",
			fixture: "broad_permissions.yml",
			expectKinds: map[string]findings.Severity{
				"broad-permissions": findings.Medium, // explicit write-all
			},
		},
		{
			name:    "known_bad",
			fixture: "known_bad.yml",
			expectKinds: map[string]findings.Severity{
				"compromised-action": findings.High,
				"unpinned-action":    findings.Medium,
			},
		},
		{
			name:    "self_hosted_pr",
			fixture: "self_hosted_pr.yml",
			expectKinds: map[string]findings.Severity{
				"self-hosted-runner-pr": findings.High,
			},
		},
		{
			name:    "reusable_workflow",
			fixture: "reusable_workflow.yml",
			expectKinds: map[string]findings.Severity{
				"reusable-workflow-input-injection": findings.High,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf := loadFixture(t, "vulnerable", tc.fixture)
			fs := rules.Run(rules.Default(), wf)

			byKind := map[string]findings.Severity{}
			for _, f := range fs {
				if cur, ok := byKind[f.Kind]; !ok || f.Severity.Order() > cur.Order() {
					byKind[f.Kind] = f.Severity
				}
			}

			for kind, wantSev := range tc.expectKinds {
				gotSev, ok := byKind[kind]
				if !ok {
					t.Errorf("missing finding kind %q (got: %v)", kind, kindList(byKind))
					continue
				}
				if gotSev.Order() < wantSev.Order() {
					t.Errorf("kind %q: severity %s, want at least %s", kind, gotSev, wantSev)
				}
			}
			for _, kind := range tc.mustNotEmitKinds {
				if _, ok := byKind[kind]; ok {
					t.Errorf("unexpected finding kind %q in safe-from-this-angle fixture", kind)
				}
			}
		})
	}
}

func TestRules_SafeFixtureProducesNoFindings(t *testing.T) {
	wf := loadFixture(t, "safe", "safe.yml")
	fs := rules.Run(rules.Default(), wf)
	if len(fs) != 0 {
		var summary []string
		for _, f := range fs {
			summary = append(summary, string(f.Severity)+":"+f.Kind+"@"+f.Location)
		}
		t.Fatalf("safe.yml produced %d findings: %v", len(fs), summary)
	}
}

func TestUnpinnedRule_IgnoresShaPinned(t *testing.T) {
	wf := &workflow.Workflow{
		Path: "x.yml",
		Jobs: map[string]*workflow.Job{
			"j": {
				ID: "j",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
				},
			},
		},
	}
	if got := (rules.UnpinnedRule{}).Check(wf); len(got) != 0 {
		t.Errorf("UnpinnedRule fired on a SHA-pinned step: %v", got)
	}
}

func TestUnpinnedRule_FlagsTagOnUnverifiedPublisher(t *testing.T) {
	wf := &workflow.Workflow{
		Path: "x.yml",
		Jobs: map[string]*workflow.Job{
			"j": {
				ID: "j",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "thirdparty-vendor/some-tool@v1"},
				},
			},
		},
	}
	got := (rules.UnpinnedRule{}).Check(wf)
	if len(got) != 1 {
		t.Fatalf("UnpinnedRule = %d findings, want 1 (unverified + mutable ref)", len(got))
	}
	if got[0].Kind != "unpinned-action" {
		t.Errorf("Kind = %q", got[0].Kind)
	}
}

func TestUnpinnedRule_SilentOnTrustedPublisherTag(t *testing.T) {
	// actions/checkout@v4 is mutable but the publisher is on the well-known
	// allowlist with no incident history — flagging is more noise than
	// signal, per the project's "actionable risk only" stance.
	wf := &workflow.Workflow{
		Path: "x.yml",
		Jobs: map[string]*workflow.Job{
			"j": {
				ID: "j",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "actions/checkout@v4"},
				},
			},
		},
	}
	if got := (rules.UnpinnedRule{}).Check(wf); len(got) != 0 {
		t.Errorf("UnpinnedRule fired on trusted publisher @v4: %v", got)
	}
}

func TestUnpinnedRule_FiresForKnownBadEvenIfTrusted(t *testing.T) {
	// tj-actions is on the known-bad list. Even on a tag, we WANT to flag
	// it — the public-incident-history short-circuits the well-known gate.
	wf := &workflow.Workflow{
		Path: "x.yml",
		Jobs: map[string]*workflow.Job{
			"j": {
				ID: "j",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "tj-actions/changed-files@v44"},
				},
			},
		},
	}
	got := (rules.UnpinnedRule{}).Check(wf)
	if len(got) != 1 {
		t.Fatalf("UnpinnedRule should fire for known-bad action on a tag, got %d findings", len(got))
	}
}

func TestKnownBadRule_OnlyFiresWhenInList(t *testing.T) {
	wf := &workflow.Workflow{
		Path: "x.yml",
		Jobs: map[string]*workflow.Job{
			"j": {
				ID: "j",
				Steps: []*workflow.Step{
					{Index: 0, Uses: "tj-actions/changed-files@v44"},
					{Index: 1, Uses: "actions/checkout@v4"},
				},
			},
		},
	}
	got := rules.KnownBadActionRule{KnownBad: rules.DefaultKnownBad()}.Check(wf)
	if len(got) != 1 {
		t.Fatalf("KnownBadActionRule = %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Evidence, "tj-actions/changed-files") {
		t.Errorf("evidence missing the offending uses string: %q", got[0].Evidence)
	}
}

// ---------------------------------------------------------------------------

// loadFixture copies a workflow file from /testdata/<bucket>/<name> into a
// throw-away repo layout and runs the real ingest pipeline against it.
func loadFixture(t *testing.T, bucket, name string) *workflow.Workflow {
	t.Helper()
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("..", "..", "testdata", bucket, name)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
	wfs, errs := ingest.ScanRepo(repo)
	for _, e := range errs {
		t.Errorf("ingest: %v", e)
	}
	if len(wfs) != 1 {
		t.Fatalf("expected 1 workflow from fixture, got %d", len(wfs))
	}
	return wfs[0]
}

func kindList(m map[string]findings.Severity) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

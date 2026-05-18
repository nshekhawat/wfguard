package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanRepo_FindsAndParsesWorkflows(t *testing.T) {
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const wf = `name: smoke
on: push
jobs:
  one:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
`
	if err := os.WriteFile(filepath.Join(wfDir, "smoke.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}
	// Non-yaml file should be ignored.
	if err := os.WriteFile(filepath.Join(wfDir, "README.md"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	wfs, errs := ScanRepo(repo)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(wfs) != 1 {
		t.Fatalf("expected 1 workflow, got %d", len(wfs))
	}
	got := wfs[0]
	if got.Name != "smoke" {
		t.Errorf("Name = %q, want %q", got.Name, "smoke")
	}
	if got.Path != ".github/workflows/smoke.yml" {
		t.Errorf("Path = %q", got.Path)
	}
	if len(got.Jobs) != 1 {
		t.Fatalf("Jobs = %d, want 1", len(got.Jobs))
	}
	job, ok := got.Jobs["one"]
	if !ok {
		t.Fatalf("missing job 'one'")
	}
	if job.ID != "one" {
		t.Errorf("job.ID = %q, want 'one'", job.ID)
	}
	if len(job.Steps) != 2 {
		t.Fatalf("Steps = %d, want 2", len(job.Steps))
	}
	if job.Steps[0].Index != 0 || job.Steps[1].Index != 1 {
		t.Errorf("step indexes = %d,%d", job.Steps[0].Index, job.Steps[1].Index)
	}
}

func TestScanRepo_NoWorkflowsDir(t *testing.T) {
	repo := t.TempDir()
	wfs, errs := ScanRepo(repo)
	if len(wfs) != 0 {
		t.Errorf("expected no workflows, got %d", len(wfs))
	}
	if len(errs) == 0 {
		t.Error("expected an error when .github/workflows missing")
	}
}

func TestScanRepo_BadYAMLDoesNotAbortBatch(t *testing.T) {
	repo := t.TempDir()
	wfDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Valid file
	good := `name: ok
on: push
jobs: { one: { runs-on: ubuntu-latest, steps: [{ run: echo }] } }
`
	if err := os.WriteFile(filepath.Join(wfDir, "good.yml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	// Bad file
	if err := os.WriteFile(filepath.Join(wfDir, "bad.yml"), []byte(":\n\t- not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	wfs, errs := ScanRepo(repo)
	if len(wfs) != 1 {
		t.Errorf("expected 1 workflow despite parse error, got %d", len(wfs))
	}
	if len(errs) == 0 {
		t.Error("expected the bad file to surface as a parse error")
	}
}

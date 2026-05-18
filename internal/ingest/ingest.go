// Package ingest walks a repository and parses its GitHub Actions
// workflow files into typed structs.
package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nshekhawat/wfguard/internal/workflow"
)

// ScanRepo walks repoPath/.github/workflows/ and returns parsed workflows.
//
// Files matching *.yml and *.yaml are included. Parse errors on individual
// files do not abort the whole scan; they are returned as the second value
// alongside whichever workflows did parse successfully.
func ScanRepo(repoPath string) ([]*workflow.Workflow, []error) {
	wfDir := filepath.Join(repoPath, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return nil, []error{fmt.Errorf("read workflows dir: %w", err)}
	}

	var (
		out  []*workflow.Workflow
		errs []error
	)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		full := filepath.Join(wfDir, name)
		wf, err := parseFile(full)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		// Make path relative to repo root.
		if rel, err := filepath.Rel(repoPath, full); err == nil {
			wf.Path = rel
		} else {
			wf.Path = full
		}
		out = append(out, wf)
	}
	return out, errs
}

func parseFile(path string) (*workflow.Workflow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wf workflow.Workflow
	if err := yaml.Unmarshal(b, &wf); err != nil {
		return nil, err
	}
	if wf.Name == "" {
		base := filepath.Base(path)
		wf.Name = strings.TrimSuffix(strings.TrimSuffix(base, ".yml"), ".yaml")
	}
	// Backfill index/id metadata that YAML doesn't carry.
	for jobID, job := range wf.Jobs {
		if job == nil {
			continue
		}
		job.ID = jobID
		for i, st := range job.Steps {
			if st != nil {
				st.Index = i
			}
		}
	}
	return &wf, nil
}

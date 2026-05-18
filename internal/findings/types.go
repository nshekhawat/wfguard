// Package findings defines the audit finding type and a deduplicating
// accumulator.
//
// Findings come from two sources:
//   - the deterministic rules pass (internal/rules)
//   - submit_finding tool calls from the LLM agent (internal/llm)
//
// The Accumulator merges them and removes duplicates.
package findings

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Severity is the criticality of a finding.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Order returns the sort weight (higher = more severe).
func (s Severity) Order() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// ParseSeverity normalizes a string into a Severity. Returns an error on
// unknown values; case is ignored. Empty input returns Low so a missing
// `--min-severity` flag falls back to "show everything".
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return Low, nil
	case "critical":
		return Critical, nil
	case "high":
		return High, nil
	case "medium":
		return Medium, nil
	case "low":
		return Low, nil
	}
	return "", fmt.Errorf("unknown severity %q (want critical|high|medium|low)", s)
}

// FilterByMinSeverity returns the subset of fs at or above min. The relative
// order of fs is preserved, so a sorted input yields a sorted output.
func FilterByMinSeverity(fs []Finding, min Severity) []Finding {
	if min == "" || min == Low {
		return fs
	}
	threshold := min.Order()
	out := fs[:0:0]
	for _, f := range fs {
		if f.Severity.Order() >= threshold {
			out = append(out, f)
		}
	}
	return out
}

// Finding is one issue detected by the auditor.
type Finding struct {
	// Severity bucket.
	Severity Severity `json:"severity"`

	// Kind is a short category id, e.g. "unpinned-action",
	// "expression-injection", "pwn-request", "compromised-action".
	Kind string `json:"kind"`

	// Location is a file:line or workflow:job:step path identifying where
	// the issue lives.
	Location string `json:"location"`

	// Evidence is a short YAML or code excerpt showing the issue.
	Evidence string `json:"evidence"`

	// Fix is a concrete, actionable remediation (1-3 sentences).
	Fix string `json:"fix"`

	// Source is "rules" (deterministic) or "agent" (LLM).
	Source string `json:"source"`
}

// Key returns a stable identifier used for deduplication.
func (f Finding) Key() string {
	return fmt.Sprintf("%s|%s|%s", f.Kind, f.Location, f.Evidence)
}

// Accumulator collects findings from multiple sources and dedups by Key.
// Safe for concurrent use.
type Accumulator struct {
	mu   sync.Mutex
	seen map[string]struct{}
	all  []Finding
}

// NewAccumulator returns an empty Accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{seen: map[string]struct{}{}}
}

// Add stores f if not already present (by Key). Returns true if it was
// added, false if it was a duplicate.
func (a *Accumulator) Add(f Finding) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := f.Key()
	if _, ok := a.seen[k]; ok {
		return false
	}
	a.seen[k] = struct{}{}
	a.all = append(a.all, f)
	return true
}

// All returns a snapshot of accumulated findings sorted by severity
// (descending), then kind, then location.
func (a *Accumulator) All() []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Finding, len(a.all))
	copy(out, a.all)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Order() != out[j].Severity.Order() {
			return out[i].Severity.Order() > out[j].Severity.Order()
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Location < out[j].Location
	})
	return out
}

// Len returns the number of unique findings collected so far.
func (a *Accumulator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.all)
}

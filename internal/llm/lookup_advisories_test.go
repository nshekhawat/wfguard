package llm_test

import (
	"context"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/llm"
)

// Without a *github.Client (GitHub: nil), lookup_advisories should still
// answer using the static known-bad list seeded from internal/rules.

func TestDispatch_LookupAdvisories_StaticKnownBadHit(t *testing.T) {
	d := &llm.AuditDispatcher{
		Acc: findings.NewAccumulator(),
		// GitHub: nil — only static lookup will run.
	}
	got, err := d.Dispatch(context.Background(), "lookup_advisories", map[string]any{
		"action": "tj-actions/changed-files",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["known_bad"] != true {
		t.Errorf("known_bad = %v, want true", m["known_bad"])
	}
	if note, _ := m["known_bad_note"].(string); note == "" {
		t.Errorf("known_bad_note empty, expected the seeded incident note")
	}
	// advisories list should be empty (no GitHub client).
	if list, _ := m["advisories"].([]any); len(list) != 0 {
		t.Errorf("advisories should be empty without a GitHub client, got %v", list)
	}
}

func TestDispatch_LookupAdvisories_StaticMiss(t *testing.T) {
	d := &llm.AuditDispatcher{Acc: findings.NewAccumulator()}
	got, err := d.Dispatch(context.Background(), "lookup_advisories", map[string]any{
		"action": "actions/checkout",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["known_bad"] != false {
		t.Errorf("known_bad = %v, want false (not on the static list)", m["known_bad"])
	}
}

func TestDispatch_LookupAdvisories_BadFormat(t *testing.T) {
	d := &llm.AuditDispatcher{Acc: findings.NewAccumulator()}
	if _, err := d.Dispatch(context.Background(), "lookup_advisories", map[string]any{
		"action": "owner-only",
	}); err == nil {
		t.Error("expected error on action without owner/repo separator")
	}
}

package rules

// DefaultKnownBad seeds the list of actions known to have been compromised at
// some point in their history. Update as new incidents are confirmed; the
// long-term home for this data should be the GitHub Advisory DB once we wire
// up `lookup_advisories` (see internal/llm/audit_dispatcher.go).
//
// Each entry is "owner/repo" -> a short human-readable note describing the
// incident window. The KnownBadActionRule uses this map by default; callers
// can pass a different map to test or to add private intel.
func DefaultKnownBad() map[string]string {
	return map[string]string{
		"tj-actions/changed-files": "Compromised in March 2025: malicious commit force-pushed across all tagged versions; rotate any secrets touched by workflows that ran the action between 2025-03-14 and 2025-03-15.",
		"aquasecurity/trivy-action": "Compromised window in March 2026.",
	}
}

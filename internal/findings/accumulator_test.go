package findings_test

import (
	"sync"
	"testing"

	"github.com/nshekhawat/wfguard/internal/findings"
)

func makeFinding(sev findings.Severity, kind, loc, evidence string) findings.Finding {
	return findings.Finding{
		Severity: sev,
		Kind:     kind,
		Location: loc,
		Evidence: evidence,
		Fix:      "fix",
		Source:   "rules",
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    findings.Severity
		wantErr bool
	}{
		{"critical", findings.Critical, false},
		{"HIGH", findings.High, false},
		{"  Medium  ", findings.Medium, false},
		{"low", findings.Low, false},
		{"", findings.Low, false}, // empty -> Low ("show everything")
		{"spicy", "", true},
	}
	for _, tc := range cases {
		got, err := findings.ParseSeverity(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSeverity(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSeverity(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFilterByMinSeverity(t *testing.T) {
	fs := []findings.Finding{
		makeFinding(findings.Critical, "k1", "a", "e"),
		makeFinding(findings.High, "k2", "b", "e"),
		makeFinding(findings.Medium, "k3", "c", "e"),
		makeFinding(findings.Low, "k4", "d", "e"),
	}
	cases := []struct {
		min       findings.Severity
		wantKinds []string
	}{
		{findings.Critical, []string{"k1"}},
		{findings.High, []string{"k1", "k2"}},
		{findings.Medium, []string{"k1", "k2", "k3"}},
		{findings.Low, []string{"k1", "k2", "k3", "k4"}},
		{"", []string{"k1", "k2", "k3", "k4"}}, // empty min -> no filter
	}
	for _, tc := range cases {
		out := findings.FilterByMinSeverity(fs, tc.min)
		if len(out) != len(tc.wantKinds) {
			t.Errorf("min=%q: got %d, want %d", tc.min, len(out), len(tc.wantKinds))
			continue
		}
		for i, k := range tc.wantKinds {
			if out[i].Kind != k {
				t.Errorf("min=%q: out[%d].Kind = %q, want %q", tc.min, i, out[i].Kind, k)
			}
		}
	}
}

func TestFilterByMinSeverity_PreservesInputOrder(t *testing.T) {
	// Order is interleaved across severities; filter must keep relative order
	// for matching elements.
	fs := []findings.Finding{
		makeFinding(findings.Low, "low-1", "a", "e"),
		makeFinding(findings.High, "high-1", "b", "e"),
		makeFinding(findings.Medium, "med-1", "c", "e"),
		makeFinding(findings.High, "high-2", "d", "e"),
	}
	out := findings.FilterByMinSeverity(fs, findings.High)
	if len(out) != 2 || out[0].Kind != "high-1" || out[1].Kind != "high-2" {
		t.Errorf("order not preserved: %+v", out)
	}
}

func TestSeverity_Order(t *testing.T) {
	cases := []struct {
		s    findings.Severity
		want int
	}{
		{findings.Critical, 4},
		{findings.High, 3},
		{findings.Medium, 2},
		{findings.Low, 1},
		{findings.Severity("nonsense"), 0},
		{findings.Severity(""), 0},
	}
	for _, tc := range cases {
		if got := tc.s.Order(); got != tc.want {
			t.Errorf("%q.Order() = %d, want %d", tc.s, got, tc.want)
		}
	}
}

func TestFinding_KeyDistinguishes(t *testing.T) {
	a := makeFinding(findings.High, "k", "loc", "ev")
	b := makeFinding(findings.High, "k", "loc", "ev2")
	c := makeFinding(findings.High, "k2", "loc", "ev")
	if a.Key() == b.Key() {
		t.Error("different evidence should produce different keys")
	}
	if a.Key() == c.Key() {
		t.Error("different kind should produce different keys")
	}
}

func TestAccumulator_Add_Dedupes(t *testing.T) {
	acc := findings.NewAccumulator()
	f := makeFinding(findings.Medium, "unpinned-action", "x.yml:job:step[0]", "uses: actions/x@v1")
	if !acc.Add(f) {
		t.Error("first Add should report inserted")
	}
	if acc.Add(f) {
		t.Error("duplicate Add should report not-inserted")
	}
	if got := acc.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1 after dedup", got)
	}
}

func TestAccumulator_All_SortedBySeverityThenKindThenLocation(t *testing.T) {
	acc := findings.NewAccumulator()
	// Insert in reverse order so ordering correctness is observable.
	inserts := []findings.Finding{
		makeFinding(findings.Low, "broad-permissions", "z.yml", "ev"),
		makeFinding(findings.Medium, "unpinned-action", "b.yml", "ev"),
		makeFinding(findings.Medium, "unpinned-action", "a.yml", "ev"),
		makeFinding(findings.Critical, "pwn-request", "any.yml", "ev"),
		makeFinding(findings.High, "compromised-action", "c.yml", "ev"),
		makeFinding(findings.Medium, "broad-permissions", "a.yml", "ev"),
	}
	for _, f := range inserts {
		acc.Add(f)
	}
	all := acc.All()
	if len(all) != len(inserts) {
		t.Fatalf("Len after Adds = %d, want %d", len(all), len(inserts))
	}

	// Severity descending
	for i := 1; i < len(all); i++ {
		if all[i-1].Severity.Order() < all[i].Severity.Order() {
			t.Errorf("severity not descending at %d: %s before %s", i, all[i-1].Severity, all[i].Severity)
		}
	}

	// Within Medium bucket: kind ascending then location ascending.
	var medBucket []findings.Finding
	for _, f := range all {
		if f.Severity == findings.Medium {
			medBucket = append(medBucket, f)
		}
	}
	if len(medBucket) != 3 {
		t.Fatalf("Medium bucket size = %d", len(medBucket))
	}
	want := []struct{ kind, loc string }{
		{"broad-permissions", "a.yml"},
		{"unpinned-action", "a.yml"},
		{"unpinned-action", "b.yml"},
	}
	for i, w := range want {
		if medBucket[i].Kind != w.kind || medBucket[i].Location != w.loc {
			t.Errorf("medium[%d] = %s@%s, want %s@%s",
				i, medBucket[i].Kind, medBucket[i].Location, w.kind, w.loc)
		}
	}
}

func TestAccumulator_All_ReturnsCopy(t *testing.T) {
	acc := findings.NewAccumulator()
	acc.Add(makeFinding(findings.High, "k", "loc", "ev"))
	a := acc.All()
	a[0].Kind = "mutated"
	b := acc.All()
	if b[0].Kind == "mutated" {
		t.Error("All() must return a copy that callers can mutate without affecting subsequent calls")
	}
}

func TestAccumulator_ConcurrentAddsAreRaceFree(t *testing.T) {
	acc := findings.NewAccumulator()
	var wg sync.WaitGroup
	const writers = 16
	const perWriter = 50
	for w := 0; w < writers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				acc.Add(makeFinding(findings.Medium, "unpinned-action",
					locFor(w, i), "ev"))
			}
		}()
	}
	wg.Wait()
	if got := acc.Len(); got != writers*perWriter {
		t.Errorf("Len() = %d, want %d (each unique location dedups by itself)", got, writers*perWriter)
	}
}

func locFor(w, i int) string {
	return "wf-" + itoa(w) + ".yml:j:step[" + itoa(i) + "]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

package envfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nshekhawat/wfguard/internal/envfile"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ParsesKeyValueLines(t *testing.T) {
	t.Setenv("WFG_TEST_A", "")
	t.Setenv("WFG_TEST_B", "")
	t.Setenv("WFG_TEST_C", "")
	os.Unsetenv("WFG_TEST_A")
	os.Unsetenv("WFG_TEST_B")
	os.Unsetenv("WFG_TEST_C")

	body := `# a comment
WFG_TEST_A=plain
WFG_TEST_B="quoted"
WFG_TEST_C='single quoted'

# blank above
NOT_PARSED no equals
=missing-key
`
	if err := envfile.Load(writeEnv(t, body)); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("WFG_TEST_A"); got != "plain" {
		t.Errorf("WFG_TEST_A = %q", got)
	}
	if got := os.Getenv("WFG_TEST_B"); got != "quoted" {
		t.Errorf("WFG_TEST_B = %q", got)
	}
	if got := os.Getenv("WFG_TEST_C"); got != "single quoted" {
		t.Errorf("WFG_TEST_C = %q", got)
	}
}

func TestLoad_DoesNotOverrideExisting(t *testing.T) {
	t.Setenv("WFG_TEST_OVERRIDE", "fromprocess")
	if err := envfile.Load(writeEnv(t, "WFG_TEST_OVERRIDE=fromfile")); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("WFG_TEST_OVERRIDE"); got != "fromprocess" {
		t.Errorf("file value clobbered process env: got %q", got)
	}
}

func TestLoad_MissingFileIsNotError(t *testing.T) {
	if err := envfile.Load(filepath.Join(t.TempDir(), "no-such-file")); err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
}

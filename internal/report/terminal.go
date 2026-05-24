package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nshekhawat/wfguard/internal/findings"
)

// TerminalOptions configures the human-friendly terminal renderer.
//
// The renderer is intentionally a different output path from WriteMarkdown:
// markdown is the on-disk / piped format (machine-friendly, stable);
// terminal is what a user sees when they run `wfguard scan` interactively.
// Two renderers, one source of truth (Finding).
type TerminalOptions struct {
	Color          bool   // emit ANSI escapes; pass false for redirects, file output, or NO_COLOR
	Width          int    // terminal width in columns; 0 falls back to 80
	Workflows      int    // workflow count for the summary header
	Hidden         int    // findings hidden below --min-severity (for the header)
	Threshold      string // human-readable threshold value, e.g. "high"
	ExitOnFindings bool   // include the "wfguard will exit 1" footer line
}

// IsTerminal reports whether f is a character device (TTY). Returns false
// when the user opted out of color via the NO_COLOR convention.
//
// Works on the wfguard-supported platforms (Darwin/Linux). No external
// dependency — we just stat the fd and check ModeCharDevice.
func IsTerminal(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if f == nil {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// WriteTerminal renders findings as a compact human-friendly report. It
// reads the same Finding slice WriteMarkdown does; only the formatting is
// different.
//
// Empty findings produce a single-line "No findings." with the hidden
// count appended when applicable — useful confirmation that the scan ran.
func WriteTerminal(w io.Writer, fs []findings.Finding, opts TerminalOptions) error {
	width := opts.Width
	if width <= 0 {
		width = 80
	}
	if width > 120 {
		width = 120 // long lines hurt readability more than they help
	}
	p := palette{enabled: opts.Color}
	rule := strings.Repeat("─", width)

	// ---- header ------------------------------------------------------------
	fmt.Fprintln(w, p.dim(rule))

	if len(fs) == 0 {
		if opts.Workflows > 0 {
			fmt.Fprintf(w, "  wfguard · %d workflow%s scanned · %s\n",
				opts.Workflows, plural(opts.Workflows), p.green("no findings"))
		} else {
			fmt.Fprintln(w, "  "+p.green("no findings"))
		}
		if opts.Hidden > 0 {
			fmt.Fprintf(w, "  %s\n", p.dim(fmt.Sprintf(
				"%d finding%s hidden below --min-severity %s",
				opts.Hidden, plural(opts.Hidden), opts.Threshold)))
		}
		fmt.Fprintln(w, p.dim(rule))
		return nil
	}

	counts := countBySeverity(fs)
	fmt.Fprintf(w, "  wfguard · %d workflow%s scanned · %d finding%s %s\n",
		opts.Workflows, plural(opts.Workflows),
		len(fs), plural(len(fs)), formatCountSummary(counts, p))
	if opts.Hidden > 0 {
		fmt.Fprintf(w, "  %s\n", p.dim(fmt.Sprintf(
			"%d hidden below --min-severity %s", opts.Hidden, opts.Threshold)))
	}
	fmt.Fprintln(w, p.dim(rule))
	fmt.Fprintln(w)

	// ---- per-finding -------------------------------------------------------
	for i, f := range fs {
		writeFinding(w, f, width, p)
		if i < len(fs)-1 {
			fmt.Fprintln(w)
		}
	}

	// ---- footer ------------------------------------------------------------
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.dim(rule))
	if opts.ExitOnFindings {
		fmt.Fprintf(w, "  %d finding%s at or above --min-severity %s — exit 1 (use --soft-fail to suppress)\n",
			len(fs), plural(len(fs)), opts.Threshold)
	}
	fmt.Fprintln(w, p.dim("  For a full Markdown report, pass: --report markdown -o report.md"))
	fmt.Fprintln(w, p.dim(rule))
	return nil
}

// writeFinding renders one finding block.
func writeFinding(w io.Writer, f findings.Finding, width int, p palette) {
	// Header line: "<SEV>  <kind>     [agent]"
	sevLabel := strings.ToUpper(string(f.Severity))
	if sevLabel == "" {
		sevLabel = "FINDING"
	}
	sevTag := p.severity(f.Severity, fmt.Sprintf(" %-8s ", sevLabel))
	kind := p.bold(f.Kind)
	if f.Source == "agent" {
		kind += " " + p.dim("[agent]")
	}
	fmt.Fprintf(w, "%s  %s\n", sevTag, kind)
	fmt.Fprintf(w, "    %s\n", p.dim(f.Location))

	// Evidence: prefix every line with "  > ". Trim leading/trailing blank lines.
	ev := strings.TrimSpace(f.Evidence)
	if ev != "" {
		for _, line := range strings.Split(ev, "\n") {
			fmt.Fprintf(w, "    %s %s\n", p.dim("│"), line)
		}
	}

	// Fix: word-wrapped, lead arrow on the first line.
	fix := strings.TrimSpace(f.Fix)
	if fix != "" {
		lines := wrapWords(fix, width-6)
		for j, line := range lines {
			prefix := "    " + p.dim("→") + " "
			if j > 0 {
				prefix = "      "
			}
			fmt.Fprintln(w, prefix+line)
		}
	}
}

// ----- helpers ---------------------------------------------------------------

type palette struct {
	enabled bool
}

const (
	ansiReset    = "\x1b[0m"
	ansiBold     = "\x1b[1m"
	ansiDim      = "\x1b[2m"
	ansiRed      = "\x1b[31m"
	ansiYellow  = "\x1b[33m"
	ansiCyan     = "\x1b[36m"
	ansiGreen    = "\x1b[32m"
	ansiBgRed    = "\x1b[41m"
	ansiWhiteFg  = "\x1b[97m"
)

func (p palette) wrap(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + ansiReset
}

func (p palette) bold(s string)   string { return p.wrap(ansiBold, s) }
func (p palette) dim(s string)    string { return p.wrap(ansiDim, s) }
func (p palette) red(s string)    string { return p.wrap(ansiRed+ansiBold, s) }
func (p palette) yellow(s string) string { return p.wrap(ansiYellow+ansiBold, s) }
func (p palette) cyan(s string)   string { return p.wrap(ansiCyan, s) }
func (p palette) green(s string)  string { return p.wrap(ansiGreen+ansiBold, s) }

// severity returns a padded, colored tag for the severity. Critical gets
// reverse-video for emphasis; lower severities get foreground color only.
func (p palette) severity(sev findings.Severity, padded string) string {
	switch sev {
	case findings.Critical:
		return p.wrap(ansiBgRed+ansiWhiteFg+ansiBold, padded)
	case findings.High:
		return p.red(padded)
	case findings.Medium:
		return p.yellow(padded)
	case findings.Low:
		return p.cyan(padded)
	}
	return padded
}

func countBySeverity(fs []findings.Finding) map[findings.Severity]int {
	out := map[findings.Severity]int{}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

func formatCountSummary(counts map[findings.Severity]int, p palette) string {
	parts := make([]string, 0, 4)
	for _, sev := range []findings.Severity{findings.Critical, findings.High, findings.Medium, findings.Low} {
		n := counts[sev]
		if n == 0 {
			continue
		}
		label := fmt.Sprintf("%d %s", n, sev)
		switch sev {
		case findings.Critical, findings.High:
			label = p.red(label)
		case findings.Medium:
			label = p.yellow(label)
		case findings.Low:
			label = p.cyan(label)
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// wrapWords word-wraps s to at most maxWidth columns. Splits on whitespace;
// words longer than maxWidth get their own line untruncated.
func wrapWords(s string, maxWidth int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if maxWidth < 20 {
		maxWidth = 20
	}
	words := strings.Fields(s)
	var lines []string
	var cur strings.Builder
	for _, w := range words {
		add := len(w)
		if cur.Len() > 0 {
			add += 1 // space
		}
		if cur.Len() > 0 && cur.Len()+add > maxWidth {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

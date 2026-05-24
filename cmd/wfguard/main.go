// Package main is the wfguard CLI entry point.
//
// Subcommands:
//
//	scan    - audit a repository for supply-chain risks in its workflows
//	smoke   - end-to-end smoke test against the chosen LLM backend
//	version - print version
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nshekhawat/wfguard/internal/envfile"
	"github.com/nshekhawat/wfguard/internal/findings"
	"github.com/nshekhawat/wfguard/internal/harden"
	"github.com/nshekhawat/wfguard/internal/ingest"
	"github.com/nshekhawat/wfguard/internal/llm"
	"github.com/nshekhawat/wfguard/internal/report"
	"github.com/nshekhawat/wfguard/internal/resolver"
	"github.com/nshekhawat/wfguard/internal/rules"
	"github.com/nshekhawat/wfguard/internal/workflow"
)

const (
	defaultModel = "gemma-4-31b-it"
	version      = "0.0.1"
)

func main() {
	// Load .env from the working directory before anything reads env vars.
	// Process env wins on conflicts; missing file is not an error.
	if err := envfile.Load(".env"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to read .env: %v\n", err)
	}

	configureLogging()

	root := &cobra.Command{
		Use:   "wfguard",
		Short: "Audit GitHub Actions workflows for supply-chain attacks (Gemma 4 powered)",
	}

	root.AddCommand(newScanCmd())
	root.AddCommand(newSmokeCmd())
	root.AddCommand(newVersionCmd())

	if err := root.Execute(); err != nil {
		slog.Error("command failed", "err", err)
		os.Exit(1)
	}
}

// ---- scan ------------------------------------------------------------------

// scanFlags groups the flags newScanCmd binds. Tests construct it directly.
type scanFlags struct {
	reportFmt     string
	output        string
	modelID       string
	maxSteps      int
	useLLM        bool
	harden        bool
	softFail      bool
	minSeverity   string
	backend       string
	openaiBaseURL string
	openaiAPIKey  string
	trustedOrgs   string
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Audit the GitHub Actions workflows in the repo at PATH",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runScan(ctx, args[0], *f)
		},
	}
	cmd.Flags().StringVar(&f.reportFmt, "report", "markdown", "report format: markdown|sarif|both")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "output file path (default: stdout for markdown; report.sarif for sarif; with both, writes <output>.md and <output>.sarif)")
	cmd.Flags().StringVar(&f.modelID, "model", envOr("WFGUARD_MODEL", defaultModel), "model id (e.g. gemma-4-31b-it for gemini; whatever LM Studio shows for openai)")
	cmd.Flags().IntVar(&f.maxSteps, "max-steps", 15, "max agent loop iterations per trigger surface")
	cmd.Flags().BoolVar(&f.useLLM, "llm", false, "run the LLM agent loop after the deterministic rules pass (extra audit findings)")
	cmd.Flags().BoolVar(&f.harden, "harden", false, "after the scan, ask the LLM to generate per-file fixes for visible findings; writes a unified patch (apply with `git apply`)")
	cmd.Flags().BoolVar(&f.softFail, "soft-fail", false, "always exit 0 (default: exit 1 if any finding is at or above --min-severity)")
	cmd.Flags().StringVar(&f.minSeverity, "min-severity", "high", "rendering / exit-code threshold: critical | high | medium | low. Findings below this level are computed but not shown")
	// Defaults are left empty so the flag → env → built-in-default
	// precedence can be resolved in resolveGeneratorSpec. The effective
	// defaults are documented in the help text.
	cmd.Flags().StringVar(&f.backend, "backend", "", "LLM backend: gemini | openai (any OpenAI-compatible server: Unsloth, vLLM, llama.cpp, Ollama, LM Studio). Default gemini, or $WFGUARD_BACKEND")
	cmd.Flags().StringVar(&f.openaiBaseURL, "openai-base-url", "", "OpenAI-compatible base URL for --backend openai, e.g. http://192.168.1.2:8888/v1. Default "+llm.DefaultOpenAIBaseURL+", or $WFGUARD_OPENAI_BASE_URL")
	// IMPORTANT: do NOT pass os.Getenv(...) as the default value here.
	// Cobra prints the default in --help, which would leak the key.
	// We fall back to the env var at runtime instead.
	cmd.Flags().StringVar(&f.openaiAPIKey, "openai-api-key", "", "API key for the OpenAI-compatible endpoint (or env $OPENAI_API_KEY). Required by hosted gateways and servers like Unsloth; LM Studio doesn't need one")
	cmd.Flags().StringVar(&f.trustedOrgs, "trusted-org", envOr("WFGUARD_TRUSTED_ORGS", ""), "comma-separated GitHub orgs to treat as trusted publishers (e.g. your own org). Augments the built-in well-known list; silences unpinned-action and secrets-exposure findings for first-party actions. Also via $WFGUARD_TRUSTED_ORGS")
	return cmd
}

// runScan is the testable body of the scan subcommand.
func runScan(ctx context.Context, repoPath string, f scanFlags) error {
	slog.Debug("scan", "path", repoPath, "report", f.reportFmt,
		"llm", f.useLLM, "harden", f.harden, "backend", effectiveBackend(f.backend))

	// 1. Ingest.
	workflows, parseErrs := ingest.ScanRepo(repoPath)
	for _, e := range parseErrs {
		slog.Warn("ingest error", "err", e)
	}
	if len(workflows) == 0 {
		return fmt.Errorf("no workflows found under %s/.github/workflows", repoPath)
	}
	slog.Debug("ingest", "workflows", len(workflows))

	// 2. Deterministic rules pass.
	acc := findings.NewAccumulator()
	ruleSet := rules.DefaultWithOptions(rules.Options{
		TrustedOrgs: parseCSV(f.trustedOrgs),
	})
	for _, wf := range workflows {
		for _, r := range ruleSet {
			for _, x := range r.Check(wf) {
				acc.Add(x)
			}
		}
	}
	deterministicCount := acc.Len()
	slog.Debug("rules pass", "findings", deterministicCount)

	// 3. The LLM stages (agent + hardener) share one Generator. Build it
	// once if either is requested.
	var gen llm.Generator
	if f.useLLM || f.harden {
		g, err := buildGenerator(ctx, f)
		if err != nil {
			return fmt.Errorf("build generator: %w", err)
		}
		gen = g
	}

	// 4. Optional LLM agent pass.
	if f.useLLM {
		if err := runAgentPass(ctx, gen, workflows, acc, f); err != nil {
			slog.Error("llm pass failed", "err", err)
		}
		slog.Debug("llm pass", "agent_findings", acc.Len()-deterministicCount)
	}

	// 5. Render. Findings below the threshold are computed (so the LLM
	// agent saw them as suspicions) but not surfaced to the user.
	threshold, err := findings.ParseSeverity(f.minSeverity)
	if err != nil {
		return fmt.Errorf("--min-severity: %w", err)
	}
	all := acc.All()
	visible := findings.FilterByMinSeverity(all, threshold)
	hidden := len(all) - len(visible)
	slog.Debug("findings hidden below threshold", "hidden", hidden, "threshold", threshold)

	exitOnFindings := !f.softFail && len(visible) > 0
	if err := renderReport(f, visible, len(workflows), hidden, string(threshold), exitOnFindings); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	// 6. Optional hardening pass — generate fixes for visible findings.
	if f.harden && len(visible) > 0 {
		if err := runHardener(ctx, gen, repoPath, workflows, visible, f); err != nil {
			slog.Error("harden failed", "err", err)
		}
	}

	// 7. Exit code: any visible finding fails the run unless --soft-fail.
	// The terminal renderer already announced this in its footer; the
	// markdown path doesn't need a slog WARN noise line either.
	if exitOnFindings {
		os.Exit(1)
	}
	return nil
}

// renderReport picks between the human-friendly terminal renderer (when
// markdown is going to a TTY stdout) and the canonical writeReport path
// (everything else — file output, SARIF, pipes). The terminal renderer is
// purely a presentation layer; the underlying findings are identical.
func renderReport(f scanFlags, fs []findings.Finding, workflowCount, hidden int, threshold string, exitOnFindings bool) error {
	if f.reportFmt == "markdown" && f.output == "" && report.IsTerminal(os.Stdout) {
		return report.WriteTerminal(os.Stdout, fs, report.TerminalOptions{
			Color:          true,
			Workflows:      workflowCount,
			Hidden:         hidden,
			Threshold:      threshold,
			ExitOnFindings: exitOnFindings,
		})
	}
	return writeReport(f.reportFmt, f.output, fs)
}

// buildGenerator constructs the LLM Generator from CLI flags + env. Shared
// by the agent pass and the hardener.
func buildGenerator(ctx context.Context, f scanFlags) (llm.Generator, error) {
	return llm.NewGenerator(ctx, resolveGeneratorSpec(f.backend, f.openaiBaseURL, f.openaiAPIKey))
}

// resolveGeneratorSpec applies flag → env → built-in-default precedence for
// the backend settings, so the whole local-endpoint config can live in
// .env (loaded at startup). An explicit flag always wins over an env var.
//
// Recognized env vars:
//
//	WFGUARD_BACKEND          gemini | openai
//	WFGUARD_OPENAI_BASE_URL  e.g. http://192.168.1.2:8888/v1
//	OPENAI_API_KEY           bearer token for endpoints that require one
//	GEMINI_API_KEY           key for the gemini backend
func resolveGeneratorSpec(backend, baseURL, apiKey string) llm.GeneratorSpec {
	if backend == "" {
		backend = envOr("WFGUARD_BACKEND", string(llm.BackendGemini))
	}
	if baseURL == "" {
		baseURL = envOr("WFGUARD_OPENAI_BASE_URL", llm.DefaultOpenAIBaseURL)
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	return llm.GeneratorSpec{
		Backend:       llm.Backend(backend),
		GeminiAPIKey:  os.Getenv("GEMINI_API_KEY"),
		OpenAIBaseURL: baseURL,
		OpenAIAPIKey:  apiKey,
	}
}

// effectiveBackend resolves the backend name for logging/display, mirroring
// the precedence in resolveGeneratorSpec.
func effectiveBackend(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return envOr("WFGUARD_BACKEND", string(llm.BackendGemini))
}

// runAgentPass wires up resolver + dispatcher + agent and runs one session
// per (workflow, trigger) surface. Findings are written into acc.
func runAgentPass(ctx context.Context, gen llm.Generator, wfs []*workflow.Workflow, acc *findings.Accumulator, f scanFlags) error {
	gh := resolver.NewAuthedClient(os.Getenv("GITHUB_TOKEN"))
	res := resolver.NewGitHubResolver(gh, resolver.NewCache(""))

	wfMap := make(map[string]*workflow.Workflow, len(wfs))
	for _, wf := range wfs {
		wfMap[filepath.Base(wf.Path)] = wf
	}

	dispatcher := &llm.AuditDispatcher{
		Workflows: wfMap,
		Resolver:  res,
		GitHub:    gh,
		Acc:       acc,
	}

	agent := llm.NewAgent(gen, dispatcher, f.modelID, llm.SystemPrompt)
	if f.maxSteps > 0 {
		agent.MaxSteps = f.maxSteps
	}

	// Snapshot deterministic findings keyed by workflow path so each surface
	// only sees its own suspicions.
	suspicionsByPath := groupByWorkflowPath(acc.All())

	for _, wf := range wfs {
		triggers := surfaceTriggers(wf)
		for _, trig := range triggers {
			input := llm.BuildSurfaceInput(llm.SurfaceInput{
				Workflow:   wf,
				Trigger:    trig,
				Suspicions: suspicionsByPath[wf.Path],
			})
			dispatcher.CurrentWorkflow = filepath.Base(wf.Path)
			slog.Info("agent surface", "wf", wf.Path, "trigger", trig)
			if err := agent.Run(ctx, input); err != nil {
				slog.Error("agent run", "wf", wf.Path, "trigger", trig, "err", err)
			}
		}
	}
	return nil
}

// runHardener asks the LLM to produce a fixed version of every workflow
// file with at least one visible finding, then composes a unified patch
// and writes it next to the report. Per-file failures (model declined,
// invalid YAML output, no diff) are logged and skipped — they don't
// abort the whole pass.
func runHardener(ctx context.Context, gen llm.Generator, repoPath string, wfs []*workflow.Workflow, visible []findings.Finding, f scanFlags) error {
	byPath := groupByWorkflowPath(visible)
	fixer := llm.NewFixer(gen, f.modelID)

	var patches []harden.FilePatch
	for _, wf := range wfs {
		wfFindings := byPath[wf.Path]
		if len(wfFindings) == 0 {
			continue
		}
		full := filepath.Join(repoPath, wf.Path)
		srcBytes, err := os.ReadFile(full)
		if err != nil {
			slog.Warn("harden: read source", "path", wf.Path, "err", err)
			continue
		}
		src := string(srcBytes)

		slog.Info("harden propose", "wf", wf.Path, "findings", len(wfFindings))
		result, err := fixer.Propose(ctx, llm.FixRequest{
			Path:     wf.Path,
			Source:   src,
			Findings: wfFindings,
		})
		if err != nil {
			slog.Error("harden propose", "wf", wf.Path, "err", err)
			continue
		}
		if result.Fixed == "" {
			slog.Info("harden no fix", "wf", wf.Path, "note", result.Note)
			continue
		}
		patches = append(patches, harden.FilePatch{
			Path:   wf.Path,
			Before: src,
			After:  result.Fixed,
		})
	}

	if len(patches) == 0 {
		slog.Info("harden: no fixes produced")
		return nil
	}

	patch, err := harden.UnifiedPatch(patches)
	if err != nil {
		return err
	}
	patchPath := patchPathFor(f)
	if err := os.WriteFile(patchPath, []byte(patch), 0o644); err != nil {
		return fmt.Errorf("write patch: %w", err)
	}
	slog.Info("wrote patch", "path", patchPath, "files", len(patches))
	return nil
}

// patchPathFor returns the destination for the unified-diff output. With
// `-o report` it becomes `report.patch`; without `-o` it defaults to
// `report.patch` in cwd.
func patchPathFor(f scanFlags) string {
	if f.output == "" {
		return "report.patch"
	}
	return f.output + ".patch"
}

// surfaceTriggers extracts the list of trigger names for a workflow's `on:`
// value. A workflow with no recognizable triggers returns one empty string so
// the agent still runs once.
func surfaceTriggers(wf *workflow.Workflow) []string {
	var out []string
	switch v := wf.On.(type) {
	case string:
		out = []string{v}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		for k := range v {
			out = append(out, k)
		}
		sort.Strings(out)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// groupByWorkflowPath bins findings by the workflow path embedded at the
// front of their Location field ("path/to/wf.yml:job:step[N]" → "path/to/wf.yml").
func groupByWorkflowPath(fs []findings.Finding) map[string][]findings.Finding {
	out := map[string][]findings.Finding{}
	for _, f := range fs {
		path := f.Location
		if i := strings.Index(path, ":"); i > 0 {
			path = path[:i]
		}
		out[path] = append(out[path], f)
	}
	return out
}

// writeReport renders fs in the requested format(s) to the requested
// destination(s).
func writeReport(format, output string, fs []findings.Finding) error {
	switch format {
	case "markdown", "md":
		return writeOne(output, "", func(w io.Writer) error { return report.WriteMarkdown(w, fs) })
	case "sarif":
		dest := output
		if dest == "" {
			dest = "report.sarif"
		}
		return writeOne(dest, dest, func(w io.Writer) error { return report.WriteSARIF(w, fs) })
	case "both":
		mdPath := "report.md"
		sarifPath := "report.sarif"
		if output != "" {
			mdPath = output + ".md"
			sarifPath = output + ".sarif"
		}
		if err := writeOne(mdPath, mdPath, func(w io.Writer) error { return report.WriteMarkdown(w, fs) }); err != nil {
			return err
		}
		return writeOne(sarifPath, sarifPath, func(w io.Writer) error { return report.WriteSARIF(w, fs) })
	}
	return fmt.Errorf("unknown report format %q (want markdown|sarif|both)", format)
}

// writeOne writes via fn to the file at path, or stdout when path is empty.
// stdoutMarker is non-empty when the file is the intended destination (so we
// log it); empty means "stdout — don't bother announcing".
func writeOne(path, stdoutMarker string, fn func(io.Writer) error) error {
	if path == "" {
		return fn(os.Stdout)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := fn(f); err != nil {
		return err
	}
	if stdoutMarker != "" {
		slog.Info("wrote report", "path", stdoutMarker)
	}
	return nil
}

// ---- smoke -----------------------------------------------------------------

func newSmokeCmd() *cobra.Command {
	var (
		modelID       string
		backend       string
		openaiBaseURL string
		openaiAPIKey  string
	)
	cmd := &cobra.Command{
		Use:   "smoke",
		Short: "Verify the chosen LLM backend is reachable and replies",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			spec := resolveGeneratorSpec(backend, openaiBaseURL, openaiAPIKey)
			gen, err := llm.NewGenerator(ctx, spec)
			if err != nil {
				return fmt.Errorf("generator: %w", err)
			}
			req := llm.GenerateRequest{
				Model: modelID,
				History: []llm.Turn{{
					Role: llm.RoleUser,
					Text: "Reply with exactly: 'wfguard smoke OK'",
				}},
				Temperature: 0,
			}
			resp, err := gen.Generate(ctx, req)
			if err != nil {
				return fmt.Errorf("generate: %w", err)
			}
			fmt.Println("backend:", spec.Backend)
			if spec.Backend == llm.BackendOpenAI {
				fmt.Println("endpoint:", spec.OpenAIBaseURL)
			}
			fmt.Println("model:  ", modelID)
			fmt.Println("reply:  ", strings.TrimSpace(resp.Text))
			fmt.Println("----")
			fmt.Println("OK — model reachable.")
			return nil
		},
	}
	cmd.Flags().StringVar(&modelID, "model", envOr("WFGUARD_MODEL", defaultModel), "model id")
	cmd.Flags().StringVar(&backend, "backend", "", "LLM backend: gemini | openai. Default gemini, or $WFGUARD_BACKEND")
	cmd.Flags().StringVar(&openaiBaseURL, "openai-base-url", "", "OpenAI-compatible base URL. Default "+llm.DefaultOpenAIBaseURL+", or $WFGUARD_OPENAI_BASE_URL")
	// Don't read OPENAI_API_KEY here — Cobra would print it as the default
	// in `--help`, leaking the secret. Falls back to env at runtime above.
	cmd.Flags().StringVar(&openaiAPIKey, "openai-api-key", "", "API key for the OpenAI-compatible endpoint (or env $OPENAI_API_KEY)")
	return cmd
}

// ---- version ---------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("wfguard", version)
		},
	}
}

// ---- helpers ---------------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseCSV splits a comma-separated string into trimmed, non-empty values.
// Returns nil for an empty input so callers can ignore the result cleanly.
func parseCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func configureLogging() {
	// Default is WARN: the interactive UX is the report itself, not a stream
	// of routine info logs. Bump to info/debug via WFGUARD_LOG_LEVEL when
	// you need plumbing visibility (--llm runs, harden retries, etc.).
	lvl := slog.LevelWarn
	switch strings.ToLower(os.Getenv("WFGUARD_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
		// Drop the timestamp prefix — it eats horizontal space on a terminal
		// without telling anyone anything they don't already know.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

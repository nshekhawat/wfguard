# wfguard — GitHub Actions Supply-Chain Auditor

> A security tool that audits GitHub Actions workflows for supply-chain attack
> patterns, using **Gemma 4 31B** (`gemma-4-31b-it`) for cross-file taint
> analysis and pattern recognition. Built in Go.

This is the project's design document. It captures the architecture, the
deterministic-vs-LLM split, the agent loop, the rule taxonomy, and the
implementation plan. Read this before making non-trivial changes.

---

## 1. Status & Dates

- **Stage:** Initial scaffold (Day 0).
- **Owner:** Narendra (HashiCorp infra/CI-CD-security background; Go is the preferred language).
- **Submission:** dev.to **Gemma 4 Challenge — Build with Gemma 4** prompt.
- **Deadline:** **May 24, 2026, 11:59 PM PDT.**
- **Prize alignment:** Build category, $500 + DEV++ + badge.

A second submission to the **Write About Gemma 4** prompt is planned, framed
around model selection trade-offs (E4B vs 26B-A4B vs 31B Dense) using this
project's empirical results.

---

## 2. Quick Reference

```bash
# One-time setup
export GEMINI_API_KEY="<your key from aistudio.google.com>"
export GITHUB_TOKEN="<personal access token, repo:read scope>"
go mod tidy

# Smoke-test the model end-to-end
go run ./cmd/wfguard smoke

# Audit a repo
go run ./cmd/wfguard scan /path/to/cloned/repo
go run ./cmd/wfguard scan /path/to/cloned/repo \
  --report sarif --output report.sarif

# Tests
go test ./...
make test
```

The project ships a `Makefile` with `build`, `test`, `lint`, `smoke`, `scan-self`.

---

## 3. What This Tool Does

Given a Git repository on disk, wfguard:

1. Walks `.github/workflows/*.yml` and parses them into typed Go structs.
2. For every `uses:` reference, resolves the ref to a commit SHA via the
   GitHub API, fetches the action's `action.yml`, and (for JS actions) the
   `dist/` scripts. Caches everything to disk.
3. Builds a dependency graph: `workflow → job → step → action → files`.
4. Runs a **deterministic rules pass** for cheap pattern wins (no LLM).
5. Hands the graph + the deterministic suspicions to a **Gemma 4 31B agent
   loop** that does cross-cutting taint analysis and explanation.
6. Emits **SARIF** (for the GitHub code-scanning UI) and a Markdown summary.

---

## 4. Why Gemma 4 31B (model selection narrative)

The challenge weighs *intentional model selection* heavily. This is the
narrative that the dev.to writeup should emphasize.

| Model | Used? | Reasoning |
|---|---|---|
| `gemma-4-e2b-it` | No | Too small for multi-step taint analysis across files. |
| `gemma-4-e4b-it` | Comparison run only | Cheap, fast, fine for single-action triage. Used in benchmark to show where 31B's extra capacity actually pays off. |
| `gemma-4-26b-a4b-it` (MoE) | Comparison run only | ~4B active params; faster than 31B with similar quality on many tasks. |
| **`gemma-4-31b-it` (Dense)** | **Primary** | Strongest dense Gemma reasoning. **256K context** fits a whole workflow plus all referenced action sources in a single prompt. Native function-calling. Native vision (unused here, available for future screenshot-based features). |

**Build it model-agnostic.** `ModelID` is read from a CLI flag / env var, not
hardcoded. At the end of the build phase we run the same audit suite across
E4B / 26B-A4B / 31B and put the comparison table in the writeup. This is
"basically free" if the abstraction stays clean.

API endpoint: `https://generativelanguage.googleapis.com/v1beta/models/gemma-4-31b-it:generateContent`
Go SDK: `google.golang.org/genai`.

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI (cobra)        wfguard scan ./repo --report sarif          │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Ingest      (internal/ingest)                               │
│     Walk .github/workflows, parse YAML to typed structs         │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Resolver    (internal/resolver)                             │
│     For each `uses:`, GitHub API → SHA, action.yml, scripts     │
│     Cache to $XDG_CACHE_HOME/wfguard to keep dev cheap          │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Graph       (internal/workflow)                             │
│     workflow → job → step → uses → action → files               │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Deterministic rules pass   (internal/rules)                 │
│     Cheap pattern matches; NO LLM. Generates initial findings   │
│     and a "suspicions" list seeded into the agent's prompt.     │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Agent loop (Gemma 4 31B)   (internal/llm)                   │
│     One session per "trigger surface" (workflow × on:-trigger)  │
│     System prompt + graph context + 7 tools                     │
│     Plan → call tools → submit_finding(...) → terminate         │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Report      (internal/report)                               │
│     SARIF + Markdown                                            │
└─────────────────────────────────────────────────────────────────┘
```

### The deterministic / LLM split

**Rule:** do not let Gemma 4 do work that Go can do reliably.

YAML parsing, GitHub API calls, ref resolution, and regex pinning checks are
deterministic — they go in Go. The model's job is **reasoning over a
normalized, pre-built graph**: cross-step taint analysis, recognizing the
*class* of a suspicious pattern, generating human-readable explanations,
prioritizing severity. This split makes the system fast, cheap, debuggable,
unit-testable, and lets us write proper tests on the Go bits without paying
API costs every test run.

A "trigger surface" = one entry point into a workflow (e.g. `on:
pull_request_target`). Auditing per surface keeps each agent session focused
and bounded. Surfaces can run in parallel goroutines once the loop is stable.

---

## 6. Tool Set (what the model sees)

The agent sees seven tools, each with a strict JSON schema. See
`internal/llm/tools.go` for the exact declarations.

| Tool | Purpose |
|---|---|
| `list_workflows()` | Returns workflow file names + their `on:` triggers. |
| `get_workflow(name)` | Returns parsed jobs/steps as JSON for one workflow. |
| `get_action_source(uses)` | Returns `action.yml` + scripts for a referenced action. |
| `resolve_reference(uses)` | Returns `{pinned_to_sha, sha, latest_release, publisher_verified}`. |
| `lookup_advisories(action)` | GitHub Advisory DB lookup for known CVEs on this action. |
| `trace_expression_flow(workflow, expr)` | Lists every step where `${{ expr }}` appears as input or in `run:`. |
| `submit_finding(severity, kind, location, evidence, fix)` | **The only output channel.** |

### Critical design rule

`submit_finding` is the **only** way the agent can record output. Anything
else the model "says" is discarded. This forces structured output without
needing strict JSON-mode generation, and gives a clean schema for downstream
SARIF emission.

There is **no** `done()` tool. The loop terminates when the model returns a
turn with no tool calls, or when the step budget (default 15) is hit.

---

## 7. Agent Loop Pattern

Plan-and-execute, per trigger surface:

```
SYSTEM: <prompts/system.md>

USER:   <pre-built graph summary for this trigger surface>
        <list of pre-flagged suspicions from the deterministic pass>

LOOP (max 15 iterations):
   resp = client.GenerateContent(history, tools=AllTools, model=ModelID)
   if no FunctionCall parts in resp -> break
   for each function_call in resp:
       result = dispatcher.Dispatch(name, args)   // pure Go
       history += {function_call, function_response}
   continue
```

The deterministic pass already finds half the bugs. The agent's job is the
cross-cutting stuff: *"step 4 reads `pull_request.title`, sets it as env var
`MSG`, step 6 runs `git tag $MSG` — that's an injection sink, here's the
path."* That's the multi-hop reasoning a regex can't do.

Implementation: `internal/llm/agent.go` (already scaffolded).

---

## 8. Project Layout

```
wfguard/
├── DESIGN.md                       ← this file
├── README.md
├── Makefile
├── go.mod
├── .env.example
├── .gitignore
├── cmd/wfguard/main.go             ← cobra CLI: scan, smoke, version
├── internal/
│   ├── llm/
│   │   ├── client.go               ← genai client wrapper
│   │   ├── agent.go                ← the loop (full impl)
│   │   ├── tools.go                ← tool declarations
│   │   ├── dispatcher.go           ← Dispatcher interface + registry
│   │   └── prompts.go              ← embeds prompts/system.md
│   ├── workflow/
│   │   └── types.go                ← Workflow/Job/Step structs
│   ├── findings/
│   │   └── types.go                ← Finding type, severity, dedup
│   ├── ingest/
│   │   └── ingest.go               ← repo walk + YAML parse  (TODO)
│   ├── resolver/
│   │   └── resolver.go             ← go-github + cache       (TODO)
│   ├── rules/
│   │   └── rules.go                ← deterministic checks    (partial)
│   └── report/
│       └── sarif.go                ← SARIF writer            (TODO)
├── prompts/
│   └── system.md                   ← the agent's system prompt
└── testdata/
    └── vulnerable/
        └── pwn_request.yml         ← synthetic vulnerable example
```

---

## 9. Setup

```bash
go mod tidy

# Required env
export GEMINI_API_KEY="<from https://aistudio.google.com/apikey>"
export GITHUB_TOKEN="<PAT, scopes: public_repo (or repo for private)>"

# Optional
export WFGUARD_MODEL="gemma-4-31b-it"   # default
export WFGUARD_LOG_LEVEL="debug"
```

Use `.env.example` as a template for `.env` (loaded automatically when
present; do not commit `.env`).

---

## 10. Code Conventions

### DO

- Use `log/slog` for logging. Pass a `*slog.Logger` through context or as a
  struct field.
- Pass `context.Context` as the first argument to any function that does I/O
  or could block.
- Return concrete types from package APIs; accept interfaces.
- Cache GitHub API responses on disk (`os.UserCacheDir()` →
  `wfguard/<sha>.json`).
- Handle GitHub rate limits with exponential backoff and respect the
  `X-RateLimit-Reset` header.
- Use cobra subcommands: `scan`, `smoke`, `version`.
- Write table-driven tests for `internal/rules`.
- Embed prompt files with `//go:embed` so the binary is self-contained.

### DON'T

- Don't ask Gemma 4 to parse YAML or perform HTTP calls. The model reasons;
  Go fetches.
- Don't make the model the source of truth for any deterministic fact (a SHA
  is a SHA — verify it in Go, not by asking the model).
- Don't hardcode `gemma-4-31b-it`. Read from `WFGUARD_MODEL` or `--model`
  flag, default `gemma-4-31b-it`.
- Don't `panic` for control flow. Return errors. `panic` is only for
  programmer errors that indicate the binary is broken.
- Don't commit `GEMINI_API_KEY` or `GITHUB_TOKEN`. `.env` is gitignored.
- Don't add tools to the agent's tool set without considering whether a
  deterministic Go function would be safer.

### Style

- `gofmt` / `goimports`. Run via `make lint`.
- Errors: wrap with `fmt.Errorf("doing X: %w", err)`. Don't lose the cause.
- Prefer small functions. If a function exceeds ~80 lines, consider
  extracting.

---

## 11. Vulnerability Patterns the Auditor Detects

The "supply-chain attack class" — the auditor's scope. Each pattern should
have at least one synthetic example in `testdata/vulnerable/` and one
table-driven test in `internal/rules/`.

1. **Unpinned action references.** Mutable tags (`@main`, `@v1`, `@latest`)
   instead of commit SHAs. The rule is **deliberately narrowed**: it only
   fires for unverified publishers (i.e. NOT on `resolver.IsWellKnownOrg`'s
   allowlist), or for actions on the known-bad list. Pinning everything is
   the "correct" advice but in practice the noise drowns the signal — most
   `@v4` references are on `actions/*`, which has never been compromised.
   wfguard's stance: only flag where pinning actually buys protection.
2. **Compromised actions.** Cross-reference `internal/rules/known_bad.go`.
   Initial seed: the March-2025 `tj-actions/changed-files` compromise and
   the March-2026 `aquasecurity/trivy-action` window. Refresh from GitHub
   Advisory DB.
3. **"Pwn request" pattern.** `pull_request_target` trigger combined with
   `actions/checkout` of the PR HEAD ref
   (`github.event.pull_request.head.sha` or `head.ref`).
4. **Expression injection sinks.** `${{ github.event.* }}` values (notably
   `pull_request.title`, `issue.body`, `head_ref`, `comment.body`,
   `commits.*.message`) flowing into a `run:` script body — even via env
   vars, since `env: FOO: ${{ ... }}` then `run: echo "$FOO"` is still
   exploitable through `$()` injection.
5. **Secrets exposure.** `secrets.*` passed as inputs to actions whose
   source we can't verify (unpinned, no advisories check, JS action with
   network access).
6. **Self-hosted runners on public repos.** Container/host escape risk if
   forks can run.
7. **Reusable workflow without input validation.** `workflow_call` consuming
   caller-controlled inputs that flow into shell.
8. **Overly broad permissions.** `permissions: write-all` or no
   `permissions:` block at all on a workflow handling untrusted input.
9. **Outdated actions with known CVEs.** Action version older than the
   patched advisory.
10. **Suspicious patterns inside JS actions.** `dist/` files that fetch
    arbitrary URLs, exfiltrate env vars, or use `post:` steps to read
    secrets.

---

## 12. Reference Incidents (for testdata + writeup)

- **`tj-actions/changed-files` (March 2025):** widely-used action
  compromised; all tagged versions had a malicious commit force-pushed onto
  them. **Detection signal in wfguard:** SHA-pinning check + a deterministic
  rule that flags any unpinned reference to known-targeted actions.
- **`aquasecurity/trivy-action` (March 2026):** the supply-chain attack we
  discussed. Reference for the "compromised popular CI tool" pattern.
- **Build at least one synthetic example** in `testdata/vulnerable/` for
  each pattern in §11. Each must have a corresponding "expected findings"
  golden file used by integration tests.

---

## 13. 14-Day Implementation Plan

| Day | Goal | Files |
|---|---|---|
| 1–2 | CLI scaffold, YAML→struct ingest. `wfguard scan ./repo` lists workflows + referenced actions. | `cmd/wfguard/main.go`, `internal/ingest/`, `internal/workflow/types.go` |
| 3–4 | Resolver: go-github client, ref→SHA, action source fetch. Disk cache. | `internal/resolver/` |
| 5 | Deterministic rules pass: unpinned refs, pull_request_target+checkout, known-bad list. **At end of day 5, the tool is already useful as a regex-based linter.** | `internal/rules/` |
| 6–7 | Wire up Gemma 4 31B. Smoke test → first tool (`get_action_source`) → `submit_finding` end-to-end on one synthetic workflow. | `internal/llm/` |
| 8–9 | Implement the rest of the tool set; agent loop with step budget; iterate the system prompt against `testdata/vulnerable/*`. | `internal/llm/`, `prompts/system.md` |
| 10–11 | SARIF writer + Markdown report. Test on real public repos with known CVEs. Reproduce tj-actions and Trivy patterns in `testdata/`. | `internal/report/` |
| 12 | Demo recording + cover image + README polish. | — |
| 13–14 | dev.to writeup focusing on the model-selection narrative. Run the comparison across E4B / 26B-A4B / 31B. Submit. | — |

**Day 5 is the safety milestone.** If the agent loop falls behind for any
reason, the deterministic rules pass alone is shippable as a useful tool
plus a smaller writeup.

---

## 14. TODOs / Where to Pick Up

The immediate next tasks when picking up the project are:

1. **`internal/ingest`** is currently a stub. Implement `ScanRepo(path
   string) ([]*workflow.Workflow, error)` that walks `.github/workflows/`,
   parses each YAML file, returns typed `Workflow` values. Use
   `gopkg.in/yaml.v3`.
2. **`internal/workflow/types.go`** — verify the structs cover all fields
   we need (currently has the basics; may need `defaults`, `concurrency`,
   `environment`).
3. **`internal/resolver`** — implement `ResolveAction(ctx,
   uses string) (*Action, error)` using `github.com/google/go-github/v66`.
   Cache responses on disk.
4. **`internal/rules`** — `Run(graph) []findings.Finding`. Start with three
   rules: `UnpinnedRule`, `PullRequestTargetCheckoutRule`,
   `KnownBadActionRule`.
5. **`internal/llm/dispatcher.go`** — implement the concrete
   `auditDispatcher` that backs each tool with the matching Go function.

Smoke test should already work (`go run ./cmd/wfguard smoke`) once
`GEMINI_API_KEY` is set.

---

## 15. References

- Gemma 4 model card: <https://ai.google.dev/gemma/docs/core>
- Gemma on Gemini API: <https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api>
- Go genai SDK: <https://pkg.go.dev/google.golang.org/genai>
- Challenge announcement: <https://dev.to/devteam/join-the-gemma-4-challenge-3000-prize-pool-for-ten-winners-23in>
- SARIF spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- GitHub Advisory DB: <https://github.com/advisories>

### arxiv background (for the writeup)

- 2506.02153 — "Small Language Models are the Future of Agentic AI"
- 2510.03847 — "SLMs for Agentic Systems: A Survey"
- 2412.12039 — "Can LLM Prompting Serve as a Proxy for Static Analysis"
- 2602.05868 — "Persistent Human Feedback, LLMs, and Static Analyzers"

---

## 16. Implementation Notes

- Development target: Darwin/arm64; CI target: Darwin/arm64 + Linux/amd64.
  No Windows-specific assumptions are baked in.
- All file I/O stays inside the project root by convention; the cache lives
  under `os.UserCacheDir()/wfguard`.
- For testing scans, prefer a small synthetic vulnerable workflow under
  `testdata/vulnerable/` over pulling arbitrary public repos.
- When iterating on the system prompt (`internal/llm/system.md`), also add
  or update a corresponding `testdata/` example that demonstrates the
  prompt change is needed.
- Don't add new tools to the agent without first considering whether the
  work could be done deterministically in Go. Tools are expensive (latency,
  token cost, potential model mistakes); deterministic checks are cheap.
- Don't mark TODOs as done without a passing test.
- **Signal over noise.** Default `--min-severity high` means a baseline
  scan only renders findings with real exploit paths. Hygiene rules
  (`unpinned-action`, missing `permissions:` block) compute findings that
  the LLM agent can use as context, but they don't surface to the user
  unless explicitly opted into via `--min-severity low`. This is what
  separates wfguard from "every CI scanner that yells about everything".
- **Hardening is opt-in via `--harden`.** When set, the LLM is asked to
  produce a corrected version of each workflow file with visible findings.
  We diff it against the original and emit a unified patch (`report.patch`).
  The fixer is a separate prompt from the audit agent — strict "output
  only YAML" instructions, temperature 0, validated by re-parsing as YAML
  before inclusion. Per-file failures are logged and skipped; the
  composed patch contains only successful, diff-producing fixes.

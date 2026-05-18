# wfguard

> Audit GitHub Actions workflows for supply-chain attack patterns,
> powered by **Google Gemma 4** for cross-file taint analysis.

`wfguard` combines a fast, deterministic rules pass over your workflow YAML
with an LLM agent loop that reasons about *patterns* — the kind of multi-hop
"this PR-controlled input flows into that shell exec" analysis a regex can't
catch but a long-context language model can.

## About this project

This is a submission to the [**Gemma 4 Challenge — Build with Gemma 4**](https://dev.to/devteam/join-the-gemma-4-challenge-3000-prize-pool-for-ten-winners-23in)
on dev.to. The agent loop is built **specifically around Gemma 4** (`gemma-4-31b-it`
by default), and the project is designed to demonstrate the model-selection
trade-offs across the Gemma 4 family: E4B (small, fast), 26B-A4B (MoE),
and 31B Dense (the strongest reasoning, used as the primary).

You can run it two ways:

- **Hosted Gemini API** — uses `gemma-4-31b-it` over `google.golang.org/genai`. Best results, paid.
- **Local LLM** — uses any OpenAI-compatible server (LM Studio, vLLM, llama.cpp's openai server). Free, slower, smaller models.

The rule taxonomy, design rationale, and 14-day implementation plan live in [DESIGN.md](./DESIGN.md).

---

## Quick start

```bash
git clone https://github.com/nshekhawat/wfguard.git
cd wfguard
go mod tidy
make build      # produces bin/wfguard
```

Pick a backend and verify it's reachable.

### Option A — Gemini API (default)

1. Get a key at <https://aistudio.google.com/apikey>.
2. Drop it into `.env` (auto-loaded by the binary at startup):

   ```bash
   cp .env.example .env
   $EDITOR .env     # paste GEMINI_API_KEY=...
   ```

3. Smoke-test:

   ```bash
   make smoke
   # → "OK — model reachable."
   ```

### Option B — Local LLM via LM Studio

1. Install [LM Studio](https://lmstudio.ai/), download a Gemma 4 build (e.g. `gemma-4-e4b-it-mlx`), and click **Start Server** (defaults to port 1234).
2. Confirm the server is up:

   ```bash
   curl -s http://localhost:1234/v1/models
   ```

3. Smoke-test wfguard against it (replace the model id with whatever LM Studio shows for `id`):

   ```bash
   ./bin/wfguard smoke --backend openai --model gemma-4-e4b-it-mlx
   # → "OK — model reachable."
   ```

The same `--backend openai` works for any OpenAI-compatible endpoint:
**vLLM**, **llama.cpp**'s `llama-server`, etc. Set `--openai-base-url` to the server's `/v1` URL.

---

## Run a scan

The deterministic rules pass needs no API access; the LLM agent loop is opt-in via `--llm`.

```bash
# Deterministic pass only (fast, free, no LLM)
./bin/wfguard scan /path/to/some/repo

# Full agent loop using hosted Gemma 4 31B (the canonical mode)
./bin/wfguard scan /path/to/some/repo --llm

# Full agent loop using local Gemma 4 via LM Studio
./bin/wfguard scan /path/to/some/repo \
  --llm --backend openai --model gemma-4-e4b-it-mlx

# Emit SARIF for GitHub's code-scanning UI
./bin/wfguard scan /path/to/some/repo --report sarif --output report.sarif

# Emit both formats side-by-side
./bin/wfguard scan /path/to/some/repo --report both -o report
# → writes report.md and report.sarif
```

By default the deterministic pass alone catches the common patterns
(`unpinned-action`, `pwn-request`, `compromised-action`, `broad-permissions`,
`expression-injection`, etc.). `--llm` adds cross-cutting taint analysis on top.

### `scan` command flags

| Flag | Default | Description |
|---|---|---|
| `--report` | `markdown` | Output format: `markdown` \| `sarif` \| `both` |
| `--output, -o` | stdout (md), `report.sarif` (sarif) | Output file path. With `--report both`, writes `<output>.md` and `<output>.sarif` |
| `--llm` | `false` | Run the LLM agent loop after the deterministic rules pass (extra audit findings) |
| `--harden` | `false` | After the scan, ask Gemma 4 to generate per-file fixes for visible findings; writes a unified patch you can `git apply` |
| `--backend` | `gemini` | LLM backend: `gemini` or `openai` (LM Studio / vLLM / etc.) |
| `--model` | `gemma-4-31b-it` (or `$WFGUARD_MODEL`) | Model id. For `openai`, set this to whatever your local server shows |
| `--openai-base-url` | `http://localhost:1234/v1` | OpenAI-compatible base URL |
| `--openai-api-key` | `$OPENAI_API_KEY` | Optional — LM Studio doesn't require it |
| `--max-steps` | `15` | Max agent loop iterations per trigger surface |
| `--min-severity` | `high` | Rendering / exit-code threshold: `critical` \| `high` \| `medium` \| `low`. Findings below this level are computed (and visible to the LLM agent as context) but not surfaced |
| `--soft-fail` | `false` | Always exit 0. Default exits 1 if any finding lands at or above `--min-severity` |

### `smoke` command flags

Sends a tiny request to verify the chosen backend is reachable.
Same `--backend`, `--model`, `--openai-base-url`, `--openai-api-key` flags as `scan`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan ran. Either no findings, or only `medium` / `low` |
| `1` | Scan ran and produced at least one `high` or `critical` finding (suppress with `--soft-fail`) |
| non-zero, no report written | Setup or API error (missing API key, malformed `--report` value, etc.) |

---

## What gets detected

Each finding has a severity (`critical` → `low`), a kind, a location, and a
concrete fix. wfguard's design bias is **signal over noise** — by default
(`--min-severity high`), only findings with real exploit paths are rendered.
The deterministic rules cover:

- **`pwn-request`** *(critical)* — `pull_request_target` + checkout of PR HEAD
- **`expression-injection`** *(critical/high)* — `${{ github.event.* }}` flowing into shell, direct or via env vars
- **`compromised-action`** *(high)* — references to actions on the known-compromised list (e.g. `tj-actions/changed-files`)
- **`secrets-exposure`** *(high)* — `secrets.*` passed to an unpinned third-party action
- **`self-hosted-runner-pr`** *(high)* — self-hosted runner reachable from fork PRs
- **`reusable-workflow-input-injection`** *(high)* — `${{ inputs.* }}` interpolated into `run:` in a `workflow_call`
- **`unpinned-action`** *(medium)* — mutable tags / branches **for unverified publishers** or actions with a known compromise history. Hidden by default. (The "pin everything" advice is correct in theory but mostly noise on real repos — `actions/checkout@v4` from a verified org isn't worth a finding. Use `--min-severity low` to see them.)
- **`broad-permissions`** *(medium/low)* — explicit `permissions: write-all` (medium) or missing `permissions:` block (low; mostly silenced by GitHub's modern read-only default). Hidden by default.

The LLM agent adds (when `--llm` is set):

- Cross-step taint analysis the rules can't express (e.g. `$GITHUB_REF` flowing into `sed`)
- Action-source review (fetches the action's `action.yml` + entry script and reasons about it)
- Severity calls that depend on the workflow's overall trigger surface

See [DESIGN.md §11](./DESIGN.md) for the full taxonomy and example payloads.

---

## Hardening — auto-generate the fix

`--harden` turns wfguard from "here's what's wrong" into "here's the patch — apply it". For every visible finding, Gemma 4 produces a corrected version of the workflow file; we diff it against the original and emit a `git apply`-compatible unified patch.

```bash
./bin/wfguard scan /path/to/repo --harden -o report
# writes:
#   report.md       (the audit findings)
#   report.patch    (one unified diff covering every file with a fix)

cd /path/to/repo
git apply /tmp/report.patch
git diff               # see exactly what changed
git commit -m "wfguard: harden workflows"
```

Per-file failures (LLM declined, output didn't parse as YAML, no diff) are logged and skipped — they don't kill the rest of the patch. The model only operates on visible findings, so combined with `--min-severity high` (default), the LLM is never burning cycles on hygiene noise.

**Standard mitigations the model is instructed to apply**:
- `pwn-request` → switch trigger to `pull_request` (drops secrets from scope) or remove the explicit checkout of PR HEAD
- `expression-injection` (direct or via env) → bind to an `env:` var, reference `"$VAR"` with hard quoting
- `secrets-exposure` → pin the action to a 40-char SHA
- `self-hosted-runner-pr` → switch to `ubuntu-latest`, or gate on `head.repo.full_name == github.repository`
- `reusable-workflow-input-injection` → env-var indirection in the run body

**Model-selection note**: smaller Gemma variants (E4B) can occasionally over-edit (e.g. drop unrelated comments while applying the security fix). Gemma 4 31B is more conservative and recommended for production hardening; E4B is fine for a quick local pass. This trade-off is exactly what the project's writeup is about.

---

## Reports

- **Markdown** — bucketed by severity, one section per finding with evidence + fix. Default format; goes to stdout unless `-o` is set.
- **SARIF** — SARIF 2.1.0, ready to upload to GitHub's code-scanning UI:

   ```yaml
   # .github/workflows/wfguard.yml
   - run: ./bin/wfguard scan . --report sarif --output report.sarif --soft-fail
   - uses: github/codeql-action/upload-sarif@<sha>
     with:
       sarif_file: report.sarif
   ```

---

## Environment variables

All of these can be set in `.env` (loaded automatically; never committed):

| Var | Used by | Notes |
|---|---|---|
| `GEMINI_API_KEY` | Gemini backend | Required for `--llm` with the default backend |
| `GITHUB_TOKEN` | Resolver | Personal access token, scope `public_repo` (or `repo` for private). Without it, anonymous GitHub API rate limits apply (~60 req/hr) |
| `OPENAI_API_KEY` | OpenAI backend | Optional — LM Studio doesn't require one |
| `WFGUARD_MODEL` | both | Default model id for `--model`. Useful if you always want a non-default model |
| `WFGUARD_LOG_LEVEL` | logging | `debug` \| `info` \| `warn` \| `error`. Default `info` |

---

## Development

```bash
make build       # go build -o bin/wfguard ./cmd/wfguard
make test        # go test ./... -race -count=1
make lint        # go vet ./... && go fmt ./...
make smoke       # end-to-end model reachability check
make scan-self   # scan this repo's own workflows
```

Coverage runs at ~85% on the logic-heavy packages (rules, ingest, resolver, report, findings, workflow) and ~72% on the LLM glue. See [DESIGN.md](./DESIGN.md) for the architecture.

---

## License

Apache-2.0. (Same as Gemma 4.)

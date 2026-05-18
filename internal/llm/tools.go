package llm

// ToolDecls returns the seven function-calling declarations the agent
// exposes. The shape is backend-neutral; gemini.go and openai.go translate
// to their respective schemas at request time.
//
// Design rule (DESIGN.md §6): submit_finding is the ONLY way the agent
// records output. Anything the model says outside of a tool call is
// discarded. There is no done() tool; the loop terminates when the model
// returns a turn with no tool calls.
func ToolDecls() []ToolDecl {
	return []ToolDecl{
		{
			Name: "list_workflows",
			Description: "Returns the names of every workflow file in the repo " +
				"and their `on:` triggers. Call this once at the start to orient.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name: "get_workflow",
			Description: "Returns the parsed structure of one workflow file as JSON: " +
				"its triggers, jobs, steps, and per-step `uses:` and `run:` content.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Workflow file name relative to .github/workflows/, e.g. 'ci.yml'",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			Name: "get_action_source",
			Description: "Fetches the action.yml of a referenced action, plus its " +
				"entry script (dist/index.js for JS actions, the composite steps " +
				"for composite actions, the Dockerfile for container actions).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"uses": map[string]any{
						"type":        "string",
						"description": "The full `uses:` string, e.g. 'actions/checkout@v4' or 'owner/repo/path@sha'",
					},
				},
				"required": []string{"uses"},
			},
		},
		{
			Name: "resolve_reference",
			Description: "Returns metadata about an action reference: whether it is " +
				"pinned to a commit SHA, the resolved SHA, the latest release tag, " +
				"and whether the publisher is verified by GitHub.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"uses": map[string]any{"type": "string"},
				},
				"required": []string{"uses"},
			},
		},
		{
			Name:        "lookup_advisories",
			Description: "Looks up known GitHub Security Advisories for an action.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": map[string]any{
						"type":        "string",
						"description": "Action repo in 'owner/repo' form, e.g. 'tj-actions/changed-files'",
					},
				},
				"required": []string{"action"},
			},
		},
		{
			Name: "trace_expression_flow",
			Description: "Lists every step within a workflow where a given GitHub " +
				"expression appears — as an env var value, an input to an action, or " +
				"inside a `run:` block. Use this for taint analysis.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"workflow": map[string]any{
						"type":        "string",
						"description": "Workflow file name",
					},
					"expr": map[string]any{
						"type":        "string",
						"description": "Expression body, e.g. 'github.event.pull_request.title'",
					},
				},
				"required": []string{"workflow", "expr"},
			},
		},
		{
			Name: "submit_finding",
			Description: "Record an audit finding. This is the ONLY way to produce output. " +
				"Each call appends one finding to the audit report. Be specific — " +
				"include exact file:line locations, quoted YAML evidence, and an " +
				"actionable fix.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": map[string]any{
						"type":        "string",
						"description": "Severity level",
						"enum":        []string{"low", "medium", "high", "critical"},
					},
					"kind": map[string]any{
						"type": "string",
						"description": "Finding kind, e.g. 'unpinned-action', 'expression-injection', " +
							"'pwn-request', 'compromised-action', 'secrets-leak', 'broad-permissions'",
					},
					"location": map[string]any{
						"type":        "string",
						"description": "file:line, or workflow:job:step path",
					},
					"evidence": map[string]any{
						"type":        "string",
						"description": "Quoted YAML or code excerpt showing the issue",
					},
					"fix": map[string]any{
						"type":        "string",
						"description": "Concrete remediation (1-3 sentences)",
					},
				},
				"required": []string{"severity", "kind", "location", "evidence", "fix"},
			},
		},
	}
}

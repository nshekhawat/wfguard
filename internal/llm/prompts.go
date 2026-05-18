package llm

import _ "embed"

// SystemPrompt is the system instruction sent to Gemma 4 at the start of
// every audit session. Source of truth lives in prompts/system.md so it can
// be edited without recompiling deeply nested escape sequences.
//
//go:embed system.md
var SystemPrompt string

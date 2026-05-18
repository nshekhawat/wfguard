// Package workflow defines typed Go representations of GitHub Actions
// workflow YAML.
//
// These structs cover the surface wfguard needs for supply-chain analysis.
// They intentionally use loose types (`any`, `map[string]any`) for the
// long-tail fields we don't reason about, so unknown YAML doesn't break
// parsing.
package workflow

// Workflow is one parsed .github/workflows/*.yml file.
type Workflow struct {
	// Path of the workflow file on disk, relative to the repo root.
	Path string `yaml:"-"`

	// Name as declared in the YAML, or the file's basename if absent.
	Name string `yaml:"name,omitempty"`

	// On is the trigger config. May be a string ("push"), a list
	// (["push", "pull_request"]), or a map keyed by trigger name.
	On any `yaml:"on,omitempty"`

	// Permissions is either a string ("read-all"|"write-all") or a map
	// from scope name to "read"|"write"|"none".
	Permissions any `yaml:"permissions,omitempty"`

	// Env at the workflow level.
	Env map[string]string `yaml:"env,omitempty"`

	// Jobs map keyed by job id.
	Jobs map[string]*Job `yaml:"jobs,omitempty"`

	// Concurrency, defaults, and so on go in Extra. We don't reason about
	// them today; preserved for fidelity.
	Extra map[string]any `yaml:",inline"`
}

// Job is one job inside a workflow.
type Job struct {
	// ID is the YAML key under jobs:. Filled in after parsing.
	ID string `yaml:"-"`

	Name        string         `yaml:"name,omitempty"`
	RunsOn      any            `yaml:"runs-on,omitempty"` // string or list
	Permissions any            `yaml:"permissions,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
	Needs       any            `yaml:"needs,omitempty"` // string or list
	If          string         `yaml:"if,omitempty"`
	Steps       []*Step        `yaml:"steps,omitempty"`

	// Reusable-workflow form: jobs.<id>.uses
	Uses string         `yaml:"uses,omitempty"`
	With map[string]any `yaml:"with,omitempty"`
	Secrets any         `yaml:"secrets,omitempty"`

	Extra map[string]any `yaml:",inline"`
}

// Step is one step inside a job.
type Step struct {
	// Index is the 0-based index within the parent job's steps.
	// Filled in after parsing.
	Index int `yaml:"-"`

	ID    string `yaml:"id,omitempty"`
	Name  string `yaml:"name,omitempty"`
	If    string `yaml:"if,omitempty"`

	// Either Uses or Run is set, not both.
	Uses string         `yaml:"uses,omitempty"`
	With map[string]any `yaml:"with,omitempty"`
	Run  string         `yaml:"run,omitempty"`

	Shell      string            `yaml:"shell,omitempty"`
	WorkingDir string            `yaml:"working-directory,omitempty"`
	Env        map[string]string `yaml:"env,omitempty"`
	ContinueOnError any          `yaml:"continue-on-error,omitempty"`

	Extra map[string]any `yaml:",inline"`
}

// IsUses reports whether this step invokes another action.
func (s *Step) IsUses() bool { return s.Uses != "" }

// IsRun reports whether this step runs a shell command.
func (s *Step) IsRun() bool { return s.Run != "" }

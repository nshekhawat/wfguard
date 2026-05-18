package llm

import (
	"encoding/json"
	"testing"

	"google.golang.org/genai"
)

// ToolDecls() is the source of truth for tool schemas. Verify each backend
// translation produces well-formed output that round-trips through JSON.

func TestToolDecls_Stable(t *testing.T) {
	decls := ToolDecls()
	if len(decls) != 7 {
		t.Errorf("got %d tool decls, want 7 (per DESIGN.md §6)", len(decls))
	}
	want := map[string]bool{
		"list_workflows":        true,
		"get_workflow":          true,
		"get_action_source":     true,
		"resolve_reference":     true,
		"lookup_advisories":     true,
		"trace_expression_flow": true,
		"submit_finding":        true,
	}
	for _, d := range decls {
		if !want[d.Name] {
			t.Errorf("unexpected tool %q", d.Name)
		}
		delete(want, d.Name)
		if d.Description == "" {
			t.Errorf("tool %q: empty description", d.Name)
		}
		if _, ok := d.Parameters["type"].(string); !ok {
			t.Errorf("tool %q: missing top-level type", d.Name)
		}
	}
	for n := range want {
		t.Errorf("missing tool decl: %q", n)
	}
}

func TestSubmitFindingDecl_HasSeverityEnum(t *testing.T) {
	for _, d := range ToolDecls() {
		if d.Name != "submit_finding" {
			continue
		}
		props := d.Parameters["properties"].(map[string]any)
		sev := props["severity"].(map[string]any)
		enum, _ := sev["enum"].([]string)
		if len(enum) != 4 {
			t.Errorf("severity enum has %d entries, want 4", len(enum))
		}
		want := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		for _, v := range enum {
			delete(want, v)
		}
		if len(want) != 0 {
			t.Errorf("severity enum missing values: %v", want)
		}
		return
	}
	t.Error("submit_finding decl not found")
}

func TestToolsToGemini_TranslatesAllSeven(t *testing.T) {
	gtools := toolsToGemini(ToolDecls())
	if len(gtools) != 1 {
		t.Fatalf("toolsToGemini returned %d Tool wrappers, want 1", len(gtools))
	}
	if got := len(gtools[0].FunctionDeclarations); got != 7 {
		t.Errorf("FunctionDeclarations = %d, want 7", got)
	}
}

func TestToolsToGemini_TranslatesParameterSchema(t *testing.T) {
	decl := ToolDecl{
		Name:        "test",
		Description: "x",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name field",
				},
				"flags": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
				"sev": map[string]any{
					"type": "string",
					"enum": []string{"low", "high"},
				},
			},
			"required": []string{"name"},
		},
	}
	gtools := toolsToGemini([]ToolDecl{decl})
	fn := gtools[0].FunctionDeclarations[0]
	if fn.Parameters.Type != genai.TypeObject {
		t.Errorf("top-level type = %v, want TypeObject", fn.Parameters.Type)
	}
	if got := fn.Parameters.Properties["name"].Type; got != genai.TypeString {
		t.Errorf("name.type = %v, want TypeString", got)
	}
	if got := fn.Parameters.Properties["flags"].Type; got != genai.TypeArray {
		t.Errorf("flags.type = %v, want TypeArray", got)
	}
	if got := fn.Parameters.Properties["flags"].Items.Type; got != genai.TypeString {
		t.Errorf("flags.items.type = %v, want TypeString", got)
	}
	enum := fn.Parameters.Properties["sev"].Enum
	if len(enum) != 2 || enum[0] != "low" || enum[1] != "high" {
		t.Errorf("enum = %v", enum)
	}
	if len(fn.Parameters.Required) != 1 || fn.Parameters.Required[0] != "name" {
		t.Errorf("required = %v", fn.Parameters.Required)
	}
}

func TestToolsToGemini_RequiredFromAnySlice(t *testing.T) {
	decl := ToolDecl{
		Name: "t",
		Parameters: map[string]any{
			"type":     "object",
			"required": []any{"a", "b"}, // post-JSON-roundtrip shape
		},
	}
	gtools := toolsToGemini([]ToolDecl{decl})
	got := gtools[0].FunctionDeclarations[0].Parameters.Required
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("required from []any = %v", got)
	}
}

func TestStringSliceFromAny(t *testing.T) {
	if got := stringSliceFromAny(nil); got != nil {
		t.Errorf("nil input -> %v, want nil", got)
	}
	if got := stringSliceFromAny([]string{"x", "y"}); len(got) != 2 || got[0] != "x" {
		t.Errorf("[]string passthrough failed: %v", got)
	}
	if got := stringSliceFromAny([]any{"a", 7, "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("[]any partial filter failed: %v", got)
	}
	if got := stringSliceFromAny("not a slice"); got != nil {
		t.Errorf("non-slice input -> %v, want nil", got)
	}
}

func TestToolsToOpenAI_Shape(t *testing.T) {
	tools := toolsToOpenAI(ToolDecls())
	if len(tools) != 7 {
		t.Errorf("toolsToOpenAI returned %d, want 7", len(tools))
	}
	for _, tw := range tools {
		if tw.Type != "function" {
			t.Errorf("tool type = %q, want 'function'", tw.Type)
		}
		if tw.Function.Name == "" {
			t.Error("empty function name")
		}
		if _, ok := tw.Function.Parameters["type"].(string); !ok {
			t.Errorf("tool %q: parameters missing 'type'", tw.Function.Name)
		}
	}
}

func TestToolsToOpenAI_SerializesToValidJSON(t *testing.T) {
	bs, err := json.Marshal(toolsToOpenAI(ToolDecls()))
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip and check length is sane.
	var back []map[string]any
	if err := json.Unmarshal(bs, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 7 {
		t.Errorf("round-tripped %d tools, want 7", len(back))
	}
}

func TestToMap_Variants(t *testing.T) {
	if got := toMap(nil); len(got) != 0 {
		t.Errorf("nil -> %v, want empty map", got)
	}
	if got := toMap(map[string]any{"a": 1}); got["a"] != 1 {
		t.Errorf("map passthrough lost value: %v", got)
	}
	// struct serializes to a map
	type s struct {
		X int `json:"x"`
	}
	got := toMap(s{X: 3})
	if v, _ := got["x"].(float64); v != 3 {
		t.Errorf("struct -> map.x = %v, want 3", got["x"])
	}
	// scalar wraps under "value"
	got = toMap(42)
	if _, ok := got["value"]; !ok {
		t.Errorf("scalar should wrap under 'value', got %v", got)
	}
}

package intercept

import (
	"encoding/json"
	"strings"
	"testing"
)

// The judge prompt is English now, so the English comment shape is the main
// path. prompt_test.go keeps the Chinese shape as the legacy path.
func TestParseVerdictEnglishShape(t *testing.T) {
	valid := `{"decision":"allow","comment":"Action: read the file; Consequence: returns its content; Rule: A5"}`
	if got := ParseVerdict(valid); got.Action != "allow" || !strings.HasSuffix(got.Reason, "Rule: A5") {
		t.Fatalf("english verdict rejected: %+v", got)
	}
	deny := `{"decision":"deny","comment":"Action: delete a production file; Consequence: business data is lost; Rule: D4"}`
	if got := ParseVerdict("```json\n" + deny + "\n```"); got.Action != "deny" {
		t.Fatalf("fenced english verdict lost: %+v", got)
	}
	for _, reply := range []string{
		strings.Replace(valid, "Action: read the file", "Action: ", 1),
		strings.Replace(valid, "Consequence: returns its content", "Consequence: ", 1),
		strings.Replace(valid, "Rule: A5", "Rule: ", 1),
		strings.Replace(valid, "; Rule: A5", "", 1),
		valid + "\nI also suggest a manual review.",
	} {
		if got := ParseVerdict(reply); got.Action != "" {
			t.Errorf("accepted incomplete english verdict: %q => %+v", reply, got)
		}
	}
	reason := "Action: " + strings.Repeat("write report ", 30) + "; Consequence: only saves the file; Rule: A2"
	raw, _ := json.Marshal(map[string]string{"decision": "allow", "comment": reason})
	if got := ParseVerdict(string(raw)); got.Reason != reason {
		t.Fatal("english explanation was truncated or lost its rule")
	}
}

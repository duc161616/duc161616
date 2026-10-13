// Command validate-rules compiles every intercept-rule pattern with Go's
// regexp package and checks the enum fields.
//
// This exists because ARTEX matches rules with Go's regexp (RE2, see
// intercept/intercept.go:545), which rejects Perl constructs that Python and
// PCRE accept — lookahead above all. A rule whose pattern does not compile is
// a rule that never fires, which on a live engagement means a gate you believe
// is protecting you and is not. Run this after every edit:
//
//	go run ./bbkit/validate-rules bbkit/intercept-rules.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type rule struct {
	Name          string `json:"name"`
	Pattern       string `json:"pattern"`
	MatchTarget   string `json:"match_target"`
	MatchType     string `json:"match_type"`
	Action        string `json:"action"`
	TimeoutAction string `json:"timeout_action"`

	// ShouldMatch and ShouldNotMatch are the rule's own test corpus. A gate
	// that compiles but does not fire is as useless as one that does not
	// compile, and a gate that fires on ordinary commands gets disabled by
	// the operator within an hour — so both directions are checked.
	ShouldMatch    []string `json:"should_match"`
	ShouldNotMatch []string `json:"should_not_match"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-rules <rules.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var doc struct {
		Rules []rule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(2)
	}
	if len(doc.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "no rules found")
		os.Exit(2)
	}

	oneOf := func(v string, allowed ...string) bool {
		for _, a := range allowed {
			if v == a {
				return true
			}
		}
		return false
	}

	bad := 0
	for _, r := range doc.Rules {
		var problems []string
		var re *regexp.Regexp
		if r.MatchType == "regex" {
			var err error
			if re, err = regexp.Compile(r.Pattern); err != nil {
				problems = append(problems, "pattern does not compile with RE2: "+err.Error())
			}
		}
		if re != nil {
			for _, s := range r.ShouldMatch {
				if !re.MatchString(s) {
					problems = append(problems, "should have matched but did not: "+s)
				}
			}
			for _, s := range r.ShouldNotMatch {
				if re.MatchString(s) {
					problems = append(problems, "false positive on an ordinary command: "+s)
				}
			}
		}
		if len(r.ShouldMatch) == 0 {
			problems = append(problems, "no should_match samples: this rule is untested")
		}
		if !oneOf(r.MatchTarget, "tool_name", "tool_input") {
			problems = append(problems, "match_target must be tool_name or tool_input, got "+r.MatchTarget)
		}
		if !oneOf(r.MatchType, "regex", "contains") {
			problems = append(problems, "match_type must be regex or contains, got "+r.MatchType)
		}
		if !oneOf(r.Action, "allow", "deny", "ask") {
			problems = append(problems, "action must be allow, deny or ask, got "+r.Action)
		}
		if !oneOf(r.TimeoutAction, "deny", "allow") {
			problems = append(problems, "timeout_action must be deny or allow, got "+r.TimeoutAction)
		}
		if len(problems) == 0 {
			fmt.Printf("ok    %s\n", r.Name)
			continue
		}
		bad++
		fmt.Printf("FAIL  %s\n", r.Name)
		for _, p := range problems {
			fmt.Printf("      %s\n", p)
		}
	}
	fmt.Printf("\n%d/%d rules valid\n", len(doc.Rules)-bad, len(doc.Rules))
	if bad > 0 {
		os.Exit(1)
	}
}

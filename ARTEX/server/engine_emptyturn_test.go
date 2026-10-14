package server

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// 空转回合(仅思考、无正文无工具)的识别与续跑，见 steerHooks.Stop。

func assistantThinking(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: text, Signature: "sig"},
	}}
}

func TestIsThinkingOnlyTurn(t *testing.T) {
	toolUse := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "scan ports first"},
		{Type: llm.BlockToolUse, ID: "t1", Name: "run_nuclei"},
	}}
	cases := []struct {
		name string
		msgs []llm.Message
		want bool
	}{
		{"reasoning only", []llm.Message{llm.UserText("start"), assistantThinking("let me think")}, true},
		{"reasoning + tool", []llm.Message{llm.UserText("start"), toolUse}, false},
		{"reasoning + text", []llm.Message{assistantThinking("let me think"), {
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("conclusion")},
		}}, false},
		{"text is only whitespace", []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("  \n ")},
		}}, true},
		{"completely empty assistant turn", []llm.Message{{Role: llm.RoleAssistant}}, true},
		// 工具结果是 user 角色，判定必须回溯到它前面那条 assistant，而不是就近误判。
		{"last message is a tool result", []llm.Message{toolUse, {
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "t1"}},
		}}, false},
		{"no assistant message", []llm.Message{llm.UserText("start")}, false},
		{"empty history", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isThinkingOnlyTurn(c.msgs); got != c.want {
				t.Fatalf("isThinkingOnlyTurn = %v, want %v", got, c.want)
			}
		})
	}
}

// fakeHooks 是一个可编程的 inner HookRunner，用来验证 steerHooks 对 inner 决定的尊重。
type fakeHooks struct {
	prevent  bool
	blocking []string
	msg      string
}

func (f fakeHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (f fakeHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (f fakeHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return f.prevent, f.blocking, f.msg
}

func TestSteerHooksStopNudgesEmptyTurn(t *testing.T) {
	empty := []llm.Message{assistantThinking("I should enumerate subdomains first")}

	t.Run("idle turn injects a continue instruction", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges, label: "worker-1 · #1"}
		prevent, blocking, _ := h.Stop(context.Background(), empty)
		if prevent {
			t.Fatal("an idle turn should not hard-stop")
		}
		if len(blocking) != 1 || blocking[0] != emptyTurnNudge {
			t.Fatalf("blocking = %v, want [emptyTurnNudge]", blocking)
		}
	})

	t.Run("no intervention when there is text or a tool", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		normal := []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("scan finished, no open ports found")},
		}}
		if _, blocking, _ := h.Stop(context.Background(), normal); blocking != nil {
			t.Fatalf("a normal ending was misjudged as an idle turn: %v", blocking)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("should not count when not intervening, got %d", n)
		}
	})

	t.Run("allows ending once the limit is reached", func(t *testing.T) {
		const limit = 5 // 用户把「空响应重试次数」配成 5
		h := steerHooks{nudges: &atomic.Int64{}, limit: limit}
		for i := 1; i <= limit; i++ {
			if _, blocking, _ := h.Stop(context.Background(), empty); len(blocking) != 1 {
				t.Fatalf("attempt %d should still be within quota, blocking = %v", i, blocking)
			}
		}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting past the limit: %v", blocking)
		}
	})

	// 「空响应重试次数」配 -1 = 关掉这层，emptyTurnNudgeLimit 解析成 0。
	t.Run("no intervention when the config is off", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: 0}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting after being turned off: %v", blocking)
		}
	})

	t.Run("no stacking when inner decides a hard stop", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{prevent: true, msg: "guard refused to end"}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		prevent, blocking, msg := h.Stop(context.Background(), empty)
		if !prevent || msg != "guard refused to end" || blocking != nil {
			t.Fatalf("inner's hard stop was rewritten: prevent=%v blocking=%v msg=%q", prevent, blocking, msg)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("yielding to inner should not consume quota, got %d", n)
		}
	})

	t.Run("no stacking when inner already wants to continue", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{blocking: []string{"guard's reason to continue"}}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		_, blocking, _ := h.Stop(context.Background(), empty)
		if len(blocking) != 1 || blocking[0] != "guard's reason to continue" {
			t.Fatalf("inner's continue message was rewritten: %v", blocking)
		}
	})

	t.Run("behavior unchanged without a counter installed", func(t *testing.T) {
		h := steerHooks{limit: defaultEmptyTurnNudges} // 例如未来其他调用点忘了传 nudges
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("should not inject without a counter: %v", blocking)
		}
	})
}

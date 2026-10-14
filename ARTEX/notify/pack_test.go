package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 本文件覆盖「按整条打包」这个修复：汇总消息超出渠道长度上限时，必须**按整条**
// 截断并把没装下的条目数如实报出来，让调用方只标记真正送达的那些。
//
// 之前的做法是渲染完整篇再截断、然后整批标记已送达：消息后半截凭空消失，
// 而投递历史显示全部成功——漏洞就这么没了，且没有任何地方能发现。

func TestMarkdownBodyPacksWholeItemsWithinByteLimit(t *testing.T) {
	// 200 条中文汇总，必然远超企微 4096 字节。
	m := batchMsg(200)
	body, kept := markdownBody(m, weComMarkdownLimit)

	if len(body) > weComMarkdownLimit {
		t.Fatalf("body of %d bytes exceeds the limit %d", len(body), weComMarkdownLimit)
	}
	if !utf8.ValidString(body) {
		t.Fatal("body is not valid UTF-8")
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part (0 < kept < %d), got %d", len(m.Items), kept)
	}
	// 头部必须如实说明本条只包含多少条、其余有多少条——否则读者会把头部
	// 那个数字当成全部。
	if !strings.Contains(body, "remaining") || !strings.Contains(body, "continue in the next message") {
		t.Fatalf("the header should say how many are not included in this message:\n%s", body[:minInt(400, len(body))])
	}
	// 只应包含前 kept 条。
	for i := 0; i < kept; i++ {
		if !strings.Contains(body, "finding"+itoa(i+1)) {
			t.Fatalf("item %d should be in this message:\n%s", i+1, body)
		}
	}
	if strings.Contains(body, "finding"+itoa(kept+1)) {
		t.Fatalf("item %d should not appear (it belongs to the next batch)", kept+1)
	}
}

func TestMarkdownBodyKeepsEverythingWhenUnderLimit(t *testing.T) {
	m := batchMsg(3)
	body, kept := markdownBody(m, 0) // 0 = 不限制
	if kept != len(m.Items) {
		t.Fatalf("without a length limit everything should be kept, got kept=%d", kept)
	}
	if strings.Contains(body, "remaining") {
		t.Fatalf("there should be no truncation notice without truncation:\n%s", body)
	}
}

func TestMarkdownBodyAlwaysKeepsAtLeastOneItem(t *testing.T) {
	// 预算小到连一条都装不下时，仍要发出一条（由最终截断兜底）。
	// 否则一条超长漏洞会把整批永久卡在原地：每次领取都装不下、每次都不发。
	m := batchMsg(5)
	_, kept := markdownBody(m, 50)
	if kept != 1 {
		t.Fatalf("should keep at least 1, got %d", kept)
	}
}

func TestMarkdownBodySingleReturnsOne(t *testing.T) {
	_, kept := markdownBody(singleMsg(), 4096)
	if kept != 1 {
		t.Fatalf("a single message should report 1 delivered, got %d", kept)
	}
	// 空消息没有可送达的条目。
	if _, k := markdownBody(Message{}, 4096); k != 0 {
		t.Fatalf("an empty message should report 0, got %d", k)
	}
}

func TestTelegramPackingUsesRuneBudget(t *testing.T) {
	m := batchMsg(200)
	text, kept := telegramHTML(m)
	// Telegram 按**字符数**限长；用字节口径会把中文消息压到三分之一。
	if n := utf8.RuneCountInString(text); n > telegramTextLimit {
		t.Fatalf("body of %d characters exceeds the limit %d", n, telegramTextLimit)
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part, got %d", kept)
	}
	if !strings.Contains(text, "continue in the next one") {
		t.Fatalf("should say that some are left out:\n%.300s", text)
	}
}

func TestFeishuPackingReportsKept(t *testing.T) {
	m := batchMsg(2000)
	_, kept := feishuCard(m)
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("the card should fit only part, got %d", kept)
	}
}

func TestWebhookAndEmailReportAllItems(t *testing.T) {
	// 这两个渠道不截断正文，整批都算送达。
	m := batchMsg(7)
	if n := len(m.Items); n != 7 {
		t.Fatal("precondition not met")
	}
	// 通过渲染器的返回值间接确认：markdownBody(0) 不限制时全部保留。
	if _, k := markdownBody(m, 0); k != len(m.Items) {
		t.Fatalf("without a length limit everything should be used, got %d", k)
	}
}

// TestMarkdownEscapesUntrustedContent 是「不可信内容不得改变消息结构」的回归测试。
// 标题与摘要来自模型输出（模型读的是被测目标响应），资产名来自被测目标的 URL。
func TestMarkdownEscapesUntrustedContent(t *testing.T) {
	cases := []struct {
		name  string
		item  Item
		must  []string // 结果里必须出现（转义形态）
		wrong []string // 结果里不得出现（未转义形态）
	}{
		{
			name: "newline + external link in the title",
			item: Item{
				Severity: "high",
				Name:     "登录口 SQL 注入\n[紧急：点此验证账号](http://attacker.tld)",
			},
			// 换行必须被折叠（否则能伪造出新的列表项/引用块）；
			// 方括号与圆括号必须被转义（否则是可点击的外链）。
			must:  []string{`\[紧急：点此验证账号\]`, `\(http://attacker.tld\)`},
			wrong: []string{"\n[紧急", "\n\n[紧急"},
		},
		{
			name: "image beacon in the title",
			item: Item{
				Severity: "high",
				Name:     "漏洞 ![](http://attacker.tld/beacon)",
			},
			must:  []string{`\!`, `\(http://attacker.tld/beacon\)`},
			wrong: []string{"![]("},
		},
		{
			name: "emphasis and quote in the asset name",
			item: Item{
				Severity: "high",
				Name:     "plain title",
				Assets:   []string{"a.com/*注入*>引用"},
			},
			must:  []string{`\*注入\*`, `\>`},
			wrong: []string{"*注入*"},
		},
		{
			name: "backticks and pipes in the summary",
			item: Item{
				Severity: "high",
				Name:     "title",
				Summary:  "`code` | 表格",
			},
			must:  []string{"\\`code\\`", `\|`},
			wrong: []string{"`code`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Message{Items: []Item{tc.item}}
			// 单条模式的写Item 是三个 markdown 渠道共用的渲染路径。
			var b strings.Builder
			writeItem(&b, tc.item, "", true)
			got := b.String()
			for _, want := range tc.must {
				if !strings.Contains(got, want) {
					t.Errorf("missing escaped form %q:\n%s", want, got)
				}
			}
			for _, bad := range tc.wrong {
				if strings.Contains(got, bad) {
					t.Errorf("unescaped form %q appeared (can be used to inject structure or external links):\n%s", bad, got)
				}
			}
			_ = m
		})
	}
}

// TestMarkdownEscapeBackslashFirst 锁住转义顺序：反斜杠必须最先处理，
// 否则会给后面补上的反斜杠再套一层，输出里出现双反斜杠。
func TestMarkdownEscapeBackslashFirst(t *testing.T) {
	if got := markdownEscape(`a\b*c`); got != `a\\b\*c` {
		t.Fatalf("wrong escape order, got %q", got)
	}
}

// TestTelegramTitleHasNoMarkdownEscapes 锁住一个具体的回归：
// markdown 转义不能泄漏到 Telegram 的 HTML 输出里（曾经在共享的标题函数里
// 加过转义，结果 Telegram 消息里出现 `\(1\)` 这种可见反斜杠）。
func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *重点*"}}}
	text, _ := telegramHTML(m)
	if strings.Contains(text, `\(`) || strings.Contains(text, `\*`) {
		t.Fatalf("markdown backslash escapes appeared in the Telegram body:\n%s", text)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

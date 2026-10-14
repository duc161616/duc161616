package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// 本文件锁住通用 Webhook 模板的**能力边界**。
//
// 这是全包唯一「用户提供的字符串会被当代码求值」的地方，所以要明确它能做什么、
// 不能做什么，并用测试把这些性质固定下来——否则将来有人顺手给模板上下文加个
// 方法、或在 FuncMap 里加个 readFile，能力面就静默扩大了，而 diff 看起来
// 只是一个无害的小函数。

// TestTemplateContextHasNoMethods 是最重要的一条。
//
// text/template 会调用导出方法（{{.Foo}} 既能取字段也能调方法）。所以模板上下文
// 只要能接触到**任何**带导出方法的类型，就等于把那些方法暴露给了模板作者。
// 本功能的上下文刻意全是纯数据（只有导出字段、零方法）。
//
// 若这条失败：说明有人给 webhookTemplateData / webhookItem 加了方法。
// 在决定放行之前，先想清楚那个方法能不能被模板用来读取不希望暴露的东西。
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which hands those methods' capabilities to template authors", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal 锁住暴露给模板的函数集合。
//
// FuncMap 里每多一个函数就多一项能力。当前只有 json / jsons，作用是把值序列化
// 成 JSON 片段——不能读文件、不能发请求、不能执行命令。
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the template function set changed: got %v, want %v. Before adding a function, make sure it does not widen the capability surface"+
			" (cannot read/write files, make network requests or run commands)", got, want)
	}
}

// TestTemplateCannotReachUnknownData 覆盖模板里的越界访问：
// 访问不存在的东西必须失败，而不是回显点什么；且失败信息不得带出内部数据。
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a nonexistent field should be an error")
	}
	// 错误里不能出现模板上下文里的真实内容（漏洞标题/摘要）。
	for _, leak := range []string{"SQL injection", "parameter id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently 模板写错属于配置错误，重试不会自愈。
// 若被判成可重试，一条坏模板会让每次投递都白跑三轮退避。
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("template syntax errors should be blocked at save time")
	}
	// 即便绕过校验直接投递，也必须判永久失败而不是反复重试。
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a broken template should be judged a permanent failure, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON 覆盖「模板渲染结果必须是合法 JSON」这条约束。
// 它顺带挡住了「用模板生成纯文本去触发别的协议」这类用法。
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// 合法模板能过。
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// 渲染出非 JSON 时必须拒绝（而不是原样发出去）。
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("rendering non-JSON should be judged a permanent failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("error message should say it is a JSON problem, got %v", err)
	}
}

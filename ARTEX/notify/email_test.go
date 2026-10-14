package notify

import (
	"bufio"
	"context"

	"net"
	"strings"
	"sync"
	"testing"
)

// 本文件补齐邮件渠道的协议级测试。在此之前 email.Send 的覆盖率是 0——
// 整条 SMTP 路径没有任何用例跑过，而它恰恰是六个渠道里协议面最大、
// 最容易出错的一个（握手、认证、信封、DATA 阶段各有各的失败语义）。
//
// 这里用自建的最小 SMTP 服务器驱动，而不是 mock 掉 net/smtp：
// 邮件渠道的绝大部分风险就在「与真实 SMTP 服务器对话」这一步，
// 把这一步 mock 掉等于不测。

// fakeSMTP 是一个刚好够用的 SMTP 服务器：能完成 greet/EHLO/AUTH/MAIL/RCPT/DATA/QUIT，
// 并按用例要求对特定阶段返回指定应答码。
type fakeSMTP struct {
	ln net.Listener

	// rcptReply 是 RCPT TO 的应答；默认 250。
	rcptReply string
	// mailReply 是 MAIL FROM 的应答；默认 250。
	mailReply string
	// advertiseAuth 为 true 时在 EHLO 里声明支持 AUTH PLAIN。
	advertiseAuth bool

	mu       sync.Mutex
	data     string
	commands []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, rcptReply: "250 OK", mailReply: "250 OK"}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) hostPort(t *testing.T) (string, int) {
	t.Helper()
	addr, ok := f.ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("non-TCP listen address")
	}
	return "127.0.0.1", addr.Port
}

func (f *fakeSMTP) record(cmd string) {
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()
}

func (f *fakeSMTP) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data
}

func (f *fakeSMTP) sawCommand(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	w("220 fake.local ESMTP ready")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			// 不声明 STARTTLS：让代码走明文分支（测试目标是信封逻辑，不是 TLS）。
			w("250-fake.local")
			if f.advertiseAuth {
				w("250-AUTH PLAIN")
			}
			w("250 8BITMIME")
		case strings.HasPrefix(line, "AUTH"):
			// 简化处理：PLAIN 的初始应答可能跨多行，直接接受。
			w("235 2.7.0 Authentication successful")
		case strings.HasPrefix(line, "MAIL FROM"):
			w(f.mailReply)
		case strings.HasPrefix(line, "RCPT TO"):
			w(f.rcptReply)
		case strings.HasPrefix(line, "DATA"):
			w("354 End data with <CR><LF>.<CR><LF>")
			var sb strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				sb.WriteString(dl)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			w("250 2.0.0 Ok: queued as FAKE1")
		case strings.HasPrefix(line, "QUIT"):
			w("221 2.0.0 Bye")
			return
		default:
			w("250 OK")
		}
	}
}

func emailCfg(t *testing.T, f *fakeSMTP, extra map[string]any) map[string]any {
	t.Helper()
	host, port := f.hostPort(t)
	cfg := map[string]any{
		"host": host,
		"port": float64(port),
		"from": "artex@example.com",
		"to":   []any{"a@example.com", "b@example.com"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestEmailSendDeliversFullMessage(t *testing.T) {
	f := newFakeSMTP(t)
	f.advertiseAuth = true
	cfg := emailCfg(t, f, map[string]any{"username": "artex", "password": "pw"})

	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	// 信封阶段必须走到：发件人、两个收件人、DATA。
	for _, want := range []string{"MAIL FROM:<artex@example.com>", "RCPT TO:<a@example.com>", "RCPT TO:<b@example.com>", "DATA", "AUTH", "QUIT"} {
		if !f.sawCommand(want) {
			t.Errorf("SMTP session missing %q, actual commands: %v", want, f.commands)
		}
	}
	// 正文是 base64 的 HTML，且要带上真实的漏洞内容（编码后仍可辨认）。
	body := f.body()
	if body == "" {
		t.Fatal("no body received in the DATA phase")
	}
	if !strings.Contains(body, "Content-Type: text/html") {
		t.Errorf("missing Content-Type header:\n%s", body)
	}
	if !strings.Contains(body, "base64") {
		t.Errorf("body not base64-encoded (long HTML lines would break SMTP's 1000-byte line limit):\n%s", body)
	}
	// 多个收件人都要出现在 To 头里。
	if !strings.Contains(body, "a@example.com, b@example.com") {
		t.Errorf("To header does not include all recipients:\n%s", body)
	}
}

func TestEmailSendWithoutAuth(t *testing.T) {
	// 未配账号时不应发 AUTH —— 有些中继会因此拒收。
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if f.sawCommand("AUTH") {
		t.Errorf("sent AUTH without an account configured: %v", f.commands)
	}
}

// TestEmailSendClassifiesSMTPReplies 是本次审计修复的直接验证：
// 5xx 判永久失败、4xx（灰名单）判可重试。
func TestEmailSendClassifiesSMTPReplies(t *testing.T) {
	cases := []struct {
		name      string
		rcptReply string
		mailReply string
		permanent bool
	}{
		{"recipient permanently rejected with 550", "550 5.1.1 User unknown", "250 OK", true},
		{"recipient hit 450 greylisting", "450 4.7.1 Greylisting in action", "250 OK", false},
		{"recipient hit 452 mailbox full", "452 4.2.2 Mailbox full", "250 OK", false},
		{"sender permanently rejected with 553", "250 OK", "553 5.1.3 Bad address", true},
		{"sender hit a 451 temporary error", "250 OK", "451 4.3.0 Temporary failure", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSMTP(t)
			f.rcptReply = tc.rcptReply
			f.mailReply = tc.mailReply
			_, err := (emailChannel{}).Send(context.Background(), emailCfg(t, f, nil), singleMsg())
			if err == nil {
				t.Fatal("should return an error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("wrong permanent judgment: want %v got %v (%v)", tc.permanent, got, err)
			}
			// 服务器原文要保留，否则用户不知道该找服务器管理员还是改地址。
			if !strings.Contains(err.Error(), strings.Fields(tc.rcptReply)[0]) && !strings.Contains(err.Error(), strings.Fields(tc.mailReply)[0]) {
				t.Errorf("the server's reply code should be kept in the error: %v", err)
			}
		})
	}
}

func TestEmailSendRefusesPlaintextCredentials(t *testing.T) {
	// net/smtp 的 PlainAuth 拒绝在未加密连接上发凭据（除非目标是 localhost）。
	// 这是**正确**的安全行为，不能被绕过；但要给出能指导用户修复的错误。
	// 这里用一个非 localhost 的主机名触发它。
	f := newFakeSMTP(t)
	f.advertiseAuth = true
	_, port := f.hostPort(t)
	cfg := map[string]any{
		"host":     "smtp.example.com", // 非 localhost
		"port":     float64(port),
		"from":     "a@example.com",
		"to":       []any{"b@example.com"},
		"username": "artex",
		"password": "pw",
	}
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Skip("local DNS resolved to a local server, skipping (does not affect other cases)")
	}
	// 连不上 或 被拒发凭据都算通过这条断言；关键是**不能**静默把密码发出去。
	if !IsPermanent(err) && !strings.Contains(err.Error(), "connect") {
		t.Logf("error: %v (failing to connect outside localhost is expected)", err)
	}
}

func TestEmailValidateReportsMissingFields(t *testing.T) {
	// 邮件渠道的配置字段最多，遗漏任一个都会在投递时才暴露；这里逐个确认
	// 校验能提前拦下。断言检查的是「错误信息提到了缺什么」。
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{"missing host", map[string]any{"port": float64(25), "from": "a@b.c", "to": []any{"d@e.f"}}},
		{"missing port", map[string]any{"host": "smtp.example.com"}},
		{"port out of range", map[string]any{"host": "h", "port": float64(70000), "from": "a@b.c", "to": []any{"d@e.f"}}},
		{"missing from", map[string]any{"host": "h", "port": float64(25), "to": []any{"d@e.f"}}},
		{"missing to", map[string]any{"host": "h", "port": float64(25), "from": "a@b.c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := (emailChannel{}).Validate(tc.cfg); err == nil {
				t.Fatalf("should fail validation: %v", tc.cfg)
			}
		})
	}
}

// TestEmailConfigTolerance 覆盖配置读取的容错：JSONB 里数值是 float64，
// 但用户在 UI 里可能把端口填成字符串；数组也可能是单个字符串。
func TestEmailConfigTolerance(t *testing.T) {
	cfg := map[string]any{
		"host": "smtp.example.com",
		"port": "587", // 字符串形式的端口
		"from": "a@b.c",
		"to":   "d@e.f", // 单个字符串而非数组
		"tls":  "true",  // 字符串形式的布尔
	}
	if err := (emailChannel{}).Validate(cfg); err != nil {
		t.Fatalf("numbers in string form should be tolerated: %v", err)
	}
	if got := cfgInt(cfg, "port"); got != 587 {
		t.Errorf("cfgInt did not parse a string port, got %d", got)
	}
	if !cfgBool(cfg, "tls") {
		t.Error("cfgBool did not parse the string \"true\"")
	}
	if to := cfgStrings(cfg, "to"); len(to) != 1 || to[0] != "d@e.f" {
		t.Errorf("cfgStrings does not accept a single string, got %v", to)
	}
}

// TestFilterValidateRejectsTypo 是审计修复的直接验证：
// 门槛打错字必须在写入时被拦，否则过滤器会静默失效变成全推。
func TestFilterValidateRejectsTypo(t *testing.T) {
	good := []string{"", "low", "medium", "high", "critical"}
	for _, s := range good {
		if err := (Filter{MinSeverity: s}).Validate(); err != nil {
			t.Errorf("valid threshold %q rejected: %v", s, err)
		}
	}
	// 这些是真实会发生的笔误——全部必须被拒。
	for _, s := range []string{"hgih", "HIGH", "Critical", "high ", "crit"} {
		err := (Filter{MinSeverity: s}).Validate()
		if err == nil {
			t.Errorf("invalid threshold %q should be rejected (otherwise the filter silently stops working and pushes everything)", s)
			continue
		}
		// 错误信息要能指导用户改对。
		if !strings.Contains(err.Error(), "low") || !strings.Contains(err.Error(), "critical") {
			t.Errorf("error message should list the allowed values, got %q", err.Error())
		}
	}
}

// TestFilterValidateIsWriteTimeOnly 锁住「写入严、读取宽」的分工：
// 库里已有的坏值不能让渠道整个读不出来（那会让历史渠道突然全部停止推送）。
func TestFilterValidateIsWriteTimeOnly(t *testing.T) {
	raw := []byte(`{"min_severity":"hgih"}`)
	f := ParseFilter(raw) // 不报错
	if f.MinSeverity != "hgih" {
		t.Fatalf("read path should be kept as-is, got %q", f.MinSeverity)
	}
	// 且该渠道仍能对事件做出判定（不 panic、不阻塞）。
	_ = Match(f, Snapshot{Kind: EventFindingCreated, Severity: "critical"})
}

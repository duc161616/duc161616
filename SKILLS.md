# Skill dir (overlay)

> File này nằm ở GỐC repo, không nằm trong `skills/`. Lý do: `skill.LoadDir()`
> coi **mọi file `.md`** ở đầu thư mục skill là một skill
> (`ARTEX/norma/skill/skill.go:233` fallback tên = tên file). Để `README.md`
> trong `skills/` thì nó load thành một skill tên "README" với description rỗng.

Đây là skill dir thật mà ARTEX load (`deploy/docker-compose.yml` mount thư mục
này vào `/app/skills`), **không phải** `ARTEX/skills/`. Mục đích: giữ
`ARTEX/` sạch nguyên trạng để còn diff được với upstream, đồng thời có chỗ sửa
và thêm skill.

## Khác gì so với upstream

| Skill | Thay đổi |
|---|---|
| `api-recon/` | giữ nguyên |
| `playwright-cli/` | giữ nguyên |
| `scopesentry/` | **sửa frontmatter hỏng** |

### Chi tiết bug đã sửa

Frontmatter gốc của `scopesentry/SKILL.md`:

```
---

## name: scopesentry-mcp
description: 通过 ScopeSentry MCP 管理...

# ScopeSentry MCP 使用指南
```

Hai lỗi: `name:` bị viết thành `## name:` (heading markdown, không phải key
YAML), và **không có `---` đóng**.

Parser của norma (`ARTEX/norma/skill/skill.go:261`) cố ý "degrade gracefully":
frontmatter lỗi thì field để rỗng, body vẫn load, không báo lỗi gì. Hậu quả
đo được bằng chính `skill.LoadDir()`:

```
TRƯỚC: name=scopesentry  instructions=15228 bytes  description=""
SAU:   name=scopesentry  instructions=16250 bytes  description="通过 ScopeSentry MCP..."
```

1. `description` **rỗng**. Đây là field discovery duy nhất hiển thị cho LLM
   (`skill.go:179-182`: *"Description is the primary discovery field per the
   agentskills.io spec"*) — agent thấy một cái tên không mô tả nên gần như
   không bao giờ gọi đúng lúc. Skill coi như chết.
2. **Mất ~1 KB nội dung**. Vì không có `---` đóng, parser quét tới `\n---` đầu
   tiên *trong body* (một horizontal rule markdown) và coi toàn bộ đoạn trước
   đó là frontmatter → bỏ đi. Mục "1. 准备工作" không bao giờ tới tay agent.

Kiểm chứng lại sau khi sửa skill:

```go
// go.mod cần: replace github.com/Autumn-27/norma => ./ARTEX/norma
r, _ := skill.LoadDir("skills")
for _, s := range r.List() {
    fmt.Printf("%s desc=%q instr=%d\n", s.Name, s.Description, len(s.Instructions))
}
```

## Thêm skill mới

Format là [agentskills.io](https://agentskills.io) — cùng chuẩn với skill của
Claude, nên skill viết cho Claude Code dùng được ở đây gần như nguyên vẹn:

```
skills/<tên>/
  SKILL.md          # bắt buộc
  references/*.md   # tài liệu tải theo nhu cầu
  scripts/*         # script chạy được
```

`SKILL.md` frontmatter — key mà norma đọc (`ARTEX/norma/skill/skill.go:248`):

```yaml
---
name: hunt-idor
description: Mô tả KHI NÀO dùng skill này. Đây là field quyết định agent có gọi
  hay không — viết trigger cụ thể, đừng viết chung chung.
allowed-tools: Bash(curl:*) Bash(ffuf:*)   # tuỳ chọn
mcps: [scopesentry]                        # tuỳ chọn, unlock MCP server
---
```

Sau khi thêm, **luôn verify bằng loader** (snippet ở trên) trước khi tin là nó
hoạt động — frontmatter sai không hề báo lỗi, chỉ im lặng không chạy. Đó đúng là
cách bug `scopesentry` tồn tại tới giờ.

Khởi động lại để ARTEX đọc skill mới:

```bash
cd deploy && docker compose restart artex
```

Phân quyền skill theo từng agent: bảng `agent_skill_visibility` (trang Agent
trong UI). Upload skill dạng zip: `POST /api/skills/upload`.


---

## Inventory (86 skill)

Verify bất cứ lúc nào bằng chính loader của ARTEX (snippet ở mục "Thêm skill mới"):
hiện tại **86 skill load được, 0 description rỗng**.

### Từ ARTEX upstream (3)

- `api-recon`
- `playwright-cli`
- `scopesentry`

### hunt-* — tầng kiến thức khai thác (58)

Đây là phần ARTEX hoàn toàn thiếu trước đó.

- `hunt-api-misconfig`
- `hunt-aspnet`
- `hunt-ato`
- `hunt-auth-bypass`
- `hunt-brute-force`
- `hunt-business-logic`
- `hunt-cache-poison`
- `hunt-captcha-bypass`
- `hunt-cicd`
- `hunt-clickjacking`
- `hunt-cloud-misconfig`
- `hunt-cors`
- `hunt-csrf`
- `hunt-deserialization`
- `hunt-dispatch`
- `hunt-dom`
- `hunt-exceptional-conditions`
- `hunt-file-upload`
- `hunt-fintech-graphql`
- `hunt-forgot-password`
- `hunt-graphql`
- `hunt-grpc`
- `hunt-host-header`
- `hunt-html-injection`
- `hunt-http-smuggling`
- `hunt-idor`
- `hunt-jwt-crypto`
- `hunt-k8s`
- `hunt-laravel`
- `hunt-ldap`
- `hunt-lfi`
- `hunt-llm-ai`
- `hunt-mfa-bypass`
- `hunt-misc`
- `hunt-nextjs`
- `hunt-nodejs`
- `hunt-nosqli`
- `hunt-ntlm-info`
- `hunt-oauth`
- `hunt-open-redirect`
- `hunt-race-condition`
- `hunt-rag-vector`
- `hunt-rce`
- `hunt-saml`
- `hunt-session`
- `hunt-shadow-api`
- `hunt-sharepoint`
- `hunt-source-leak`
- `hunt-spa-api`
- `hunt-springboot`
- `hunt-sqli`
- `hunt-ssrf`
- `hunt-ssti`
- `hunt-subdomain`
- `hunt-tls-network`
- `hunt-websocket`
- `hunt-xss`
- `hunt-xxe`

### Methodology · tooling · reporting (25)

- `api-fuzzing-bug-bounty`
- `api-security-testing`
- `broken-authentication`
- `bug-bounty`
- `bug-hunter`
- `bugcrowd-reporting`
- `burp-suite-testing`
- `burpsuite-project-parser`
- `ffuf-web-fuzzing`
- `frontend-mobile-security-xss-scan`
- `idor-testing`
- `patch-diff-exploit`
- `pentest-checklist`
- `pentest-commands`
- `pentest-tools`
- `recon-scope-triage`
- `security-arsenal`
- `shodan-reconnaissance`
- `sql-injection-testing`
- `sqlmap-database-pentesting`
- `supply-chain-attack-recon`
- `top-web-vulnerabilities`
- `web-security-testing`
- `web2-recon`
- `xss-html-injection`

---

## Nguồn và giấy phép

83 skill nhập từ
[sickn33/agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills)
(code: MIT, nội dung: CC BY 4.0 — **cả hai đều yêu cầu giữ attribution**, nên
đừng xoá mục này). Repo gốc có 2.590 skill; đây là tập đã lọc còn phần liên quan
săn bug, bỏ hết seo-audit / ux-audit / apify-* / azure-* / api-design và các
skill debug chung.

## Audit trước khi nhập

Skill là **chỉ thị mà agent tự trị sẽ làm theo**, nên đã quét trước:

| Kiểm tra | Kết quả |
|---|---|
| Script chạy được (`.sh`/`.py`/`.js`) | **0** — toàn markdown, rủi ro supply-chain gần như bằng không |
| Frontmatter hợp lệ | **83/83** (tốt hơn chính ARTEX, vốn hỏng 1/3) |
| Chỉ thị né proxy / phá bbguard | **0 hit** |
| Công cụ DoS | **0 hit** |
| Exfil ra host lạ | **0 hit** |
| `DROP TABLE` / `rm -rf` | 4 hit — đều là **payload mẫu trong tài liệu**, không phải chỉ thị |
| Prompt injection | 1 hit thật: `hunt-llm-ai` chứa chuỗi "Ignore previous instructions…" — đó là **payload để test tính năng LLM của target**, không nhắm vào agent ARTEX |

### Hai skill cần biết trước khi dùng

`pentest-commands` và `sqlmap-database-pentesting` dạy `--os-shell`,
`--file-write`, msfvenom/meterpreter. Hợp lệ cho pentest có hợp đồng, nhưng
**ngoài phạm vi PoC của bug bounty** — rule `[BB] Phá dữ liệu trên target` sẽ
chặn thẳng nếu agent làm theo. Giữ lại vì chúng vẫn có phần cheatsheet hữu ích;
xoá thư mục nếu bạn không muốn agent đọc tới.

### Hai thay đổi do audit này kéo theo

1. **`bbguard/scope.example.json` thêm OOB callback host vào `infra`**
   (`*.oast.pro`, `*.interact.sh`, `*.burpcollaborator.net`…). `hunt-ssrf` và
   `hunt-xxe` test blind bằng callback ra ngoài; không có host đó trong scope
   thì bbguard chặn và test luôn fail.
2. **Rule `[BB] Brute force` bỏ `hashcat`/`john`.** `hunt-jwt-crypto` và
   `hunt-ato` dùng `hashcat -m 16500` để crack JWT **offline** — không gửi gói
   nào tới target, nên không đáng phải xin duyệt. Tool brute force online
   (hydra/medusa/ncrack/kerbrute…) vẫn `ask`.

---

## Chi phí context — đọc mục này

Listing skill (tên + description của **mọi** skill) nằm trong định nghĩa tool
và đi theo **mọi lần gọi LLM** (`ARTEX/norma/skill/skill.go:174`). Đo thực tế:

```
86 skill  ->  8.5 KB  ~2.180 token / mỗi lần gọi LLM
```

Với planner bị đánh thức mỗi lần graph đổi, con số đó cộng dồn nhanh. Dùng
bảng `agent_skill_visibility` (trang Agent trong UI) để cắt:

| Agent | Nên thấy | Vì sao |
|---|---|---|
| `worker` | `hunt-*` + tooling (`ffuf-web-fuzzing`, `sqlmap-*`, `burp-*`) + `api-recon`, `playwright-cli` | Worker là người thực thi một intent — nó cần kỹ thuật khai thác |
| `planner` | `recon-scope-triage`, `web2-recon`, `bug-bounty`, `top-web-vulnerabilities`, `pentest-checklist` | Planner ra quyết định hướng, không tự chạy tool |
| `goals` | `recon-scope-triage`, `bug-bounty` | Chỉ cần hiểu phạm vi và mục tiêu |
| `retester` | `hunt-*` của đúng lớp lỗi đang retest | Hẹp nhất có thể |
| `mainagent` | tất cả | Bạn đang ngồi trước nó |

Gate như trên đưa listing của worker/planner về khoảng **một nửa**.

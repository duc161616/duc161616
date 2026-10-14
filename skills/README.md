# Skill dir (overlay)

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

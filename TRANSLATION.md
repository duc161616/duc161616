# Dịch ARTEX sang tiếng Anh — trạng thái

Phạm vi bạn chọn: **toàn bộ phần chức năng**, **dịch tại chỗ** (không thêm i18n
framework). Comment trong code nằm ngoài phạm vi.

## Đã xong

| Layer | Nội dung | Commit |
|---|---|---|
| `prompt` | Prompt của planner/worker/goals/mainagent/retester/intercept judge | pass 1 |
| `tooldesc` | 220 mô tả tool mà LLM đọc để chọn tool | pass 2 |
| `ui` | 1.418 string literal + ~1.540 đoạn JSX text của frontend | pass 3 |
| `apimsg` + `test` | 2.292 chuỗi: lỗi API, log, thông báo push, report Markdown/CSV, tool desc của `norma` (shell_open…), cùng toàn bộ assertion test tương ứng | pass 4 |

Kiểm chứng sau pass 4 (DB PostgreSQL mới, `go test -count=1 -p 1 ./...`):

- ARTEX: **0 regression**. Còn đúng 1 test fail vốn đã fail ở bản gốc
  (`TestGraphOverviewExpandsAssociatedCompanyScope`). `TestMgmtAPI` thỉnh thoảng
  fail vì race khi dọn TempDir — chạy riêng thì pass, bản gốc cũng vậy.
- `norma` (SDK vendored): 8 test fail — **giống hệt bản trước khi dịch**
  (đã chạy so sánh trên worktree của commit trước), không phải do dịch.
- Frontend: 187 file parse OK, `node --test` của `chat-mentions` và
  `activity-merge` pass.

## Lỗi thật tìm ra trong lúc dịch (đã sửa)

1. **@mention trong chat bị gãy sau pass `ui`.** Frontend sinh token
   `@[Finding#12 …]` nhưng server (`server/chat_mentions.go`) chỉ nhận
   `@[漏洞#12 …]` → mention bị bỏ qua âm thầm. Bằng chứng:
   `web/src/lib/chat-mentions.test.mjs` fail 2/3 sau pass `ui`, pass 3/3 ở commit
   trước. Sửa: cả hai phía nhận nhãn tiếng Anh **và** tiếng Trung (tin nhắn cũ
   trong DB vẫn resolve), thêm test cho cả hai dạng.
2. **Nhận diện hết quota LLM bị mất.** `agent/provider.go` so khớp lỗi trả về từ
   provider Trung Quốc bằng `余额不足`/`额度不足`/`额度已用尽`/`欠费`. Đây là
   chuỗi *đầu vào từ bên ngoài*, không phải nhãn — đã khôi phục, test
   `TestIsQuotaExhaustedMessage` bắt được.

## Chuỗi cố ý giữ tiếng Trung

`python3 bbkit/i18n_apply.py --coverage ARTEX` còn báo tiếng Trung — phần còn lại
đều thuộc một trong các nhóm sau (đã ghi vào `PROTECTED` trong
`bbkit/i18n_apply.py` để lần chạy sau không dịch nhầm):

| Chuỗi | Vị trí | Lý do |
|---|---|---|
| `[模型]` | `intercept/intercept.go`, `db/intercept.go`, `db/task_archives_restore.go` | Sentinel "quyết định do model" — đọc lại từ DB |
| `实际操作：…；成功后的后果：…；命中规则：` | `intercept/prompt.go` | Dạng lý do cũ; parser nhận **cả** dạng tiếng Anh `Action: …; Consequence: …; Rule: …` |
| `备案` | `db/company_scope.go` | ICP 备案 là khái niệm pháp lý, không phải nhãn |
| `余额不足` `额度不足` `额度已用尽` `欠费` | `agent/provider.go` | Provider trả lỗi tiếng Trung |
| `漏洞` `资产` `企业`… | `server/chat_mentions.go`, `web/src/lib/chat-mentions.ts` | Token mention cũ, nhận song song tiếng Anh |
| `新对话` | `server/conversations.go` | Tiêu đề mặc định cũ; bản mới dùng `New chat` |
| `意图` / `提示` | `server/server.go` | Lệnh rule-mode, đã song ngữ với `intent` / `hint` |
| `reporterToolCallMessageV1` | `server/orchestration.go` | Phải khớp từng byte với DB cũ để migration chạy |
| `失败` `丢弃` `重试`… | `server/logsink.go` | Từ khoá phân loại log — giữ thêm bên cạnh bản tiếng Anh |
| Fixture `京ICP备…`, chuỗi đo rune, tên skill Unicode | các `*_test.go` | Test hành vi xử lý chữ Hán/ICP — dịch là mất ý nghĩa test |

**Không dịch:** `web/src/lib/mock/*` (dữ liệu demo cho chế độ mock của frontend,
không chạy khi có backend) và comment trong code.

## ⚠️ Instance đã cài trước khi dịch

Prompt, mô tả tool, tên agent dựng sẵn và tên rule chặn dựng sẵn là **seed**: chỉ
được ghi khi bảng còn trống (`SeedPromptIfEmpty`, `db/config.go:743`). Cài mới →
toàn bộ là tiếng Anh. DB cũ → các dòng đó **vẫn là tiếng Trung** cho tới khi bạn
reset:

```
POST /api/agents/{key}/prompt/reset   # goals planner worker mainagent auto pentest retester
PUT  /api/tools/{key}                  # mô tả tool
```

Hoặc dễ nhất: tạo DB mới (`docker compose down -v` rồi up lại) nếu chưa có dữ
liệu cần giữ. Tên rule chặn dựng sẵn trên DB cũ: chưa kiểm chứng có endpoint
reset — sửa tay trong trang Intercept nếu cần.

## `norma` không còn trùng byte với upstream

`ARTEX/norma` trước đây giống hệt `github.com/Autumn-27/norma v0.4.3` (đã xác minh
trong `ARTEX-AUDIT-MA-DOC.md`). Pass 4 dịch mô tả tool `shell_*` và thông báo
`Task …` của nó vì LLM đọc trực tiếp, nên giờ nó **khác** upstream. Muốn kiểm tra
lại supply chain: diff với bản upstream — mọi khác biệt chỉ được nằm trong string
literal.

## Công cụ

```bash
python3 bbkit/i18n_apply.py --coverage ARTEX            # còn bao nhiêu literal tiếng Trung
python3 bbkit/i18n_apply.py ARTEX dict.json --dry-run   # áp từ điển (validator chặn literal hỏng)
python3 bbkit/i18n_jsx.py ARTEX coverage                # JSX text còn tiếng Trung
python3 bbkit/i18n_extract.py ARTEX --risky             # dò chuỗi sentinel
```

Bài học từ pass 4: sentinel không chỉ là `== "..."`. Hãy dò cả **danh sách từ
khoá** (`[]string{...}` dùng với `Contains`), **regex**, **map key**, **hằng số
migration** và chuỗi mà frontend/backend **parse của nhau** (`Tool X requests…`,
`Archive not found`, `already exists`).

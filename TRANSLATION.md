# Dịch ARTEX sang tiếng Anh

Số đo thật, lấy bằng `python3 bbkit/i18n_extract.py ARTEX` (chạy lại bất cứ lúc
nào để xem tiến độ):

| Layer | Ký tự Hán | File | % | Cần build lại? | Hậu quả nếu bỏ qua |
|---|---|---|---|---|---|
| `prompt` | 11.639 | 7 | 7% | **Không — sửa trong DB** | Agent suy nghĩ và ghi fact/finding bằng tiếng Trung |
| `tooldesc` | 5.211 | 3 | 3% | **Không — sửa trong DB** | LLM đọc mô tả tool bằng tiếng Trung khi chọn tool |
| `ui` | 24.677 | 78 | 15% | Có — frontend | Bạn vẫn thấy giao diện tiếng Trung |
| `apimsg` | 17.884 | 120 | 11% | Có — Go | Lỗi API và log tiếng Trung |
| `test` | 29.915 | 97 | 18% | Có — Go | `go test` fail khi dịch `apimsg` |
| `comment` | 64.054 | 182 | 40% | Không ảnh hưởng | Chỉ khó đọc code |

**158.400 ký tự, nhưng 40% là comment** (không ảnh hưởng gì) và 18% là test.
Phần thật sự đổi hành vi chỉ **16.850 ký tự trong 10 file** — và nó **không cần
build lại**.

## Vì sao prompt + tooldesc không cần build lại

`agent/promptcatalog.go` không phải prompt lúc chạy. Nó là **seed**: server bơm
vào bảng `agent_prompts` bằng `SeedPromptIfEmpty` (`db/config.go:743`) — chỉ ghi
khi **trống**. Tool description cũng vậy: `BuiltinToolSeeds()` → bảng `tools`.

Hệ quả hai chiều:

- Sửa source Go **không** đổi prompt của instance đang chạy (DB đã có bản tiếng
  Trung, seed không ghi đè).
- Nhưng sửa qua API thì **có hiệu lực ngay, không cần rebuild**:

```
PUT  /api/agents/{key}/prompt       # thay prompt một agent
POST /api/agents/{key}/prompt/reset # revert về seed
PUT  /api/tools/{key}               # thay mô tả một tool
```

Hoặc sửa thẳng trong UI: trang **Agent** → chọn agent → ô prompt.

Agent dựng sẵn: `goals`, `planner`, `worker`, `mainagent`, `auto`, `pentest`,
`retester`.

## Thứ tự nên làm

1. **`prompt` + `tooldesc`** — 16.850 ký tự, không rebuild, đổi hành vi nhiều
   nhất. Sau bước này agent ghi fact/finding bằng tiếng Anh, khớp với 83 skill
   tiếng Anh vừa nhập và khớp với `triage.py`/`report.py`.
2. **`ui`** — 24.677 ký tự trong 78 file. Chuỗi hardcode trong JSX, `web/package.json`
   **không có** i18n framework (next-intl/react-i18next/lingui đều không).
   Hai lựa chọn: dịch tại chỗ (nhanh, một chiều), hoặc thêm next-intl rồi tách
   chuỗi ra file locale (chậm hơn nhưng giữ được cả hai ngôn ngữ).
3. **`apimsg` + `test` cùng một commit** — 101 test đang assert trên chuỗi
   tiếng Trung; dịch production mà không sửa test là `go test ./...` đỏ.
4. **`comment`** — làm sau cùng hoặc không làm.

## Chỗ KHÔNG được dịch

### 12 chuỗi sentinel trong code production

Đây là chuỗi được **so sánh ở file khác**, không phải nhãn hiển thị. Dịch bên
sản xuất mà không sửa bên tiêu thụ = hành vi đổi âm thầm, không lỗi biên dịch.

| Vị trí | Chuỗi | Ghi chú |
|---|---|---|
| `intercept/intercept.go:481`, `db/intercept.go:251`, `db/task_archives_restore.go:680` | `[模型]` | **Sentinel 3 nơi** — đánh dấu quyết định do model đưa ra. Đổi cả 3 cùng lúc hoặc không đổi |
| `intercept/prompt.go:193` | `实际操作：` | Prefix bắt buộc của lý do; parser kiểm tra nó |
| `db/company_scope.go:160` | `备案` | **Giữ nguyên.** ICP 备案 là khái niệm pháp lý Trung Quốc, không phải chữ cần dịch — dịch là mất tính năng |
| `server/conversations.go:443` | `新对话` | Sentinel tiêu đề mặc định |
| `web/src/components/transcript.tsx:406` | `命令` | So sánh nhãn để chọn cách render |
| `install.sh`, `update.sh` | `选择` | Prompt của script, an toàn |

`server/server.go:3821-3825` thì **đã song ngữ sẵn**
(`HasPrefix(m, "意图") || HasPrefix(lower, "intent")`) — dịch được tự do.

### Cách làm an toàn với sentinel

Đừng đổi chuỗi. Thêm nhận cả hai:

```go
// trước
if strings.HasPrefix(out.Message, "[模型]") {
// sau
if strings.HasPrefix(out.Message, "[模型]") || strings.HasPrefix(out.Message, "[model]") {
```

Đúng cách mà `server/server.go:3821` đang làm. Dữ liệu cũ trong DB vẫn đọc được,
dữ liệu mới dùng tiếng Anh.

## Công cụ

```bash
python3 bbkit/i18n_extract.py ARTEX                  # bảng tổng quan + risk map
python3 bbkit/i18n_extract.py ARTEX --layer prompt   # xem từng layer
python3 bbkit/i18n_extract.py ARTEX --risky          # chỉ chuỗi sentinel
python3 bbkit/i18n_extract.py ARTEX --tsv i18n.tsv   # catalogue đầy đủ để review
```

TSV có cột `layer`, `risky`, `keep`, `file`, `line`, `chars`, `text` — mở bằng
spreadsheet, dịch cột text, rồi áp lại theo từng layer.

## Lưu ý về `ARTEX/`

`ARTEX/` là mirror nguyên trạng để còn diff với upstream. Dịch `ui`/`apimsg`
buộc phải sửa trong đó. Hai cách giữ sạch:

- **Nhánh riêng** cho bản dịch, rebase khi upstream có thay đổi (upstream thực
  tế đã chết nên rủi ro thấp).
- **Patch series** trong `patches/`, áp lúc build.

`prompt` và `tooldesc` thì không gặp vấn đề này: chúng sống trong DB, không
trong source.

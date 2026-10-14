# Phân tích repo ARTEX (mhtsec/ARTEX)

> Bản mirror source: commit upstream `a9d11cb` ("Merge PR #4: build: restore norma v0.4.3
> from Go module proxy", 2026-10-10), 810 file, nằm trong thư mục [`ARTEX/`](./ARTEX).
> Mirror nguyên trạng file set của upstream, không sửa code.

---

## 1. ARTEX là gì

**Hệ thống pentest tự trị điều khiển bởi LLM multi-agent.** Không phải scanner theo
signature: nó dùng LLM làm bộ não lập kế hoạch, chạy công cụ thật (Bash / Kali / HTTP /
Playwright / nmap) trong vòng lặp event-driven, và ghi kết quả vào hai graph trong
PostgreSQL để tự quyết định bước tiếp theo.

| | |
| --- | --- |
| Backend | Go 1.26, `net/http`, single binary (frontend nhúng qua `go:embed`) |
| Frontend | Next.js + shadcn/ui, static export, 152 `.tsx` |
| DB | PostgreSQL (pgx) + SQLite phụ (index traffic, `modernc.org/sqlite`) |
| Agent SDK | [`norma`](https://github.com/Autumn-27/norma) v0.4.3 — **upstream đã closed-source**, được restore từ Go module proxy và vendor vào `./norma` (xem `go.mod` `replace`) |
| License | AGPL-3.0 + điều khoản tác giả: **chỉ đọc/nghiên cứu source và verify trong lab local; cấm dùng tấn công hệ thống online** |

### Về lineage của repo
- Upstream gốc: `Autumn-27/ARTEX` (Docker image `autumn27/artex` đã bị xoá).
- `mhtsec/ARTEX` tự nhận là **bản backup source cuối cùng**, tự maintain image
  `mianhuatang11/artex`, và sửa Dockerfile thành multi-stage build từ source thuần
  (không phụ thuộc binary precompiled).
- Changelog 76 KB, lịch sử commit cho thấy project được phát triển khá nghiêm túc
  (có PR fix bảo mật riêng: `fix/auth-init-fail-open`, `fix(notify)` thêm SSRF guard
  cho SMTP dial, `fix/sse-same-origin`).

---

## 2. Quy mô code

| Thư mục | File Go | LOC | Vai trò |
| --- | --- | --- | --- |
| `server/` | 103 | 34.755 | REST API (~400 route), JWT, SSE, Manager vòng đời task/engine/store |
| `norma/` | 206 | 37.226 | SDK agent vendored (agentcore, tool, permission, harness, memory, transcript, compaction, llm, mcp, noa) |
| `db/` | 96 | 30.195 | Store Postgres cho dual-graph; `schema.sql` 1.386 dòng / **49 bảng**, chạy idempotent mỗi lần boot ("restart = migrate") |
| `agent/` | 52 | 10.391 | planner / worker / mainagent / goals / retester + ToolSet phơi graph thành LLM tool |
| `notify/` | 26 | 5.055 | 7 kênh: email, webhook, telegram, dingtalk, feishu, wecom, http + mask/filter/sign |
| `traffic/` | 10 | 4.158 | MITM proxy ghi traffic (go-mitmproxy) + SQLite index |
| `intercept/` | 7 | 1.572 | Cổng phê duyệt tool call (human-in-the-loop) |
| `selfupdate/` | 5 | 1.411 | Tự cập nhật: verify SHA256SUMS → smoke test → staged swap → rollback |
| `sidequestion/`, `llmpool/`, `llmrec/`, `mcphttp/`, `evidence/`, `guard/`, `enrich/`, `report/`, `config/`, `cmd/` | 33 | ~6.600 | Hệ con hỗ trợ |

Tổng ~115k LOC Go (gồm 37k vendored) + 187 file TS/TSX. Test coverage khá dày: khoảng
một nửa file Go trong `server/` và `agent/` là `_test.go`.

---

## 3. Kiến trúc cốt lõi: Dual-Graph

Đây là điểm thiết kế đáng giá nhất của project. Nó tách "**mục tiêu là gì**" khỏi
"**đã test tới đâu**" thành hai graph độc lập, nối nhau qua anchor:

**Asset Graph** (`assets`, `companies`, `company_scope`, `task_scope`) — global, chia sẻ
giữa mọi task. Node: `root_domain / subdomain / ip / service / app / endpoint`. Quan hệ
cha-con và dedup key **do code tính**, agent chỉ submit raw info → LLM không tự bịa được
cấu trúc asset.

**Exploration Graph** (`exploration_nodes`, `exploration_edges`, `activity`) — per-task.
Node: `goal / intent / fact / finding / hint`. Edge: `spawns / derived_from / yields /
proves` → tạo chuỗi huyết thống (lineage) trả lời được "hướng này sinh ra từ fact nào,
đã cho ra cái gì".

**Anchor** (`exploration_anchors(node_id, asset_id)`) nối hai graph → vừa truy được
"intent này đánh asset nào", vừa truy ngược "asset này đã bị intent nào test, ra fact
gì". Đây là nền của tính năng **asset test coverage** và **asset coverage map**.

### Vòng lặp engine
```
graph thay đổi (debounce) → wake planner → planner đọc tình hình (graph_overview + coverage/scope)
→ phát 0..N intent vào frontier → worker claimNext 1 intent → chạy tool thật qua recording proxy
→ ghi fact/asset/finding + activity từng bước → graph thay đổi → wake planner (đóng vòng)
→ cho tới khi prove_goal
```
Phân vai rõ: **planner là nguồn duy nhất sinh intent**; **worker chỉ nhận đúng 1 intent,
thực thi, ghi lại rồi dừng**.

### Hai cơ chế tạo nên tính tự trị
1. **Trao đổi thông tin ở mức process giữa các worker.** Nhiều quan sát giá trị (một
   error message, một hidden param) nằm trong *quá trình chạy* của worker chứ chưa thành
   fact chính thức. Worker có `search_all_worker_traces(q)` (tìm keyword trong step của
   work khác, tự loại trừ step của chính mình), `list_worker_traces`,
   `get_worker_trace(intent_id, step_ids)` → thông tin chảy giữa worker **ở granularity
   "execution trace"** mà không phá vỡ ranh giới mỗi worker chỉ làm 1 intent.
2. **Shared todolist của planner.** Planner là event-driven nên **mỗi lần wake là một
   session mới** (stateless). Nó giữ một todolist per-task tồn tại xuyên các lần wake →
   ghi chuỗi exploit nhiều bước có phụ thuộc (inject → lấy credential → lateral →
   privesc) **một lần**, rồi mỗi vòng chỉ phát intent cho bước đã đủ tiền đề. Đây là lý
   do chain đa bước không bị phát song song lộn thứ tự.

---

## 4. Tool surface của agent (`agent/tools.go`, `agent/tools_insert.go`)

Phân quyền tool theo role rất rõ ràng — đáng tham khảo nếu bạn tự build agent:

| Role | Tool |
| --- | --- |
| **worker** | `list_findings`, `report_finding`, `record_fact`, `insert_assets`, `list_assets`, `search_all_worker_traces`, `get_worker_trace`, `node_detail` |
| **planner** | toàn bộ read (`graph_overview`, `list_facts`, `list_findings`, `node_detail`, `expand_digest`) + `add_intent`, `prove_goal`, `goal_met`, `kill_work`, `steer_work`, `add_task_scope`, `add_company_scope`, `list_untested_assets` |
| **mainagent** (human-in-the-loop) | như planner + `add_hint`, `set_goals`, `set_constraints`, `steer_work` |
| **goals** | `set_goals`, `set_constraints` |
| **retester** | agent riêng, preset sẵn, re-verify finding → kết luận `vẫn reproduce / đã fix / không xác nhận được` |

Cố ý **không** cho worker: `add_company_scope`, `list_facts`, `list_companies`,
`list_worker_traces` — định nghĩa scope và review xuyên work là việc của planner.

Có cả **cold-digest/compaction**: node nguội bị fold thành digest, planner gọi
`expand_digest` để restore → cách xử lý context window khi graph phình to.

---

## 5. Các hệ con hỗ trợ

- **`traffic/` — recording MITM proxy.** go-mitmproxy embedded, mặc định `:8788`. Package
  doc nói rõ: *"Full capture, plaintext (no redaction), target HTTP only"*. Mọi exchange
  ghi ra file tree browse được + SQLite index để query phân trang. Dùng làm evidence cho
  finding (`evidence/`, `finding_traffic_bindings`, `traffic_evidence_snapshots`).
- **`guard/` + `intercept/` — cổng phê duyệt.** Mọi tool call đi qua hook `PreToolUse`.
  Đáng chú ý: comment trong `guard/guard.go` ghi rõ hard-code chặn destructive/exfil
  **đã bị bỏ** — giờ nằm trong intercept rule trong DB (seed dạng `[内置]`, user **có thể
  disable hoặc xoá**). Có fallback cho LLM tự judge approval (đo token riêng).
- **`llmpool/`, `llmrec/`** — pool nhiều LLM profile, health check (`llm_profile_health`),
  retry (`server/llmretry.go`), ghi lại raw request/response của LLM, đo token.
- **`notify/`** — 7 kênh, có `mask.go` (che secret trong payload), `filter.go`, `sign.go`,
  và SSRF guard cho cả SMTP dial.
- **`selfupdate/`** — update từ UI: download → so `SHA256SUMS` của Release → smoke test
  `-h` → stage `artex.new` → exit code 75 để `start.sh` relaunch và swap. Fail 3 lần
  liên tiếp → tự rollback về `artex.old`. Chỉ tải từ domain GitHub, force HTTPS.
- **`mcphttp/` + `skills/`** — MCP client (Streamable HTTP + SSE legacy) và 3 skill kèm
  theo: `api-recon`, `playwright-cli`, `scopesentry`.
- **`sidequestion/`** — agent hỏi lại người dùng giữa lúc chạy.
- **`enrich/`** — bổ sung DNS/HTTP bất đồng bộ (dnsx, miekg/dns).
- **Sync ScopeSentry** (`server/sync_scopesentry.go`) — import asset trực tiếp từ
  [ScopeSentry](https://github.com/Autumn-27/ScopeSentry).

---

## 6. Bề mặt tấn công — ghi chú khi tự deploy

> **Đây là quan sát đọc code, CHƯA kiểm chứng động.** Không coi là finding. Liệt kê để
> biết cần test gì nếu bạn dựng instance (của mình) và muốn audit nó.

**Mô hình auth** (`ARTEX/server/auth.go`): single-user, username hard-code `"ARTEX"`,
bcrypt hash lưu trong bảng `settings`, JWT HS256 TTL 7 ngày, key 32 byte ở `jwt.key`
(0600, đã được migrate ra khỏi workspace browse được — xử lý tốt).
`requireAuth` miễn trừ `/api/auth/*` và `/api/health`; `change-password` tự verify token
+ old password bên trong. `authInit` đã được vá fail-open (`InsertSettingIfAbsent` dựa
primary key, không dựa read check) — commit `fix/auth-init-fail-open`.

Những điểm cần kiểm chứng thủ công nếu audit:
1. `extractToken` nhận token qua **`?token=` query param** (cho SSE) → cần xem có rò qua
   access log / Referer / lịch sử proxy không.
2. Token lưu ở `localStorage` **và** mirror sang cookie `artex_token` set bằng
   `document.cookie` phía client (`web/src/lib/api.ts:111,128`) → cookie **không
   HttpOnly**; cần test state-change request có CSRF token không và SameSite thực tế ra sao.
3. Không thấy rate limit / lockout trên `/api/auth/login` → brute force bcrypt single-user.
4. **Traffic store là plaintext không redaction theo design** — mọi credential, token,
   session đi qua proxy nằm nguyên trên disk + SQLite index. Treat như crown jewel.
5. **Agent chạy Bash thật = RCE by design.** Guard không hard-block nữa; chặn hay không
   phụ thuộc intercept rule trong DB mà user xoá được. Đừng expose instance ra public.
6. API key LLM nằm trong env/DB; UI có trang config → đường đọc secret là
   `/api/llm/profiles` và các route config.
7. Dockerfile mặc định kéo npm/playwright qua mirror TQ (override được bằng
   `--build-arg NPM_REGISTRY=... / GOPROXY=...`) → supply chain cần cân nhắc.
8. Có **file manager workspace** (`server/workspace.go`, `DELETE /api/workspace/delete`)
   và `POST /api/skills/*` upload zip (`server/skill_zip.go`) → hai chỗ cần test path
   traversal / zip slip trước tiên nếu audit.

---

## 7. Build & chạy

```bash
# Docker (nhanh nhất)
cd ARTEX && cp .env.example .env     # điền POSTGRES_PASSWORD, tuỳ chọn ANTHROPIC_API_KEY
docker compose build && docker compose up -d        # → http://localhost:8787 (/setup lần đầu)

# Single binary từ source
cd ARTEX/web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex   # -tags embedui mới nhúng frontend
./start.sh                                  # dùng start.sh, không chạy ./artex trực tiếp

# Dev
./dev.sh          # backend :8787 + proxy :8788 + next dev :5173
go test ./...
cd web && NEXT_PUBLIC_MOCK=1 npm run dev    # preview frontend không cần backend
```
Yêu cầu: PostgreSQL + `ANTHROPIC_API_KEY` hoặc `OPENAI_API_KEY` (hoặc cấu hình trong UI).
`start.sh` là supervisor script — cơ chế one-click update phụ thuộc nó.

---

## 8. Đánh giá

**Đáng học:**
- Dual-graph + anchor là cách giải bài "agent biết mình đã test tới đâu" gọn gàng nhất mình
  thấy trong một autonomous pentest framework; coverage metric có cơ sở dữ liệu thật.
- Dedup/parent-child do **code** tính chứ không để LLM tự quyết → chặn hallucination ở
  đúng chỗ.
- Shared todolist xuyên session giải bài stateless planner mà vẫn chạy được exploit chain
  nhiều bước — pattern này áp dụng được cho bất kỳ agent system event-driven nào.
- Worker trace exchange: cho phép chia sẻ observation chưa thành fact, không phá ranh giới role.
- Phân quyền tool theo role, comment giải thích *tại sao* không cấp tool nào — code
  comment chất lượng cao bất thường (nhiều comment ghi lại bug từng xảy ra và lý do fix).
- Self-update có checksum + smoke test + auto rollback: làm đúng chuẩn.

**Hạn chế:**
- Phụ thuộc `norma` — SDK đã closed-source, bản trong repo là restore từ module proxy, sẽ
  không có update. Đây là nợ kỹ thuật lớn nhất.
- Auth single-user, không RBAC, không audit log người dùng (audit log chỉ cho tool call).
- Toàn bộ comment/UI/doc tiếng Trung — rào cản nếu team không đọc được.
- Repo là backup, không phải upstream sống: Releases không host binary ở đây.
- Chi phí LLM: mỗi graph change wake planner; có đo token nhưng vẫn là kiến trúc tốn token.

**Lưu ý pháp lý:** AGPL-3.0 (deploy thành service online → phải public source bản sửa) +
tác giả cấm dùng tool tấn công hệ thống online, kể cả asset của chính mình. Nếu bạn dùng
cho bug bounty thật thì nằm ngoài phạm vi tác giả cho phép — quyết định và trách nhiệm
là của bạn, không phải của repo.

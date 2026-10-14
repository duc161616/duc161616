# Install ARTEX + cách dùng hợp lý

Mọi con số/đường dẫn dưới đây đều lấy từ code trong `ARTEX/`, không phải từ README upstream.

---

## 0. Yêu cầu

| Thứ | Phiên bản | Vì sao |
|---|---|---|
| PostgreSQL | 16 (compose dùng `postgres:16-alpine`) | 49 bảng, schema chạy idempotent mỗi lần boot |
| Docker + Compose plugin | bất kỳ bản có `docker compose` | đường cài khuyến nghị |
| **Go** (nếu build từ source) | **≥ 1.26.3** | `ARTEX/go.mod:8` ghi `go 1.26.3`. Go cũ hơn sẽ tự tải toolchain nếu `GOTOOLCHAIN=auto` |
| **Node** (nếu build từ source) | **≥ 20** | Playwright yêu cầu; Dockerfile dùng `node:20-bookworm` |
| LLM API key | Anthropic hoặc OpenAI | có thể để trống rồi điền trong UI |
| Disk | ~5-8 GB cho image | image cài chromium + playwright + nmap + node |

Image runtime cài sẵn: `ripgrep curl wget vim git jq unzip dnsutils iputils-ping netcat-openbsd telnet whois nmap` + Node 20 + Playwright/Chromium.

---

## Cách 1 — Có bbguard (khuyến nghị, dùng được cho target thật)

Đây là đường duy nhất mình khuyên nếu bạn định chạy vào cái gì ngoài lab.
Chi tiết từng bước và lý do: [`BUG-HUNTER-SETUP.md`](./BUG-HUNTER-SETUP.md).

```bash
git clone https://github.com/duc161616/duc161616.git
cd duc161616/deploy

cp .env.example .env            # điền POSTGRES_PASSWORD + ANTHROPIC_API_KEY
mkdir -p data
cp ../bbguard/scope.example.json data/scope.json
$EDITOR data/scope.json         # scope lấy từ policy chương trình, đọc bằng mắt

docker compose up -d
docker compose logs -f bbguard  # xác nhận scope đã load đúng
```

Mở **http://localhost:8787** → trang `/setup` → đặt mật khẩu admin.

Rồi vào **Cấu hình hệ thống** đặt 3 thứ (bắt buộc, nếu không agent sẽ đứt mạng
hoặc chạy ngoài tầm kiểm soát):

1. **Proxy xuất toàn cục** = `http://bbguard:8899`
2. **LLM proxy** = `http://bbguard:8899` — compose đã set `ARTEX_LLM_PROXY` sẵn, nhưng kiểm tra lại. Cần riêng vì LLM call cố tình bỏ qua biến proxy (`agent/provider.go:404`)
3. **Tắt one-click update**

Nạp intercept rules:

```bash
cd ..
go run ./bbkit/validate-rules bbkit/intercept-rules.json     # phải ra 9/9 valid
python3 bbkit/load_rules.py --base http://localhost:8787 --token "$ARTEX_JWT"
```

Lấy token ở console browser: `localStorage.getItem('artex_token')`.

### Chạy lab trước

```bash
cd deploy
cat > data/scope.json <<'JSON'
{"program":"lab","handle":"local","allow":["juiceshop"],"deny":[],
 "infra":["api.anthropic.com","api.openai.com"]}
JSON
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
```

Target trong ARTEX: `http://juiceshop:3000`. Overlay này bật `-allow-private`
cho bbguard (juiceshop nằm trong dải IP private của Docker) — **không dùng
overlay này cho engagement thật**, nó mở đúng lớp chặn agent pivot vào mạng
nội bộ của bạn.

---

## Cách 2 — ARTEX thuần, không bbguard (CHỈ lab)

```bash
cd ARTEX
cp .env.example .env            # điền POSTGRES_PASSWORD
docker compose build            # build từ source, không cần image ngoài
docker compose up -d
```

**Hai cảnh báo thật, không phải formality:**

- `ARTEX/docker-compose.yml:37` publish `8787:8787` — tức **0.0.0.0**, mở ra mọi
  interface. Đây là app có Bash RCE by design và auth single-user không rate
  limit. Nếu máy có IP public thì bạn vừa mở một shell cho Internet. Sửa thành
  `127.0.0.1:8787:8787`, hoặc dùng Cách 1 (đã bind localhost sẵn).
- Không có bbguard = không có lớp enforce scope nào. Agent gửi request đi đâu
  là tuỳ model quyết định.

---

## Cách 3 — Single binary từ source

```bash
cd ARTEX

# 1. Frontend static export
cd web && npm ci && npm run build:static && cd ..

# 2. Nhúng vào Go
cp -r web/out server/webui/dist

# 3. Build — bắt buộc có -tags embedui mới nhúng frontend
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex

# 4. Database
cp config.example.json config.json && $EDITOR config.json   # điền database.*
#   hoặc: export ARTEX_PG_DSN='postgres://artex:pass@127.0.0.1:5432/artex?sslmode=disable'

# 5. Chạy
./start.sh                      # KHÔNG chạy ./artex trực tiếp
```

`start.sh` là supervisor, không phải wrapper cho đẹp: nó đọc exit code của
`artex` và quyết định có chạy lại không — `75` = "program xin restart để đổi
bản" (`selfupdate.ExitRestart`). Chạy `./artex` trực tiếp thì sau khi update
process chết là chết luôn.

Tham số: `./start.sh -addr :8787 -proxy :8788` — `-addr` là frontend+API,
`-proxy` là MITM ghi traffic. Chạy nền: `nohup ./start.sh >artex.log 2>&1 &`.

Build gói release đa nền tảng: `./build.sh --release`.

---

## First run & tài khoản

- Lần đầu vào `/setup` để đặt mật khẩu. **Username cố định là `ARTEX`**
  (`server/auth.go:275`), không đổi được, không có user thứ hai.
- Mật khẩu: tối thiểu 8 ký tự, tối đa 72 **byte** (giới hạn cứng của bcrypt).
- JWT sống 7 ngày, key 32 byte ở `jwt.key` (0600, nằm ngoài workspace browse được).
- Mất mật khẩu: `./reset-password.sh` (sinh bcrypt bằng pgcrypto trong DB, hỗ trợ
  cả `local` và `docker`).
- Không có rate limit trên `/api/auth/login` → đừng expose ra public, kể cả sau
  khi đặt mật khẩu mạnh.

### Upgrade

Dữ liệu được giữ: volume `pgdata`, `./data`, `./skills`. **Không cần chạy
migration tay** — `artex` chạy lại `schema.sql` idempotent mỗi lần boot
("restart = migrate").

```bash
cd deploy && docker compose build artex && docker compose up -d artex
```

Đừng dùng one-click update trong UI: `selfupdate/github.go:15` trỏ về
`Autumn-27/artex`, repo gốc không còn ai maintain. Cơ chế thì làm đúng (allowlist
domain, đối chiếu `SHA256SUMS`, smoke test, auto-rollback sau 3 lần fail) nhưng
nguồn binary là repo bạn không kiểm soát. Ở Cách 1, egress lock đã chặn sẵn.

---

## Cách sử dụng hợp lý

### Thứ ARTEX làm tốt vs không

| Làm tốt | Đừng kỳ vọng |
|---|---|
| Theo dõi **coverage trên scope lớn** — 2000 subdomain thì cái nào chưa chạm | Business logic bug — cần hiểu mô hình kinh doanh, LLM đoán rất tệ |
| Enumeration có hệ thống, không bỏ sót nhánh | Thay phán đoán của bạn về "cái gì là bug" |
| **Ghi evidence** — request/response bind vào từng finding | Race condition, chain nhiều bước tinh vi |
| Chuỗi exploit nhiều bước đơn giản (shared todolist) | Report nộp được ngay — `report_finding` là LLM tự khai |
| Import asset từ ScopeSentry rồi quản lý như inventory | Tiết kiệm chi phí — mỗi graph change đánh thức planner |

### Thiết lập một task

1. **Scope hẹp.** Một root domain, hoặc một nhóm endpoint. Scope rộng = token
   đốt vào recon vô định.
2. **Goal cụ thể.** "Tìm IDOR trong API v2 user/order" tốt hơn "tìm lỗ hổng".
3. **Dùng `set_constraints`** dù nó chỉ ở tầng prompt — nó vẫn ảnh hưởng hành vi
   thật, chỉ là không phải bảo đảm. Bảo đảm nằm ở bbguard.
4. **Worker = 1-2** trong lúc còn đang học tool (default 3, đổi ở Cấu hình hệ
   thống). Blast radius và chi phí tỉ lệ thuận với số worker.
5. **Bật traffic recording.** Không có nó thì finding không có evidence, và
   không có evidence thì không có report.

### Trong lúc chạy

- Theo dõi tab **Phê duyệt/Chặn**. Rule `ask` sẽ treo chờ bạn; `timeout_action`
  là `deny` nên bỏ mặc = lệnh bị chặn, không phải cho qua.
- Xem **Token** để biết đang đốt bao nhiêu. Dừng sớm nếu planner loop vô ích.
- `steer_work` để nắn một worker đang chạy lệch mà không làm mất tiến độ.
- Theo dõi audit của bbguard song song:
  ```bash
  tail -f deploy/data/audit.jsonl | python3 -c "
  import sys,json
  for l in sys.stdin:
      e=json.loads(l)
      print(('ALLOW ' if e['allowed'] else 'DENY  ')+e['host'], '|', e['reason'][:50])"
  ```
  Thấy `DENY` liên tục vào một host bạn biết là in-scope → sửa `scope.json`.
  Thấy `DENY` vào host lạ → agent đang đi lang thang, xem lại goal.

### Sau khi chạy

```bash
curl -H "Authorization: Bearer $ARTEX_JWT" \
  'http://localhost:8787/api/exploration/findings/export?scope=all&format=json' \
  -o findings.json
python3 bbkit/triage.py findings.json                   # 5 nhóm + dedupe
python3 bbkit/report.py findings.json --id <id> > report.md
```

Muốn có raw request/response trong report thì export `format=md-zip` (export
`json` **cố tình xoá trắng** `req_head`/`resp_head` — `server/server.go:2148`),
giải nén rồi `report.py --evidence <thư mục>`.

**Không submit trực tiếp từ ARTEX.** Finding là lead. Tự reproduce bằng tay,
tự chụp request/response của chính mình, rồi mới viết.

### Vệ sinh dữ liệu

`traffic/traffic.go` package doc nói thẳng: *"Full capture, plaintext (no
redaction)"*. Mọi credential, token, session của target đi qua proxy nằm nguyên
trên disk trong `deploy/artex-data/` + SQLite index. Xoá sau mỗi engagement:

```bash
curl -X DELETE -H "Authorization: Bearer $ARTEX_JWT" http://localhost:8787/api/traffic/all
```

### Nhịp làm việc gợi ý

| Khi nào | Làm gì |
|---|---|
| Đầu phiên | Đọc lại policy → cập nhật `scope.json` → `docker compose restart bbguard` → `curl localhost:8899/scope` xác nhận |
| Chạy | 1 task, scope hẹp, 1-2 worker, theo dõi approval + audit |
| Cuối phiên | `triage.py` → tự reproduce nhóm đầu → `report.py` → xoá traffic |
| Định kỳ | `curl localhost:8899/stats` xem tỉ lệ deny; deny cao = scope sai hoặc agent đi lang thang |

---

## Troubleshooting

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| Agent báo mọi request lỗi | Chưa set **Proxy xuất toàn cục** = `http://bbguard:8899`, nên MITM không có đường ra |
| LLM call timeout | Chưa set LLM proxy (LLM bỏ qua biến env proxy theo thiết kế) |
| bbguard trả 403 cho host in-scope | Thiếu trong `allow`, hoặc trùng một rule `deny`, hoặc host resolve về IP private (cần `-allow-private` — chỉ cho lab) |
| bbguard trả 502 "internal address" | Target resolve về loopback/RFC1918 — đúng hành vi, đang bảo vệ mạng của bạn |
| 429 liên tục | Chạm `-host-rps`; nâng trong `deploy/.env` nếu policy cho phép |
| Activity stream quay mãi | Reverse proxy đang buffer SSE. Nginx cần `proxy_buffering off; proxy_cache off; proxy_read_timeout 3600s;` |
| `go build` báo cần go cao hơn | go.mod yêu cầu 1.26.3; `export GOTOOLCHAIN=auto` để Go tự tải |
| Frontend trắng trang sau build | Thiếu `-tags embedui`, hoặc chưa `cp -r web/out server/webui/dist` |
| Update xong không khởi động lại | Đang chạy `./artex` trực tiếp thay vì `./start.sh` |
| Mất mật khẩu | `./reset-password.sh` |

---

Nhắc lại điều ở `ARTEX/README.md`: tác giả cấm dùng ARTEX tấn công hệ thống
online, kể cả asset của chính bạn. Không có gì trong repo này biến việc test
thành hợp pháp — authorization đến từ policy chương trình.

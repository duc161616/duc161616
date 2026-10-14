# ARTEX cho bug bounty — runbook

Repo này gồm 3 phần:

| Thư mục | Là gì |
|---|---|
| [`ARTEX/`](./ARTEX) | Mirror nguyên trạng `mhtsec/ARTEX` @ `a9d11cb`, **không sửa một dòng nào** (để còn diff được với upstream về sau). Phân tích kiến trúc: [`ARTEX-PHAN-TICH.md`](./ARTEX-PHAN-TICH.md) |
| [`bbguard/`](./bbguard) | Egress proxy enforce scope + rate limit + audit. Lớp ARTEX đã xoá. Go, stdlib, 20 test |
| [`bbkit/`](./bbkit) | Intercept rules cho BB, triage gate cho findings, report builder |
| [`deploy/`](./deploy) | Compose khoá egress ở tầng network |

---

## Tại sao cần thêm — 4 điều đã kiểm chứng trong code

1. **Scope không được enforce.** `guard/guard.go:4`: *"The RoE authorization-scope
   mechanism was removed."* Thứ còn lại là chữ trong system prompt
   (`agent/promptcatalog.go:25`, `agent/worker.go:235`) và `task_constraints`
   cũng chỉ render thành text (`agent/constraints.go`) — comment của tác giả
   tự gọi nó là *"tug-of-war"*.
2. **Asset gate chỉ chặn ghi DB, không chặn traffic.** `EvaluateAssetGate` được
   gọi duy nhất ở `insert_assets` (`agent/tools_insert.go:245`) — nó ngăn agent
   *ghi* asset ngoài scope vào graph, không ngăn worker *gửi request* tới đó.
   Và fail-open nếu load rule lỗi (`tools_insert.go:231`).
3. **Không có rate limit cho target.** Rate limiting duy nhất là cho LLM provider
   (`agent/provider.go`). Default 3 worker đồng thời (`server/manager.go:284`).
4. **Không có header nhận diện.** Không có `User-Agent` tuỳ biến ở đâu cả.

Mặt khác, ARTEX **có** sẵn hai thứ giúp việc này khả thi:
- `global_proxy` (`server/manager.go:262`) — upstream egress proxy cho MITM, và
  `traffic/traffic.go:170` ghi rõ *"even the transparent-passthrough paths honor
  it, so no host escapes it"*.
- Tool nhận `HTTP_PROXY/HTTPS_PROXY` qua `agent/worker.go:209`.

Chuỗi hoàn chỉnh:

```
tool ──► ARTEX MITM :8788 ──► bbguard :8899 ──► internet
         (ghi evidence)        (scope/pace/audit)
                                 ▲ lối ra duy nhất của container
```

---

## Setup

### 1. Scope

```bash
cd deploy
cp .env.example .env                       # điền POSTGRES_PASSWORD + API key
mkdir -p data
cp ../bbguard/scope.example.json data/scope.json
$EDITOR data/scope.json
```

Lấy scope từ chính policy chương trình, **đọc bằng mắt**, không suy đoán. Apex
ngoài scope thì cho vào `deny` (deny luôn thắng). LLM API và OOB server cho vào
`infra` — reachable nhưng miễn pacing và không bị gắn handle của bạn.

### 2. Khởi động với egress bị khoá

```bash
docker compose up -d        # trong deploy/
```

`artex` nằm trên network `internal: true` → **không có route ra internet**.
Host duy nhất có route là `bbguard`. Đây mới là thứ khoá scope thật: `nmap` và
`masscan` không tôn trọng `HTTP_PROXY`, nên regex rule không bắt được chúng —
nhưng không có route thì chúng không đi đâu được.

### 3. Trỏ ARTEX qua bbguard

Vào `http://localhost:8787` → **Cấu hình hệ thống**:

- **Proxy xuất toàn cục** = `http://bbguard:8899`
- **LLM proxy** = `http://bbguard:8899` — bắt buộc riêng, vì LLM call cố tình
  bỏ qua biến môi trường proxy (`agent/provider.go:404`: *"留空=直连,不回退
  HTTP_PROXY/HTTPS_PROXY 环境变量"*). Hoặc dùng `ARTEX_LLM_PROXY` (compose đã
  set sẵn), hoặc cột `proxy` của LLM profile (`db/schema.sql:367`).
- **Tắt one-click update.** `selfupdate/github.go:15` trỏ về
  `Autumn-27/artex` — repo gốc không còn ai maintain. Đó là kênh phân phối
  binary từ một repo bạn không kiểm soát. Egress lock đã chặn sẵn, đừng mở.

### 4. Nạp intercept rules

```bash
go run ./bbkit/validate-rules bbkit/intercept-rules.json     # 9/9 rules valid
python3 bbkit/load_rules.py --base http://localhost:8787 --token "$ARTEX_JWT"
```

Token lấy ở console browser: `localStorage.getItem('artex_token')`.

9 rule, quan trọng nhất là **`[BB] Né proxy` (deny)** — chặn mọi lệnh cố bỏ
proxy (`--noproxy`, `-x ''`, `unset HTTPS_PROXY`, `env -u HTTP_PROXY`). Rule
ồn nhất là `[BB] Tool fuzz/scan hàng loạt` (ask trên mọi ffuf/nuclei/gobuster) —
tắt nó nếu chương trình cho phép scan tự do.

ARTEX mặc định chỉ bật **một** rule cứng (`[内置] 破坏性系统命令`); rule chống
data-exfil của nó ship **disabled** (`db/db.go:540`) vì pattern `curl|nc`
false-positive trên reverse shell hợp lệ. Nên đừng tin rằng mặc định đã an toàn.

Mọi rule đều có `timeout_action: deny` — treo quá hạn thì chặn, không phải cho qua.

### 5. Chạy dry-run trước khi chạy thật

```bash
# trong deploy/docker-compose.yml, thêm -dry-run vào command của bbguard
docker compose up -d bbguard
# chạy 1 task nhỏ, rồi xem những gì SẼ bị chặn:
python3 - <<'PY'
import json, collections
c = collections.Counter()
for l in open('deploy/data/audit.jsonl'):
    e = json.loads(l)
    if e.get('dry_run'): c[e['host']] += 1
for h, n in c.most_common(): print(f"{n:5}  {h}")
PY
```

Host nào xuất hiện mà bạn biết chắc là in-scope → thêm vào `allow`. Xong thì
**bỏ `-dry-run`**. Đừng bao giờ chạy engagement thật ở dry-run.

---

## Vòng làm việc mỗi phiên

```bash
# 1. Trước phiên: đọc lại policy, cập nhật scope, restart bbguard
docker compose restart bbguard
curl -s localhost:8899/scope        # xác nhận đúng scope đang load

# 2. Chạy task trong ARTEX (UI)

# 3. Sau phiên: triage findings — KHÔNG submit trực tiếp
curl -H "Authorization: Bearer $ARTEX_JWT" \
  'http://localhost:8787/api/exploration/findings/export?scope=all&format=json' \
  -o findings.json
python3 bbkit/triage.py findings.json

# 4. Chỉ cái nào qua gate thì dựng report
python3 bbkit/report.py findings.json --id 101 > report.md

# 5. Kiểm tra mình đã đi những đâu
curl -s localhost:8899/stats
python3 - <<'PY'
import json, collections
c = collections.Counter()
for l in open('deploy/data/audit.jsonl'):
    e = json.loads(l); c[(e['allowed'], e['host'])] += 1
for (ok, h), n in sorted(c.items(), key=lambda kv: -kv[1])[:20]:
    print(f"{'ALLOW' if ok else 'DENY ':5} {n:5}  {h}")
PY
```

`triage.py` chia findings thành 5 nhóm và **không bao giờ gán nhãn "verified"** —
chữ đó thuộc về người đã tự reproduce:

| Nhóm | Nghĩa |
|---|---|
| `NEEDS_MANUAL_VERIFICATION` | Có evidence + asset → đây là hàng đợi làm việc |
| `NEEDS_EVIDENCE` | Confirmed nhưng không có traffic binding → chưa có gì để viết report |
| `NOT_CONFIRMED` | `status` là pending/in_progress → chính agent cũng chưa chốt |
| `LIKELY_REJECTED` | Missing header / cookie flag / TLS config / version disclosure... |
| `DISMISSED` | ARTEX đã đánh false_positive |

Nó cũng dedupe theo (vulnclass, asset) — hai worker báo cùng một bug trên cùng
endpoint là **một** report.

`report.py` đưa claim của agent vào trong `<details>` dán nhãn *unverified* và
để `TODO` ở mọi chỗ cần proof của chính bạn. **Report mà bạn chưa tự chạy PoC là
cách nhanh nhất để mất uy tín trên platform.**

Lưu ý: export `format=json` **cố tình xoá trắng** `req_head`/`resp_head`
(`server/server.go:2148`), nên muốn có raw request/response thì export
`format=md-zip` rồi `report.py --evidence <thư mục đã giải nén>`.

---

## Những gì vẫn KHÔNG được giải quyết

Nói thẳng để bạn không tưởng là đã xong:

- **bbguard không biết policy chương trình.** Nó chỉ enforce đúng những gì bạn
  gõ vào `scope.json`. Gõ sai = enforce sai.
- **Chất lượng finding vẫn là LLM.** `report_finding` là agent tự khai. Triage
  gate lọc được rác rõ ràng và dedupe, không thay được việc bạn tự reproduce.
- **CONNECT là tunnel mù.** HTTPS được enforce scope + pacing theo host trong
  CONNECT, nhưng không chèn được header. Muốn header trên TLS thì phải để
  ARTEX MITM đứng trước (chuỗi ở trên đã làm vậy).
- **Traffic store là plaintext không redaction** theo design
  (`traffic/traffic.go` package doc). Credential của target nằm nguyên trên
  disk. Đối xử với `./data` như crown jewel, và xoá sau mỗi engagement.
- **norma đã closed-source.** Bản vendored là v0.4.3 restore từ module proxy
  (đã verify byte-for-byte, xem phần audit trong `ARTEX-PHAN-TICH.md`). Không
  bao giờ có update. Đây là nợ kỹ thuật lớn nhất của ARTEX.
- **Chi phí LLM.** Mỗi graph change đánh thức planner. Có đo token, nhưng kiến
  trúc vốn tốn.
- **Giấy phép.** AGPL-3.0, cộng điều khoản tác giả **cấm dùng tấn công hệ thống
  online**, kể cả asset của chính bạn. Dùng cho bug bounty thật là ngoài phạm vi
  tác giả cho phép. Quyết định và trách nhiệm là của bạn.

Không có cái nào trong repo này biến việc test thành hợp pháp. Authorization
đến từ policy chương trình, không đến từ một allowlist.

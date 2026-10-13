# Audit mã độc — mhtsec/ARTEX @ `a9d11cb`

**Kết luận: không tìm thấy mã độc, backdoor, telemetry hay kênh exfil.**

Phần đáng ngờ nhất của repo này — thư mục `norma/` do mhtsec (không phải tác giả
gốc) tự thêm vào — đã được xác minh **byte-for-byte khớp với bản chính thức**
trong Go checksum transparency log. Mọi bước dưới đây đều tự chạy lại được.

---

## 1. norma/ — kiểm tra quan trọng nhất

`go.mod` có `replace github.com/Autumn-27/norma => ./norma`. Replace trỏ thư
mục local nên **go.sum bị bỏ qua hoàn toàn** — không có cơ chế tự động nào xác
minh 37.226 dòng Go đó. Vì vậy phải diff thủ công.

```bash
# Bản gốc trong Go module proxy, kèm commit hash upstream
curl -s "https://proxy.golang.org/github.com/%21autumn-27/norma/@v/v0.4.3.info"
# {"Version":"v0.4.3","Time":"2026-09-30T01:12:52Z","Origin":{"VCS":"git",
#  "URL":"https://github.com/Autumn-27/norma",
#  "Hash":"320ae32989da97dd91469bb89164cbfe87d83d5d","Ref":"refs/tags/v0.4.3"}}

# Hash chính thức trong transparency log (sum.golang.org — tamper-evident)
curl -s "https://sum.golang.org/lookup/github.com/%21autumn-27/norma@v0.4.3"
# github.com/Autumn-27/norma v0.4.3 h1:DnmOhJPL6OZSMnCVYO5Ujh4yVINuDarEickVi9jx1hI=

# Tải zip và diff với bản trong repo
curl -s -o norma.zip "https://proxy.golang.org/github.com/%21autumn-27/norma/@v/v0.4.3.zip"
mkdir orig && cd orig && unzip -q ../norma.zip && cd ..
diff -r "orig/github.com/Autumn-27/norma@v0.4.3" ARTEX/norma && echo "IDENTICAL"
```

Kết quả: **`diff -r` không trả về khác biệt nào** (210 file trong zip, cùng tập
file, cùng nội dung).

Và tự tính dirhash H1 để chắc zip tải về đúng là bản sumdb đã chứng thực:

```python
import hashlib, base64, zipfile
z = zipfile.ZipFile('norma.zip')
lines = ['%s  %s\n' % (hashlib.sha256(z.read(n)).hexdigest(), n)
         for n in sorted(z.namelist()) if not n.endswith('/')]
print('h1:' + base64.b64encode(hashlib.sha256(''.join(lines).encode()).digest()).decode())
# h1:DnmOhJPL6OZSMnCVYO5Ujh4yVINuDarEickVi9jx1hI=   <- khớp sumdb
```

Chuỗi tin cậy đầy đủ: **sum.golang.org → zip → code trong repo**.

## 2. mhtsec đã sửa những gì so với tác giả gốc

Commit cuối của tác giả gốc là `e6ec569`. Toàn bộ thay đổi của mhtsec:

```bash
cd ARTEX && git diff --name-status e6ec569..HEAD -- . ':(exclude)norma/'
# M  Dockerfile
# M  README.md
# M  docker-compose.yml
# M  go.mod
# M  go.sum
```

**Không một dòng Go hay TypeScript nào của ARTEX bị sửa:**

```bash
git diff --stat e6ec569..HEAD -- '*.go' ':(exclude)norma/'   # trống
git diff --stat e6ec569..HEAD -- 'web/'                      # trống
```

Thay đổi thực chất: Dockerfile đổi từ "copy binary precompiled" sang multi-stage
build từ source (thực ra là **cải thiện** về supply chain — không còn tin binary
dựng sẵn), image name `autumn27/artex` → `mianhuatang11/artex`, thêm `replace`
cho norma, và xoá 2 dòng norma trong `go.sum` (hệ quả bắt buộc của `replace`).

## 3. Các dấu hiệu mã độc thường gặp — đều âm tính

| Kiểm tra | Kết quả |
|---|---|
| `func init()` chạy ngầm lúc load | **0 cái** trong toàn repo |
| Obfuscation (base64/hex decode rồi exec) | Chỉ 1 chỗ `base64.RawURLEncoding.DecodeString` — là pagination cursor (`db/chat_mentions.go:62`) |
| Byte array kiểu shellcode `[]byte{0x..}` | Không có |
| `go:linkname`, `unsafe`, cgo | Không có (ngoài norma đã verify) |
| `exec.Command` | Chỉ ở nơi hợp lý: `norma/tool/{bash,task,ripgrep,shell_session}`, `norma/mcp/stdio`, `server/customtool`, `selfupdate/bootstrap` |
| Secret bị commit (sk-/ghp_/AKIA/private key) | Không có |
| File binary / executable lạ | Không có |
| Domain hardcode | Toàn bộ là test fixture (`example.com`, `.local`, `.invalid`, `attacker.tld`) hoặc endpoint hợp lệ: dingtalk / feishu / wecom / telegram (notify), deepseek / tavily / brave / duckduckgo (LLM + search) |
| `curl \| sh` trong script | 2 chỗ, đều tới nhà cung cấp chính thức: `get.docker.com` (install.sh:22), `deb.nodesource.com` (Dockerfile:46) |
| CI workflow | GitHub Actions chuẩn; secret chỉ dùng để push Docker Hub, không exfil |
| Script Python trong `skills/` | 4 file recon, chỉ fetch URL truyền vào qua tham số, không có host hardcode nào để gửi dữ liệu đi |

`107.172.96.177` xuất hiện trong repo nhưng chỉ là **chuỗi ví dụ trong mô tả
tool** (`traffic/traffic.go:2012`) — có lẽ là IP VPS test của tác giả bị bỏ sót
trong docstring. Không phải callback.

## 4. Những điểm cần biết khi tự deploy (không phải mã độc)

Đây là rủi ro vận hành, đã kiểm chứng từ code:

1. **Kênh one-click update trỏ về repo của người khác.** `selfupdate/github.go:15`
   là `Repo = "Autumn-27/artex"` — repo gốc, hiện không còn ai maintain. Allowlist
   domain thì làm đúng (chỉ `api.github.com` + `github.com`, bắt buộc HTTPS,
   đối chiếu `SHA256SUMS`, smoke test, auto-rollback). Nhưng đó vẫn là đường
   nhận binary từ một repo bạn không kiểm soát. **Nên tắt.**
2. **Mirror Trung Quốc trong Dockerfile** (`registry.npmmirror.com`,
   `cdn.npmmirror.com/binaries/playwright`, `goproxy.cn`). Override được bằng
   `--build-arg NPM_REGISTRY=... --build-arg GOPROXY=...` nếu bạn muốn đi
   registry gốc.
3. **Script recon tắt verify TLS** (`CTX.verify_mode = ssl.CERT_NONE` trong
   `skills/api-recon/scripts/{harvest_static,spider_mpa}.py`). Bình thường với
   recon, nhưng traffic recon của bạn MITM được.
4. **Rule chống data-exfil ship DISABLED** (`db/db.go:540`) vì pattern
   `curl|wget|nc` false-positive trên reverse shell hợp lệ. Mặc định chỉ có
   **một** rule cứng được bật.
5. **CI dùng action pin theo tag, không theo SHA** — chỉ liên quan nếu bạn chạy
   CI của chính repo đó.

Phân tích bề mặt tấn công của bản thân ARTEX (auth, workspace, skill upload…):
xem mục 6 trong [`ARTEX-PHAN-TICH.md`](./ARTEX-PHAN-TICH.md).

# ARTEX trên Windows

## Kết luận: được, nhưng chạy trong Docker, không phải Windows native

**Windows native biên dịch được** — mình đã cross-compile thật:

```
GOOS=windows GOARCH=amd64 go build -o artex.exe ./cmd/artex
# exit 0, ra artex.exe 42 MB — PE32+ executable (console) x86-64
```

Repo cũng có `start.bat`, và norma có build tag Windows đầy đủ
(`pty_other.go`, `task_windows.go` đều `//go:build windows`). Tức tác giả có
chủ ý hỗ trợ Windows.

**Nhưng agent sẽ hoạt động rất tệ ở đó**, vì 3 lý do trong code:

| Vấn đề | Ở đâu | Hậu quả |
|---|---|---|
| Tool "Bash" chạy **PowerShell** | `norma/tool/task.go:567` — `runtime.GOOS == "windows"` → `powershell -NoProfile -NonInteractive -Command` | LLM được train trên shell Linux. Nó sinh `curl ... \| grep`, `ffuf`, pipeline bash — hỏng hoặc chạy sai trên PowerShell. `curl` trong PowerShell 5.1 là alias của `Invoke-WebRequest`, khác hoàn toàn curl.exe |
| **PTY không hỗ trợ** | `norma/tool/pty_other.go` — `"interactive shell (PTY) is not supported on this platform"` | Shell session tương tác báo lỗi thẳng |
| Không có recon tooling | — | `nmap`, `ripgrep`, `jq`, `dnsutils`, Playwright/Chromium đều không có. Image Linux của ARTEX cài sẵn tất cả |

Thêm nữa: 10 intercept rule trong `bbkit/` viết theo cú pháp bash. Mình đã kiểm
và rule chặn né proxy bản bash **miss cả 5 dạng PowerShell** (`$env:HTTPS_PROXY=''`,
`Remove-Item Env:\HTTPS_PROXY`, `-NoProxy`, …). Nên đã thêm rule
`[BB] Né proxy (PowerShell)` riêng — nhưng đó chỉ là bịt một lỗ, không làm
PowerShell thành môi trường tốt cho agent pentest.

**→ Dùng Docker Desktop (WSL2 backend).** Bạn vẫn cài trên máy Windows, vào
đúng thư mục bạn muốn; chỉ là ARTEX chạy trong container Linux — đúng môi
trường nó được thiết kế cho. `deploy/` hoạt động không cần sửa gì.

## Cài

```powershell
# Clone trước (nếu thư mục còn trống)
git clone --branch claude/kind-clarke-u7ghly --depth 1 `
  https://github.com/duc161616/duc161616.git D:\pentest\artex

cd D:\pentest\artex
.\windows\Install-Artex.ps1 -InstallDir D:\pentest\artex -Handle duc161616 -Lab
```

Script làm: kiểm prereq (Docker **đang chạy**, không chỉ đã cài) → sinh `.env`
với mật khẩu Postgres ngẫu nhiên 28 ký tự → sinh `scope.json` → `docker compose
build` → `up -d` → in 4 bước tay còn lại.

Bỏ `-Lab` cho engagement thật; khi đó `scope.json` là placeholder và **bbguard
sẽ chặn mọi thứ** cho tới khi bạn điền host thật từ policy chương trình.

> **Script này chưa được chạy thử trên Windows thật.** Nó được viết trong môi
> trường Linux không có PowerShell, nên mình chỉ kiểm tra tĩnh được (ngoặc cân,
> here-string đóng đúng, có check `$LASTEXITCODE`, ghi `.env` không BOM). Nếu
> nó lỗi, `INSTALL.md` mục "Cách 1" có đủ lệnh `docker compose` để làm tay.

## Muốn Claude Code local tự cài

[`PROMPT-CLAUDE-CODE.md`](./PROMPT-CLAUDE-CODE.md) — prompt dán sẵn, gồm cả bối
cảnh để nó không làm sai (không sửa `ARTEX/`, không chạy compose gốc của
upstream, không publish port ra 0.0.0.0) và yêu cầu nó xác minh thật bằng
`docker compose ps` + `/api/health` + `/scope` chứ không chỉ báo "xong".

## Vài điều riêng của Windows

- **Dùng `curl.exe`, không dùng `curl`.** Trong PowerShell 5.1 `curl` là alias
  của `Invoke-WebRequest` — cú pháp khác hẳn. Windows 10+ có `curl.exe` thật.
- **Đường dẫn trong volume.** `deploy/docker-compose.yml` dùng đường dẫn tương
  đối (`./data`, `./artex-data`) nên Docker Desktop tự xử lý. Đừng sửa thành
  đường dẫn Windows tuyệt đối.
- **File Sharing.** Nếu Docker Desktop báo không mount được, thêm ổ đĩa chứa
  thư mục cài vào Settings → Resources → File Sharing.
- **Theo dõi audit log**: `Get-Content deploy\data\audit.jsonl -Wait -Tail 20`
  (tương đương `tail -f`).
- **CRLF.** Repo có `.gitattributes` buộc `*.sh` là LF, nên script shell trong
  container không bị vỡ vì `git config core.autocrlf` của bạn.
- **WSL2 ăn RAM.** Đặt giới hạn trong `%UserProfile%\.wslconfig` nếu máy ít RAM:
  ```ini
  [wsl2]
  memory=8GB
  processors=4
  ```

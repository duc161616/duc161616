# Prompt để Claude Code local cài ARTEX trên Windows

Mở Claude Code trong PowerShell trên máy Windows, rồi dán nguyên khối dưới đây.
**Sửa `D:\pentest\artex` thành thư mục bạn muốn** và `duc161616` thành handle của bạn.

---

```
Cài ARTEX (hệ thống pentest tự trị LLM) + bbguard vào thư mục D:\pentest\artex
trên máy Windows này, chạy qua Docker Desktop. Handle researcher của tôi:
duc161616.

BỐI CẢNH — đọc trước khi làm:

Source nằm ở https://github.com/duc161616/duc161616 branch
claude/kind-clarke-u7ghly. Repo đó gồm:
  - ARTEX/            source ARTEX (đã dịch sang tiếng Anh tại chỗ), KHÔNG được sửa
  - bbguard/          egress proxy enforce scope (Go, stdlib)
  - bbkit/            intercept rules + triage/report script
  - deploy/           docker compose đã khoá egress
  - windows/Install-Artex.ps1   script cài cho Windows
  - INSTALL.md, BUG-HUNTER-SETUP.md   runbook

CHẠY TRONG CONTAINER LINUX, KHÔNG PHẢI WINDOWS NATIVE. Lý do: trên Windows,
tool Bash của agent chạy PowerShell chứ không phải bash
(ARTEX/norma/tool/task.go:567), PTY không được hỗ trợ
(ARTEX/norma/tool/pty_other.go), và nmap/ripgrep/jq/playwright không có sẵn.
Image Linux của ARTEX cài sẵn đúng bộ tool đó. Binary Windows biên dịch được,
nhưng agent sẽ sinh lệnh bash và vỡ trên PowerShell.

VIỆC CẦN LÀM:

1. Kiểm tra prereq và báo cho tôi nếu thiếu:
   - Docker Desktop đã cài VÀ đang chạy (`docker info` phải thành công, không
     chỉ `docker --version`), backend WSL2
   - git
   - Ổ đĩa còn trống >= 15 GB (image ~5-8 GB + volume Postgres)

2. Chạy script cài có sẵn trong repo:
      cd D:\pentest\artex
      .\windows\Install-Artex.ps1 -InstallDir D:\pentest\artex -Handle duc161616 -Lab

   Script tự clone repo nếu thư mục trống, sinh .env với mật khẩu Postgres
   ngẫu nhiên, sinh scope.json preset lab, rồi build + up.

   Nếu thư mục trống thì phải clone trước mới có script — clone thủ công:
      git clone --branch claude/kind-clarke-u7ghly --depth 1 `
        https://github.com/duc161616/duc161616.git D:\pentest\artex

   LƯU Ý: script này chưa bao giờ được chạy thử trên Windows thật (nó được
   viết trong môi trường Linux không có PowerShell). Nếu nó lỗi, đừng cố
   workaround vòng vo — đọc ARTEX/INSTALL.md mục "Cách 1" rồi làm tay từng
   lệnh docker compose, và nói cho tôi biết dòng nào lỗi.

3. Sau khi container chạy, xác minh thật chứ đừng báo xong:
   - `docker compose ps` trong deploy\ : cả 3-4 service phải Up
   - `docker compose logs bbguard` : phải thấy dòng scope đã load với số
     allow/deny/infra rule
   - `curl.exe http://localhost:8787/api/health` phải trả JSON
     (dùng curl.exe, KHÔNG phải alias curl của PowerShell)
   - `curl.exe http://localhost:8899/scope` phải trả scope đang load

4. In ra cho tôi 4 bước tay còn lại (script cũng in, nhắc lại cho chắc):
   a. http://localhost:8787 -> /setup -> đặt mật khẩu admin
      (>= 8 ký tự, username cố định "ARTEX")
   b. Cấu hình hệ thống -> Proxy xuất toàn cục = http://bbguard:8899
      VÀ LLM proxy = http://bbguard:8899   (thiếu cái thứ hai thì LLM call
      timeout, vì nó cố tình bỏ qua biến env proxy)
   c. Cùng trang -> TẮT one-click update
   d. Nạp rules: python bbkit\load_rules.py --base http://localhost:8787
      --token "<JWT lấy từ localStorage.getItem('artex_token')>"

RÀNG BUỘC:
- Không sửa gì trong ARTEX/ — đó là bản đã dịch sang tiếng Anh và đã qua test
  (xem TRANSLATION.md); sửa tay dễ làm gãy các chuỗi sentinel.
- Không publish port 8787 ra 0.0.0.0. deploy/docker-compose.yml đã bind
  127.0.0.1 sẵn; đừng đổi. Đây là app có Bash RCE by design, auth single-user,
  không rate limit login.
- Không chạy `docker compose` trong ARTEX/ (compose gốc của upstream publish
  8787 ra mọi interface và không có bbguard). Chỉ dùng deploy/.
- Nếu `docker compose build` lỗi ở tag golang:1.26-bookworm không tồn tại,
  báo tôi — có thể cần bump dòng FROM trong ARTEX/Dockerfile:24.
```

---

## Sau khi cài xong, lần chạy đầu

Vẫn trong Claude Code local, dán tiếp:

```
Chạy một task thử trong ARTEX trên target lab juiceshop:
1. Mở http://localhost:8787, tạo task mới, target http://juiceshop:3000
2. Goal hẹp: "Tìm IDOR trong API /rest/basket"
3. Worker = 1 (Cấu hình hệ thống), không phải 3
4. Trong lúc nó chạy, mở 2 cửa sổ theo dõi:
   - Get-Content deploy\data\audit.jsonl -Wait -Tail 20
   - docker compose -f deploy\docker-compose.yml logs -f artex
5. Để nó chạy 15-20 phút rồi dừng. Báo cho tôi:
   - Agent đã gửi request tới những host nào (từ audit.jsonl)
   - Có request nào bị bbguard DENY không, lý do gì
   - Tốn bao nhiêu token (trang Token trong UI)
   - Nó report finding gì, và finding đó có traffic binding không
Đừng tự đánh giá finding là thật hay không — chỉ báo nó nói gì.
```

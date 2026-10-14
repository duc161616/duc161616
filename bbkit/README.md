# bbkit

Glue giữa ARTEX và một workflow bug bounty không tự hại mình.

| File | Việc |
|---|---|
| `intercept-rules.json` | 9 intercept rule cho BB, đúng schema `POST /api/intercept/rules`. Quan trọng nhất: **deny mọi lệnh né proxy**. Mỗi rule mang theo `should_match`/`should_not_match` làm test corpus |
| `validate-rules/` | Compile mọi pattern bằng **Go regexp (RE2)** và chạy corpus. ARTEX match rule bằng RE2 (`intercept/intercept.go:545`), **không có lookahead** — pattern viết kiểu PCRE sẽ không compile và rule đó im lặng không bao giờ bắn |
| `load_rules.py` | Nạp rule vào instance đang chạy |
| `triage.py` | Phân loại findings export thành 5 nhóm + dedupe. Không gán nhãn "verified" cho bất cứ thứ gì |
| `report.py` | Dựng khung report H1/Bugcrowd, claim của agent được dán nhãn unverified, mọi chỗ cần proof để `TODO` |

```bash
go run ./bbkit/validate-rules bbkit/intercept-rules.json
python3 bbkit/load_rules.py --base http://localhost:8787 --token "$ARTEX_JWT" --dry-run
python3 bbkit/triage.py findings.json
python3 bbkit/report.py findings.json --id 101 > report.md
```

Sửa rule thì **chạy lại validator** — đó chính là cái bắt được 2 pattern lookahead
không compile được trong lần viết đầu.

Chi tiết quy trình: [`../BUG-HUNTER-SETUP.md`](../BUG-HUNTER-SETUP.md)

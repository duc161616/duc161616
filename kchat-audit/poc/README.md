# Sandbox reproduction

All of this runs against loopback only. Electron is started with
`--proxy-server=http://127.0.0.1:9` so the app cannot reach any real host;
no request was ever sent to Infomaniak infrastructure.

## Setup
```
cd <repo>                      # Infomaniak/desktop-kChat @ ae71674
npm run build:main && npm run build:renderer     # produces dist/
LAB=<this dir>
mkdir -p $LAB/xdg/Electron && cp $LAB/config.json $LAB/tokens.json $LAB/xdg/Electron/
```
`config.json` = victim has one configured server `http://127.0.0.1:8099`.
`tokens.json` = `{"token":"IK_ACCESS_TOKEN_SANDBOX_abc123"}` (stand-in for the
real Infomaniak OAuth access token the app stores there).

## Run
```
node kchat-server.js &         # victim's server; root 302s to the foreign origin
node attacker-rce.js &         # foreign origin 127.0.0.2:8098 + /static/kmeet.js payload
XDG_CONFIG_HOME=$LAB/xdg HOME=$LAB xvfb-run -a node_modules/.bin/electron dist/ \
  --disable-dev-mode --no-sandbox --password-store=basic --disable-gpu \
  --proxy-server=http://127.0.0.1:9
```

## Server variants used
| file | what it tests | result |
|---|---|---|
| `kchat-server.js` | `302` from server root to foreign origin | view navigates, preload present |
| `kchat-server-link.js` | `<a target="_blank">` vs plain same-tab `<a>` click | `_blank` -> openExternal (safe); same-tab -> view navigates, preload present |
| `kchat-server-iframe.js` | cross-origin `<iframe>` | preload NOT exposed (`desktopAPI: undefined`) |

## Attacker page variants
- `attacker-rce.js` – steals the token, persists itself via `update-teams`, then
  calls `desktopAPI.openKmeetCallWindow()`; serves the Node payload at
  `/static/kmeet.js` (runs `id`, writes `/tmp/KCHAT_RCE_PROOF.txt`, exfils).
- `attacker-perm.js` – same, but probes `getUserMedia` / `Notification.requestPermission`
  instead of executing code. Needs `permissions.json` =
  `{"commons":{"media":{"allowed":true},"notifications":{"allowed":true}}}`
  (i.e. the victim had previously allowed those for the *real* server).

## Captured output
- `rce.log` – code execution proof
- `exfil.log` – token / permission probe results
- `attacker.log` – full request + exfil timeline

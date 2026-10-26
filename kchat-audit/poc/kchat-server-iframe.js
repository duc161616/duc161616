// Legit kChat server whose page embeds a cross-origin iframe (e.g. a link preview /
// embed). Tests whether the externalAPI preload is exposed inside subframes,
// which would make token theft zero-click.
const http = require('http');
http.createServer((req, res) => {
  console.log('[server] ' + req.method + ' ' + req.url);
  if (req.url.startsWith('/api/v4/config/client')) { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify({Version:'9.5.0', SiteURL:'http://127.0.0.1:8099', SiteName:'lab'})); }
  if (req.url.startsWith('/api/v4/plugins/webapp')) { res.setHeader('Content-Type','application/json'); return res.end('[]'); }
  if (req.url.startsWith('/api/v4/license/client')) { res.setHeader('Content-Type','application/json'); return res.end('{}'); }
  res.setHeader('Content-Type', 'text/html');
  res.end('<html><body>legit server page<iframe src="http://127.0.0.2:8098/?via=iframe" width="300" height="200"></iframe></body></html>');
}).listen(8099, '127.0.0.1', () => console.log('[server] listening 127.0.0.1:8099'));

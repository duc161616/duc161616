// Legit kChat server. Root serves a page containing a chat-message-like link to a
// foreign origin and clicks it as a user would (same-tab <a>, no target attr),
// to determine whether a plain link click is enough to navigate the server view.
const http = require('http');
http.createServer((req, res) => {
  console.log('[server] ' + req.method + ' ' + req.url);
  if (req.url.startsWith('/api/v4/config/client')) { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify({Version:'9.5.0', SiteURL:'http://127.0.0.1:8099', SiteName:'lab'})); }
  if (req.url.startsWith('/api/v4/plugins/webapp')) { res.setHeader('Content-Type','application/json'); return res.end('[]'); }
  if (req.url.startsWith('/api/v4/license/client')) { res.setHeader('Content-Type','application/json'); return res.end('{}'); }
  res.setHeader('Content-Type', 'text/html');
  res.end(`<html><body>
    <a id="sametab" href="http://127.0.0.2:8098/?via=sametab-link">same-tab link</a>
    <a id="blank" href="http://127.0.0.2:8098/?via=blank-link" target="_blank" rel="noreferrer">new-tab link</a>
    <script>
      // First probe the target=_blank form (what Mattermost markdown renders),
      // then the plain same-tab form.
      setTimeout(() => document.getElementById('blank').click(), 1000);
      setTimeout(() => document.getElementById('sametab').click(), 3000);
    </script></body></html>`);
}).listen(8099, '127.0.0.1', () => console.log('[server] listening 127.0.0.1:8099'));

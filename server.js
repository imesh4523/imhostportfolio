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

// Active pair tokens with 10-minute expiry
const activePairTokens = new Map();

function getOrCreatePairToken() {
    const now = Date.now();
    for (const [token, info] of activePairTokens.entries()) {
        if (info.expiresAt > now) {
            return { token, expiresAt: info.expiresAt };
        } else {
            activePairTokens.delete(token);
        }
    }
    const newToken = 'pair_' + crypto.randomBytes(10).toString('hex');
    const expiresAt = now + (10 * 60 * 1000); // 10 minutes
    activePairTokens.set(newToken, { createdAt: now, expiresAt });
    return { token: newToken, expiresAt };
}

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
            let userRes = await pool.query('SELECT id FROM telegram_users LIMIT 1');
            let userId = userRes.rows[0]?.id || 1;

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

    // 5. User Login & Signup Page UI
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
        body { background: #050a12; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .auth-card { background: #0d1522; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 24px; max-width: 440px; width: 100%; padding: 36px; box-shadow: 0 20px 50px rgba(0,0,0,0.6); }
        .logo-row { text-align: center; margin-bottom: 25px; }
        .logo-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(0, 245, 196, 0.1); color: #00f5c4; padding: 6px 16px; border-radius: 100px; font-size: 0.85rem; font-weight: 700; border: 1px solid rgba(0, 245, 196, 0.2); }
        .tabs { display: flex; background: rgba(255,255,255,0.04); padding: 4px; border-radius: 12px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.06); }
        .tab-btn { flex: 1; padding: 10px; border: none; background: transparent; color: #94a3b8; font-weight: 700; font-size: 0.9rem; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
        .tab-btn.active { background: #00f5c4; color: #050a12; box-shadow: 0 4px 12px rgba(0,245,196,0.3); }
        .input-group { margin-bottom: 16px; text-align: left; }
        .input-group label { display: block; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; font-weight: 700; margin-bottom: 6px; }
        .input-group input { width: 100%; padding: 12px 14px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; font-size: 0.95rem; outline: none; }
        .input-group input:focus { border-color: #00f5c4; }
        .btn-submit { width: 100%; padding: 14px; background: linear-gradient(135deg, #00f5c4, #00c9ff); color: #041019; border: none; border-radius: 12px; font-weight: 800; font-size: 1rem; cursor: pointer; margin-top: 10px; }
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
        <div class="footer-link"><a href="/">← Return to IM HOST Home</a></div>
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
                if (!res.ok || !data.success) throw new Error(data.message || 'Authentication failed');
                localStorage.setItem('imhost_user', JSON.stringify(data.user));
                msgBox.className = 'msg-box msg-success';
                msgBox.innerText = data.message || 'Success! Redirecting...';
                msgBox.style.display = 'block';
                setTimeout(() => { window.location.href = '/dashboard'; }, 1000);
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

    // 7. Pairing UI Endpoint: /pair or /pair/:token (10-minute auto-refresh + already connected state)
    if (pathname === '/pair' || pathname.startsWith('/pair/')) {
        let token = pathname.replace(/^\/pair\/?/, '').trim();
        const now = Date.now();
        let tokenData = activePairTokens.get(token);

        // If no token or token expired (older than 10 mins), generate fresh 10-minute token and redirect
        if (!token || !tokenData || tokenData.expiresAt <= now) {
            const pairInfo = getOrCreatePairToken();
            res.writeHead(302, { Location: `/pair/${pairInfo.token}` });
            return res.end();
        }

        const pairUrl = `${baseUrl}/pair/${token}`;
        const currentGatewayUrl = (await getDbSetting('PAYHERE_GATEWAY_URL')) || '';
        const mainAppUrl = (await getDbSetting('APP_URL')) || 'https://youuhost.com';
        const isPaired = (await getDbSetting('PAYHERE_STATUS')) === 'connected' && currentGatewayUrl.length > 0;
        const remainingSeconds = Math.max(0, Math.floor((tokenData.expiresAt - now) / 1000));

        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer-when-downgrade">
    <title>IM HOST - PayHere Gateway Pairing Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: #070c14; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(255, 255, 255, 0.1); backdrop-filter: blur(20px); border-radius: 24px; max-width: 600px; width: 100%; padding: 40px; text-align: center; box-shadow: 0 25px 60px rgba(0,0,0,0.6); }
        .badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(0, 245, 196, 0.12); color: #00f5c4; padding: 6px 16px; border-radius: 100px; font-size: 0.85rem; font-weight: 700; margin-bottom: 20px; border: 1px solid rgba(0, 245, 196, 0.25); }
        .pairing-box { background: rgba(0, 0, 0, 0.45); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 16px; padding: 20px; text-align: left; margin-bottom: 25px; }
        .url-row { display: flex; align-items: center; gap: 10px; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; padding: 12px 14px; }
        .url-text { flex: 1; font-family: monospace; font-size: 0.9rem; color: #38bdf8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .btn-copy { background: #00f5c4; color: #041019; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 800; font-size: 0.85rem; cursor: pointer; transition: all 0.2s; }
        .btn-copy:hover { transform: scale(1.03); }
        .timer-badge { display: flex; align-items: center; justify-content: space-between; margin-top: 10px; font-size: 0.8rem; color: #94a3b8; }
        .timer-val { color: #facc15; font-weight: 700; font-family: monospace; }
        .status-container { padding: 18px; border-radius: 14px; font-size: 0.95rem; font-weight: 700; text-align: center; margin-top: 20px; line-height: 1.5; }
        .status-waiting { background: rgba(234, 179, 8, 0.1); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.25); }
        .status-success { background: rgba(34, 197, 94, 0.12); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
        .btn-new-code { display: inline-block; margin-top: 15px; font-size: 0.8rem; color: #94a3b8; text-decoration: none; border-bottom: 1px dashed #64748b; }
        .btn-new-code:hover { color: #38bdf8; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">⚡ PayHere Approved Domain Gateway</div>
        <h1 style="font-size:1.6rem; font-weight:800;">Gateway Pairing Portal</h1>
        <p style="color:#94a3b8; margin: 10px 0 25px; font-size:0.9rem;">Copy this 1-click Pairing link and paste it into your <b>Admin Dashboard (PayHere Gateway)</b> to synchronize checkout & webhooks.</p>
        
        <div class="pairing-box">
            <div style="display:flex; justify-content:space-between; font-size:0.75rem; text-transform:uppercase; color:#64748b; font-weight:700; margin-bottom:8px;">
                <span>Active 1-Click Pairing Link</span>
                <span class="timer-val" id="countdownDisplay">10:00</span>
            </div>
            <div class="url-row">
                <span class="url-text" id="pairUrl">${pairUrl}</span>
                <button class="btn-copy" id="copyBtn" onclick="copyPairUrl()">Copy Link</button>
            </div>
            <div class="timer-badge">
                <span>🔄 10-Minute Auto-Refresh Window</span>
                <span>Auto-generates fresh key if expired</span>
            </div>
        </div>

        <div id="statusBox" class="status-container ${isPaired ? 'status-success' : 'status-waiting'}">
            ${isPaired 
                ? '✅ THIS LINK IS ALREADY CONNECTED & ACTIVE!<br><span style="font-size:0.85rem; color:#86efac; font-weight:500;">Paired with Shopeefy Main Store (' + mainAppUrl + ')</span>' 
                : '⏳ Waiting for Admin Dashboard to connect with this link...'}
        </div>

        <div>
            <a href="/pair" class="btn-new-code">🔄 Generate Fresh Pairing Code</a>
        </div>
    </div>

    <script>
        let secondsLeft = ${remainingSeconds};
        const countdownElem = document.getElementById('countdownDisplay');

        function updateCountdown() {
            const m = Math.floor(secondsLeft / 60).toString().padStart(2, '0');
            const s = (secondsLeft % 60).toString().padStart(2, '0');
            countdownElem.innerText = 'Expires in ' + m + ':' + s;
            if (secondsLeft <= 0) {
                window.location.href = '/pair';
            } else {
                secondsLeft--;
            }
        }
        updateCountdown();
        setInterval(updateCountdown, 1000);

        function copyPairUrl() {
            navigator.clipboard.writeText(document.getElementById('pairUrl').innerText).then(() => {
                const btn = document.getElementById('copyBtn');
                btn.innerText = 'Copied! ✓';
                btn.style.background = '#4ade80';
                setTimeout(() => { 
                    btn.innerText = 'Copy Link'; 
                    btn.style.background = '#00f5c4';
                }, 2000);
            });
        }

        // Real-time status poll every 2s
        setInterval(async () => {
            try {
                const res = await fetch('/api/pair/status?token=${token}');
                const data = await res.json();
                const box = document.getElementById('statusBox');
                if (data.status === 'connected') {
                    box.className = 'status-container status-success';
                    box.innerHTML = '✅ THIS LINK IS ALREADY CONNECTED & ACTIVE!<br><span style="font-size:0.85rem; color:#86efac; font-weight:500;">Paired with Shopeefy Main Store (' + (data.mainAppUrl || 'https://youuhost.com') + ')</span>';
                }
            } catch (e) {}
        }, 2000);
    </script>
</body>
</html>`);
    }

    // 8. API: Pair Status Poll
    if (pathname === '/api/pair/status') {
        const queryToken = parsedUrl.query.token || '';
        const status = (await getDbSetting('PAYHERE_STATUS')) || 'waiting';
        const gatewayUrl = (await getDbSetting('PAYHERE_GATEWAY_URL')) || '';
        const mainAppUrl = (await getDbSetting('APP_URL')) || 'https://youuhost.com';
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

        if (mainAppUrl) await setDbSetting('APP_URL', mainAppUrl);
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

        const itemDescription = `API Checking Service #${paymentRow.id}`;

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
                await pool.query(
                    `UPDATE payments SET status = 'completed', external_id = $1, updated_at = NOW() WHERE id = $2`,
                    [payment_id ? `PAYHERE_${payment_id}` : order_id, parsedPaymentId]
                );

                const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parsedPaymentId]);
                const pRow = pRes.rows[0];

                if (pRow && pRow.telegram_user_id) {
                    let creditCents = pRow.amount;
                    if ((pRow.currency || '').toUpperCase() === 'LKR') {
                        const lkrRate = 305.50;
                        const usdAmount = (pRow.amount / 100) / lkrRate;
                        creditCents = Math.round(usdAmount * 100);
                    }
                    await pool.query(
                        `UPDATE telegram_users SET balance = balance + $1 WHERE id = $2`,
                        [creditCents, pRow.telegram_user_id]
                    );
                    console.log(`[IM HOST IPN] Credited ${creditCents} USD cents (${pRow.currency} ${pRow.amount / 100}) to user #${pRow.telegram_user_id}`);
                }
            } catch (err) {
                console.error('[IM HOST IPN] Database update error:', err.message);
            }

            res.writeHead(200);
            return res.end('OK');
        }

        res.writeHead(200);
        return res.end('Ignored non-success status: ' + status_code);
    }

    // 12. Payment Return & Cancel URLs
    if (pathname === '/payment-return') {
        const paymentId = parsedUrl.query.payment_id;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Payment Complete</title>
<style>body{background:#050a12;color:#fff;font-family:sans-serif;text-align:center;padding:80px 20px;}
.box{background:#0d1522;padding:40px;border-radius:20px;max-width:440px;margin:0 auto;border:1px solid rgba(255,255,255,0.1);}</style></head>
<body>
<div class="box">
    <h1 style="color:#00f5c4;font-size:3rem;">✓</h1>
    <h2>Payment Successful!</h2>
    <p style="color:#94a3b8;margin:15px 0 25px;">Your deposit #${paymentId || ''} has been credited to your account balance.</p>
    <a href="/" style="display:inline-block;padding:12px 24px;background:#00f5c4;color:#000;border-radius:10px;text-decoration:none;font-weight:700;">Return to Home</a>
</div>
</body></html>`);
    }

    if (pathname === '/payment-cancel') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Payment Cancelled</title>
<style>body{background:#050a12;color:#fff;font-family:sans-serif;text-align:center;padding:80px 20px;}
.box{background:#0d1522;padding:40px;border-radius:20px;max-width:440px;margin:0 auto;border:1px solid rgba(255,255,255,0.1);}</style></head>
<body>
<div class="box">
    <h1 style="color:#f87171;font-size:3rem;">✕</h1>
    <h2>Payment Cancelled</h2>
    <p style="color:#94a3b8;margin:15px 0 25px;">The checkout transaction was cancelled.</p>
    <a href="/" style="display:inline-block;padding:12px 24px;background:#38bdf8;color:#000;border-radius:10px;text-decoration:none;font-weight:700;">Return to Home</a>
</div>
</body></html>`);
    }

    // 13. Serve Static Files from directory
    let safePath = pathname === '/' ? '/index.html' : pathname;
    let filePath = path.join(__dirname, safePath);

    fs.stat(filePath, (err, stats) => {
        if (!err && stats.isFile()) {
            const ext = path.extname(filePath).toLowerCase();
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            fs.createReadStream(filePath).pipe(res);
        } else {
            let indexPath = path.join(__dirname, 'index.html');
            fs.readFile(indexPath, (err2, content) => {
                if (err2) {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    res.end('404 Not Found');
                } else {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
                    res.end(content);
                }
            });
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[IM HOST] Production Gateway Server running on http://0.0.0.0:${PORT}`);
});

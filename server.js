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

// PostgreSQL Shared Database Pool (Robust SSL handling for DigitalOcean & remote PostgreSQL)
const rawDbUrl = process.env.DATABASE_URL || '';
const isLocalhost = !rawDbUrl || rawDbUrl.includes('localhost') || rawDbUrl.includes('127.0.0.1');

// Strip ?sslmode=require so node-postgres doesn't fail with 'self-signed certificate in certificate chain'
let cleanDbUrl = rawDbUrl;
if (!isLocalhost && cleanDbUrl) {
    cleanDbUrl = cleanDbUrl.replace(/[\?\&]sslmode=[^&]*/g, '');
    if (cleanDbUrl.endsWith('?') || cleanDbUrl.endsWith('&')) {
        cleanDbUrl = cleanDbUrl.slice(0, -1);
    }
}

const pool = new Pool({
    connectionString: cleanDbUrl,
    ssl: isLocalhost ? false : { rejectUnauthorized: false }
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
    <title>Connecting to Secure Gateway...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #050a12; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
        .spinner { width: 44px; height: 44px; border: 4px solid rgba(0, 245, 196, 0.15); border-top-color: #00f5c4; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        h3 { font-size: 1.15rem; font-weight: 700; color: #e2e8f0; margin-bottom: 8px; }
        p { font-size: 0.85rem; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="spinner"></div>
    <h3>Connecting to Secure Gateway...</h3>
    <p>Please wait a moment while we redirect you to payment...</p>

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
        <input type="hidden" name="email" value="support@imhosteepay.online">
        <input type="hidden" name="phone" value="${phone}">
        <input type="hidden" name="address" value="Sri Lanka">
        <input type="hidden" name="city" value="Colombo">
        <input type="hidden" name="country" value="Sri Lanka">
        <input type="hidden" name="hash" value="${hash}">
        <input type="hidden" name="custom_1" value="${paymentRow.telegram_user_id}">
        <input type="hidden" name="custom_2" value="${paymentRow.id}">
    </form>
    <script>
        document.getElementById('payhereForm').submit();
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

        // Direct /buy route for portfolio & items
    if (pathname === '/buy' || pathname.startsWith('/buy')) {
        const planName = parsedUrl.query.plan || 'API Checking Plan';
        const rawAmount = parseFloat(parsedUrl.query.amount) || 100;
        const currency = (parsedUrl.query.currency || 'LKR').toUpperCase();
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
            return res.end('Database error creating buy session: ' + err.message);
        }
    }

    // 10. Checkout Route: /checkout (PayHere Auto Form & Direct Auto-Redirect)
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
        const currency = (paymentRow.currency || 'USD').toUpperCase();
        const orderId = `API_${paymentRow.id}`;

        // Item description requested by user
        const itemDescription = `API Checking Service #${paymentRow.id}`;

        const hashedSecret = crypto.createHash('md5').update(merchantSecret).digest('hex').toUpperCase();
        const hash = crypto.createHash('md5').update(merchantId + orderId + formattedAmount + currency + hashedSecret).digest('hex').toUpperCase();

        const returnUrl = `${baseUrl}/payment-return?payment_id=${paymentRow.id}`;
        const cancelUrl = `${baseUrl}/payment-cancel?payment_id=${paymentRow.id}`;
        const notifyUrl = `${baseUrl}/api/payhere-notify`;

        const firstName = sanitizeText(tgUserRow?.first_name, 'Customer');
        const lastName = sanitizeText(tgUserRow?.last_name, 'Client');
        // User requirement: Assign PayHere customer email strictly to support@imhosteepay.online so PayHere receipts never go to customers
        const email = 'support@imhosteepay.online';
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
    <title>Connecting to Secure Gateway...</title>
    <script src="/assets/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #F8F9FD;
            color: #181432;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 20px;
        }
        .checkout-box {
            background: #FFFFFF;
            border: 1px solid #ECEEF8;
            border-radius: 28px;
            padding: 32px 24px;
            max-width: 360px;
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            box-shadow: 0 20px 40px -15px rgba(24, 20, 50, 0.08);
        }
        #lottie-payment {
            width: 180px;
            height: 180px;
            margin-bottom: 8px;
        }
        h3 {
            font-size: 1.15rem;
            font-weight: 800;
            color: #181432;
            letter-spacing: -0.01em;
            margin-bottom: 6px;
        }
        p {
            font-size: 0.85rem;
            font-weight: 600;
            color: #7E7998;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="checkout-box">
        <div id="lottie-payment"></div>
        <h3>Connecting to Payment Gateway...</h3>
        <p>Preparing secure checkout for ${currency} ${formattedAmount}...</p>
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
    </form>
    <script>
        function startAnim() {
            fetch('/assets/animation-payment.json')
                .then(res => res.json())
                .then(animationData => {
                    if (window.lottie) {
                        window.lottie.loadAnimation({
                            container: document.getElementById('lottie-payment'),
                            renderer: 'svg',
                            loop: true,
                            autoplay: true,
                            animationData: animationData
                        });
                    }
                })
                .catch(() => {});
        }
        if (window.lottie) {
            startAnim();
        } else {
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js';
            script.onload = startAnim;
            document.head.appendChild(script);
        }

        setTimeout(function() {
            document.getElementById('payhereForm').submit();
        }, 3000);
    </script>
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
            custom_2,
            method,
            card_no,
            card_holder_name
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

            // Detect actual payment method (FriMi, iPay, Q+ Payment, Google Pay, Mastercard, Visa, etc.)
            let rawMethod = (method || '').trim();
            let mUpper = rawMethod.toUpperCase();
            let detectedMethod = 'card';
            if (mUpper.includes('FRIMI')) detectedMethod = 'frimi';
            else if (mUpper.includes('IPAY')) detectedMethod = 'ipay';
            else if (mUpper.includes('QPLUS') || mUpper.includes('Q+')) detectedMethod = 'qplus';
            else if (mUpper.includes('GOOGLE') || mUpper.includes('GPAY')) detectedMethod = 'google_pay';
            else if (mUpper.includes('MASTER')) detectedMethod = 'mastercard';
            else if (mUpper.includes('VISA')) detectedMethod = 'visa';
            else if (mUpper.includes('AMEX')) detectedMethod = 'amex';
            else if (rawMethod) detectedMethod = rawMethod.toLowerCase();

            try {
                await pool.query(
                    `UPDATE payments SET status = 'completed', external_id = $1, payment_method = $2, txid = $3, updated_at = NOW() WHERE id = $4`,
                    [payment_id ? `PAYHERE_${payment_id}` : order_id, detectedMethod, card_no || null, parsedPaymentId]
                );

                const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parsedPaymentId]);
                const pRow = pRes.rows[0];

                if (pRow && pRow.telegram_user_id) {
                    let creditCents = pRow.amount;
                    if ((pRow.currency || '').toUpperCase() === 'LKR') {
                        let lkrRate = 329.92;
                        try {
                            const https = require('https');
                            const ratePromise = new Promise((resolve) => {
                                const reqRate = https.get('https://open.er-api.com/v6/latest/USD', { timeout: 3000 }, (resp) => {
                                    let data = '';
                                    resp.on('data', chunk => data += chunk);
                                    resp.on('end', () => {
                                        try {
                                            const json = JSON.parse(data);
                                            if (json && json.rates && json.rates.LKR) {
                                                resolve(json.rates.LKR);
                                            } else {
                                                resolve(329.92);
                                            }
                                        } catch(e) { resolve(329.92); }
                                    });
                                });
                                reqRate.on('error', () => resolve(329.92));
                                reqRate.setTimeout(3000, () => { reqRate.destroy(); resolve(329.92); });
                            });
                            lkrRate = await ratePromise;
                        } catch (e) {
                            lkrRate = 329.92;
                        }
                        const usdAmount = (pRow.amount / 100) / lkrRate;
                        creditCents = Math.round(usdAmount * 100);
                    }
                    let creditLkr = Math.round(pRow.amount / 100);
                    if ((pRow.currency || '').toUpperCase() !== 'LKR') {
                        creditLkr = Math.round((creditCents / 100) * lkrRate);
                    }

                    await pool.query(
                        `UPDATE telegram_users SET balance = balance + $1, balance_lkr = COALESCE(balance_lkr, 0) + $2 WHERE id = $3`,
                        [creditCents, creditLkr, pRow.telegram_user_id]
                    );
                    console.log(`[IM HOST IPN] Credited ${creditCents} USD cents & ${creditLkr} LKR to user #${pRow.telegram_user_id}`);

                    // Notify main app to trigger receipt email and real-time dashboard events
                    try {
                        const http = require('http');
                        const notifyPayload = JSON.stringify({ 
                            paymentId: parsedPaymentId, 
                            secret: 'youuhost_internal_secret_2026',
                            method: detectedMethod,
                            cardNo: card_no || null,
                            cardHolderName: card_holder_name || null
                        });
                        const notifyTargets = [
                            { isHttps: true, hostname: 'youuhost.com', port: 443 },
                            { isHttps: false, hostname: '18.141.224.63', port: 80 },
                            { isHttps: false, hostname: '127.0.0.1', port: 80 },
                            { isHttps: false, hostname: '127.0.0.1', port: 5000 }
                        ];
                        for (const target of notifyTargets) {
                            try {
                                const client = target.isHttps ? require('https') : require('http');
                                const postReq = client.request({
                                    hostname: target.hostname,
                                    port: target.port,
                                    path: '/api/internal/payment-success',
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(notifyPayload) },
                                    timeout: 8000
                                });
                                postReq.on('error', (e) => {});
                                postReq.write(notifyPayload);
                                postReq.end();
                            } catch (e) {}
                        }
                    } catch (e) {}
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
        let redirectUrl = 'https://youuhost.com';
        try {
            if (paymentId) {
                const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parseInt(paymentId, 10)]);
                const pRow = pRes.rows[0];
                if (pRow && (pRow.external_id || '').startsWith('IMHOST_DIR_')) {
                    redirectUrl = '/profile';
                }
            }
        } catch (e) {}

        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Payment Successful</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="/assets/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #F8F9FD;
            color: #181432;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            text-align: center;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .box {
            background: #FFFFFF;
            padding: 36px 28px;
            border-radius: 28px;
            max-width: 380px;
            width: 100%;
            border: 1px solid #ECEEF8;
            box-shadow: 0 20px 40px -15px rgba(24, 20, 50, 0.08);
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        #lottie-box { width: 160px; height: 160px; margin-bottom: 8px; }
        h2 { font-size: 1.35rem; font-weight: 800; color: #181432; margin-bottom: 8px; }
        p { color: #7E7998; font-size: 0.85rem; font-weight: 600; line-height: 1.5; margin-bottom: 16px; }
        .redirect-text { font-size: 0.75rem; font-weight: 700; color: #6C5CE7; margin-bottom: 16px; }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 12px 24px;
            background: linear-gradient(135deg, #FF5E62, #D92078, #6C5CE7);
            color: #fff;
            border-radius: 16px;
            text-decoration: none;
            font-weight: 800;
            font-size: 0.88rem;
            box-shadow: 0 8px 20px -6px rgba(108, 92, 231, 0.4);
            transition: all 0.2s;
        }
        .btn:hover { opacity: 0.92; transform: scale(1.02); }
    </style>
</head>
<body>
<div class="box">
    <div id="lottie-box"></div>
    <h2>Payment Successful!</h2>
    <p>Your payment #${paymentId || ''} has been completed and credited to your balance.</p>
    <div class="redirect-text">Redirecting to store in <span id="timer">3</span>s...</div>
    <a href="${redirectUrl}" class="btn">Return to Store</a>
</div>
<script>
    function startAnim() {
        fetch('/assets/animation-payment.json')
            .then(res => res.json())
            .then(animationData => {
                if (window.lottie) {
                    window.lottie.loadAnimation({
                        container: document.getElementById('lottie-box'),
                        renderer: 'svg',
                        loop: false,
                        autoplay: true,
                        animationData: animationData
                    });
                }
            }).catch(() => {});
    }
    if (window.lottie) {
        startAnim();
    } else {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js';
        script.onload = startAnim;
        document.head.appendChild(script);
    }

    let timeLeft = 3;
    const timerEl = document.getElementById('timer');
    const interval = setInterval(() => {
        timeLeft--;
        if (timerEl) timerEl.innerText = timeLeft;
        if (timeLeft <= 0) {
            clearInterval(interval);
            window.location.href = "${redirectUrl}";
        }
    }, 1000);
</script>
</body></html>`);
    }

    if (pathname === '/payment-cancel') {
        const paymentId = parsedUrl.query.payment_id;
        let redirectUrl = 'https://youuhost.com';
        try {
            if (paymentId) {
                const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parseInt(paymentId, 10)]);
                const pRow = pRes.rows[0];
                if (pRow && (pRow.external_id || '').startsWith('IMHOST_DIR_')) {
                    redirectUrl = '/profile';
                }
            }
        } catch (e) {}

        res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Payment Cancelled</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="/assets/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #F8F9FD;
            color: #181432;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            text-align: center;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .box {
            background: #FFFFFF;
            padding: 36px 28px;
            border-radius: 28px;
            max-width: 380px;
            width: 100%;
            border: 1px solid #ECEEF8;
            box-shadow: 0 20px 40px -15px rgba(24, 20, 50, 0.08);
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        #lottie-box { width: 160px; height: 160px; margin-bottom: 8px; }
        h2 { font-size: 1.35rem; font-weight: 800; color: #181432; margin-bottom: 8px; }
        p { color: #7E7998; font-size: 0.85rem; font-weight: 600; line-height: 1.5; margin-bottom: 16px; }
        .redirect-text { font-size: 0.75rem; font-weight: 700; color: #6C5CE7; margin-bottom: 16px; }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 12px 24px;
            background: linear-gradient(135deg, #FF5E62, #D92078, #6C5CE7);
            color: #fff;
            border-radius: 16px;
            text-decoration: none;
            font-weight: 800;
            font-size: 0.88rem;
            box-shadow: 0 8px 20px -6px rgba(108, 92, 231, 0.4);
            transition: all 0.2s;
        }
        .btn:hover { opacity: 0.92; transform: scale(1.02); }
    </style>
</head>
<body>
<div class="box">
    <div id="lottie-box"></div>
    <h2>Payment Cancelled</h2>
    <p>The checkout transaction was cancelled.</p>
    <div class="redirect-text">Redirecting to store in <span id="timer">3</span>s...</div>
    <a href="${redirectUrl}" class="btn">Return to Store</a>
</div>
<script>
    function startAnim() {
        fetch('/assets/animation-payment.json')
            .then(res => res.json())
            .then(animationData => {
                if (window.lottie) {
                    window.lottie.loadAnimation({
                        container: document.getElementById('lottie-box'),
                        renderer: 'svg',
                        loop: true,
                        autoplay: true,
                        animationData: animationData
                    });
                }
            }).catch(() => {});
    }
    if (window.lottie) {
        startAnim();
    } else {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js';
        script.onload = startAnim;
        document.head.appendChild(script);
    }

    let timeLeft = 3;
    const timerEl = document.getElementById('timer');
    const interval = setInterval(() => {
        timeLeft--;
        if (timerEl) timerEl.innerText = timeLeft;
        if (timeLeft <= 0) {
            clearInterval(interval);
            window.location.href = "${redirectUrl}";
        }
    }, 1000);
</script>
</body></html>`);
    }

    // 13. Dedicated /profile route for portfolio (index.html)
    if (pathname === '/profile' || pathname === '/profile/') {
        let indexPath = path.join(__dirname, 'index.html');
        return fs.readFile(indexPath, (err, content) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                return res.end('Error loading profile page');
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
            return res.end(content);
        });
    }

    // Root path domain/ or /index.html returns 404 error page as requested
    if (pathname === '/' || pathname === '' || pathname === '/index.html') {
        let notFoundPath = path.join(__dirname, '404.html');
        return fs.readFile(notFoundPath, (err, content) => {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
            if (!err && content) {
                return res.end(content);
            }
            return res.end('<h1>404 - Page Not Found</h1>');
        });
    }

    // 14. Serve Static Files from directory & 404 Route for unmatched paths
    let filePath = path.join(__dirname, pathname);

    fs.stat(filePath, (err, stats) => {
        if (!err && stats.isFile()) {
            const ext = path.extname(filePath).toLowerCase();
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            fs.createReadStream(filePath).pipe(res);
        } else {
            let notFoundPath = path.join(__dirname, '404.html');
            fs.readFile(notFoundPath, (err2, content) => {
                res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
                if (!err2 && content) {
                    res.end(content);
                } else {
                    res.end('<h1>404 - Page Not Found</h1>');
                }
            });
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[IM HOST] Production Gateway Server running on http://0.0.0.0:${PORT}`);
});

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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #050a12;
            color: #f1f5f9;
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
            background: rgba(13, 21, 34, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 28px;
            padding: 32px 24px;
            max-width: 360px;
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(12px);
        }
        #lottie-payment {
            width: 180px;
            height: 180px;
            margin-bottom: 12px;
        }
        h3 {
            font-size: 1.15rem;
            font-weight: 800;
            color: #ffffff;
            letter-spacing: -0.01em;
            margin-bottom: 6px;
        }
        p {
            font-size: 0.85rem;
            font-weight: 500;
            color: #94a3b8;
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
        fetch('/assets/animation-payment.json')
            .then(res => res.json())
            .then(animationData => {
                lottie.loadAnimation({
                    container: document.getElementById('lottie-payment'),
                    renderer: 'svg',
                    loop: true,
                    autoplay: true,
                    animationData: animationData
                });
            })
            .catch(() => {});

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
        let redirectUrl = 'https://youuhost.com';
        try {
            if (paymentId) {
                const pRes = await pool.query('SELECT * FROM payments WHERE id = $1 LIMIT 1', [parseInt(paymentId, 10)]);
                const pRow = pRes.rows[0];
                if (pRow && (pRow.external_id || '').startsWith('IMHOST_DIR_')) {
                    redirectUrl = '/';
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background:#050a12; color:#fff; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align:center; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
        .box { background:rgba(13, 21, 34, 0.9); padding:36px 28px; border-radius:28px; max-width:400px; width:100%; border:1px solid rgba(255,255,255,0.1); box-shadow:0 25px 50px -12px rgba(0,0,0,0.6); backdrop-filter:blur(12px); display:flex; flex-direction:column; align-items:center; }
        #lottie-box { width: 140px; height: 140px; margin-bottom: 8px; }
        h2 { font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 8px; }
        p { color: #94a3b8; font-size: 0.85rem; line-height: 1.5; margin-bottom: 20px; }
        .btn { display:inline-block; padding:12px 28px; background:linear-gradient(135deg, #00f5c4, #00c9a7); color:#000; border-radius:14px; text-decoration:none; font-weight:800; font-size: 0.9rem; transition: all 0.2s; }
        .btn:hover { opacity: 0.9; transform: scale(1.02); }
    </style>
</head>
<body>
<div class="box">
    <div id="lottie-box"></div>
    <h2>Payment Successful!</h2>
    <p>Your payment #${paymentId || ''} has been completed and credited to your balance.</p>
    <a href="${redirectUrl}" class="btn">Return to Store</a>
</div>
<script>
    fetch('/assets/animation-payment.json')
        .then(res => res.json())
        .then(animationData => {
            lottie.loadAnimation({
                container: document.getElementById('lottie-box'),
                renderer: 'svg',
                loop: false,
                autoplay: true,
                animationData: animationData
            });
        }).catch(() => {});
    setTimeout(function() { window.location.href = "${redirectUrl}"; }, 3500);
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
                    redirectUrl = '/';
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background:#050a12; color:#fff; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align:center; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
        .box { background:rgba(13, 21, 34, 0.9); padding:36px 28px; border-radius:28px; max-width:400px; width:100%; border:1px solid rgba(255,255,255,0.1); box-shadow:0 25px 50px -12px rgba(0,0,0,0.6); backdrop-filter:blur(12px); display:flex; flex-direction:column; align-items:center; }
        #lottie-box { width: 140px; height: 140px; margin-bottom: 8px; }
        h2 { font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 8px; }
        p { color: #94a3b8; font-size: 0.85rem; line-height: 1.5; margin-bottom: 20px; }
        .btn { display:inline-block; padding:12px 28px; background:rgba(255,255,255,0.1); color:#fff; border-radius:14px; text-decoration:none; font-weight:700; font-size: 0.9rem; border:1px solid rgba(255,255,255,0.15); transition: all 0.2s; }
        .btn:hover { background: rgba(255,255,255,0.18); transform: scale(1.02); }
    </style>
</head>
<body>
<div class="box">
    <div id="lottie-box"></div>
    <h2>Payment Cancelled</h2>
    <p>The checkout transaction was cancelled.</p>
    <a href="${redirectUrl}" class="btn">Return to Store</a>
</div>
<script>
    fetch('/assets/animation-payment.json')
        .then(res => res.json())
        .then(animationData => {
            lottie.loadAnimation({
                container: document.getElementById('lottie-box'),
                renderer: 'svg',
                loop: false,
                autoplay: true,
                animationData: animationData
            });
        }).catch(() => {});
    setTimeout(function() { window.location.href = "${redirectUrl}"; }, 3500);
</script>
</body></html>`);
    }

    // 13. Serve Static Files from directory & 404 Route
    let safePath = pathname === '/' ? '/index.html' : pathname;
    let filePath = path.join(__dirname, safePath);

    fs.stat(filePath, (err, stats) => {
        if (!err && stats.isFile()) {
            const ext = path.extname(filePath).toLowerCase();
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            fs.createReadStream(filePath).pipe(res);
        } else {
            // Render 404 Not Found Page with animation
            res.writeHead(404, { 'Content-Type': 'text/html; charset=UTF-8' });
            res.end(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lottie-web/5.12.2/lottie.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #050a12;
            color: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 20px;
            overflow: hidden;
            user-select: none;
        }
        .container-404 {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            max-width: 440px;
            width: 100%;
        }
        #lottie-404 {
            width: 320px;
            height: 320px;
            max-width: 85vw;
            max-height: 60vh;
            margin: 0 auto;
        }
        h1 {
            font-size: 1.8rem;
            font-weight: 800;
            color: #f1f5f9;
            margin-top: 10px;
            letter-spacing: -0.02em;
        }
    </style>
</head>
<body>
    <div class="container-404">
        <div id="lottie-404"></div>
        <h1>404 - Page Not Found</h1>
    </div>
    <script>
        fetch('/assets/animation-404.json')
            .then(res => res.json())
            .then(animationData => {
                lottie.loadAnimation({
                    container: document.getElementById('lottie-404'),
                    renderer: 'svg',
                    loop: true,
                    autoplay: true,
                    animationData: animationData
                });
            })
            .catch(() => {});
    </script>
</body>
</html>`);
        }
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[IM HOST] Production Gateway Server running on http://0.0.0.0:${PORT}`);
});

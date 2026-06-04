const express = require('express');
const multer = require('multer');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cron = require('node-cron');

const app = express();
const PORT = 3006;

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session management
const sessions = new Map();
app.use((req, res, next) => {
    const token = req.headers['x-session-token'] || req.query.token;
    if (token && sessions.has(token)) {
        req.sessionData = sessions.get(token);
        req.sessionToken = token;
    }
    next();
});

// File upload config
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Directories
const REPORTS_DIR = path.join(__dirname, 'reports');
const CONFIG_DIR = path.join(__dirname, 'config');
const TENANTS_FILE = path.join(CONFIG_DIR, 'tenants.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PS_SCRIPT = path.join(__dirname, 'report-runner.ps1');
const SCHEDULE_FILE = path.join(CONFIG_DIR, 'schedule.json');

[REPORTS_DIR, CONFIG_DIR, UPLOADS_DIR].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ==================== HELPERS ====================
function loadTenants() {
    try {
        if (fs.existsSync(TENANTS_FILE)) {
            return JSON.parse(fs.readFileSync(TENANTS_FILE, 'utf8'));
        }
    } catch (e) { console.error('Failed to load tenants:', e.message); }
    return [];
}

function findTenant(tenantId) {
    return loadTenants().find(t => t.tenantId === tenantId) || null;
}

function scanReports() {
    const reports = [];
    try {
        if (!fs.existsSync(REPORTS_DIR)) return reports;
        const entries = fs.readdirSync(REPORTS_DIR);
        for (const entry of entries) {
            const entryPath = path.join(REPORTS_DIR, entry);
            const stat = fs.statSync(entryPath);
            if (stat.isDirectory()) {
                try {
                    const files = fs.readdirSync(entryPath);
                    const htmlFile = files.find(f => f.endsWith('.html'));
                    const logFile = files.find(f => f === 'Execution.log');
                    if (htmlFile) {
                        const htmlStat = fs.statSync(path.join(entryPath, htmlFile));
                        let logContent = '';
                        if (logFile) {
                            logContent = fs.readFileSync(path.join(entryPath, logFile), 'utf8').slice(-2000);
                        }
                        reports.push({
                            id: entry,
                            folder: entry,
                            file: htmlFile,
                            size: htmlStat.size,
                            created: htmlStat.mtime,
                            path: entryPath,
                            log: logContent
                        });
                    }
                } catch (e) { /* skip */ }
            }
        }
    } catch (e) { console.error('Scan error:', e.message); }
    reports.sort((a, b) => new Date(b.created) - new Date(a.created));
    return reports;
}

// ==================== AUTH ====================
app.post('/api/login', (req, res) => {
    const { tenantId, clientId, clientSecret } = req.body;
    if (!tenantId || !clientId || !clientSecret) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const tenant = findTenant(tenantId);
    const tenantName = tenant ? tenant.name : tenantId;
    sessions.set(token, { tenantId, clientId, clientSecret, tenantName, created: Date.now() });
    res.json({ success: true, token, tenantName });
});

app.get('/api/logout', (req, res) => {
    const token = req.headers['x-session-token'];
    if (token) sessions.delete(token);
    res.json({ success: true });
});

app.get('/api/tenants', (req, res) => {
    const tenants = loadTenants().map(t => ({
        tenantId: t.tenantId,
        clientId: t.clientId,
        name: t.name,
        email: t.email || ''
    }));
    res.json(tenants);
});

app.get('/api/session-check', (req, res) => {
    res.json({ valid: !!req.sessionData });
});

app.get('/', (req, res) => {
    res.render('index');
});

// ==================== REPORT GENERATION ====================
app.post('/api/generate', upload.single('logo'), (req, res) => {
    if (!req.sessionData) {
        return res.status(401).json({ success: false, error: 'Session expired. Please login again.' });
    }

    const { tenantId, clientId, clientSecret, logoPath: existingLogo } = req.sessionData;

    // Logo
    let logoPath = '';
    if (req.file) {
        const ext = path.extname(req.file.originalname);
        logoPath = path.join(UPLOADS_DIR, `logo${ext}`);
        fs.copyFileSync(req.file.path, logoPath);
        fs.unlinkSync(req.file.path);
    } else if (existingLogo && fs.existsSync(existingLogo)) {
        logoPath = existingLogo;
    }

    // Output
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const outputDir = path.join(REPORTS_DIR, timestamp);
    fs.mkdirSync(outputDir, { recursive: true });

    // Environment
    const env = {
        ...process.env,
        REPORT_TENANT_ID: tenantId,
        REPORT_CLIENT_ID: clientId,
        REPORT_CLIENT_SECRET: clientSecret,
        REPORT_OUTPUT_PATH: outputDir,
        REPORT_LOGO_PATH: logoPath
    };

    console.log(`[${new Date().toISOString()}] Generating report for tenant ${tenantId}...`);

    const ps = spawn('pwsh.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT], {
        env,
        cwd: __dirname,
        shell: true
    });

    let stdout = '';
    let stderr = '';

    ps.stdout.on('data', d => { stdout += d.toString(); });
    ps.stderr.on('data', d => { stderr += d.toString(); });

    ps.on('error', err => {
        console.error('PowerShell error:', err.message);
        if (logoPath && req.file) try { fs.unlinkSync(logoPath); } catch(e) {}
        res.status(500).json({ success: false, error: err.message });
    });

    const timeout = setTimeout(() => {
        try { ps.kill(); } catch(e) {}
        res.status(500).json({ success: false, error: 'Report generation timed out (15 min limit)' });
    }, 15 * 60 * 1000);

    ps.on('close', code => {
        clearTimeout(timeout);
        if (logoPath && req.file) try { fs.unlinkSync(logoPath); } catch(e) {}

        if (code === 0) {
            const files = fs.readdirSync(outputDir);
            const htmlFile = files.find(f => f.endsWith('.html'));
            console.log(`[${new Date().toISOString()}] Report generated: ${htmlFile}`);
            res.json({
                success: true,
                outputDir: outputDir,
                htmlFile: htmlFile || null,
                reportId: timestamp
            });
        } else {
            console.error(`[${new Date().toISOString()}] PowerShell exit ${code}`);
            res.status(500).json({
                success: false,
                error: `Script failed (exit ${code})`,
                details: stderr.slice(-1000)
            });
        }
    });
});

// ==================== REPORTS ====================
app.get('/api/reports', (req, res) => {
    if (!req.sessionData && !req.query.token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(scanReports());
});

app.get('/view/:reportId', (req, res) => {
    const reportDir = path.join(REPORTS_DIR, req.params.reportId);
    try {
        const files = fs.readdirSync(reportDir);
        const htmlFile = files.find(f => f.endsWith('.html'));
        if (htmlFile) {
            const content = fs.readFileSync(path.join(reportDir, htmlFile), 'utf8');
            res.type('html').send(content);
        } else {
            res.status(404).send('Report not found');
        }
    } catch (e) {
        res.status(404).send('Report not found');
    }
});

// ==================== EMAIL ====================
app.post('/api/send-email', async (req, res) => {
    const token = req.headers['x-session-token'] || req.body.token;
    if (!token || !sessions.has(token)) {
        return res.status(401).json({ success: false, error: 'Session expired' });
    }

    const { to, gmailUser, gmailPass, reportId, isStaticBanner } = req.body;
    if (!to || !gmailUser || !gmailPass || !reportId) {
        return res.status(400).json({ success: false, error: 'All fields required' });
    }

    // Find report
    const reportDir = path.join(REPORTS_DIR, reportId);
    let htmlPath = '';
    try {
        const files = fs.readdirSync(reportDir);
        const htmlFile = files.find(f => f.endsWith('.html'));
        if (htmlFile) htmlPath = path.join(reportDir, htmlFile);
    } catch(e) {}

    if (!htmlPath || !fs.existsSync(htmlPath)) {
        return res.status(404).json({ success: false, error: 'Report not found' });
    }

    try {
        let reportHtml = fs.readFileSync(htmlPath, 'utf8');

        // Inject Refresh and Logout buttons into the report for the iframe view
        const injection = `
<div id="report-controls" style="position:fixed;top:20px;right:20px;display:flex;gap:10px;z-index:9999;background:rgba(255,255,255,0.9);padding:10px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.1);backdrop-filter:blur(4px);border:1px solid #e2e8f0" class="no-print">
    <button onclick="window.parent.postMessage('refresh', '*')" style="padding:8px 16px;background:#00b3a4;color:white;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-family:sans-serif;font-size:12px">Refresh Stats</button>
    <button onclick="window.parent.postMessage('logout', '*')" style="padding:8px 16px;background:#dc2626;color:white;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-family:sans-serif;font-size:12px">Logout</button>
</div>
<style>@media print{.no-print{display:none!important}}</style>
`;
        reportHtml = reportHtml.replace('</body>', injection + '</body>');

        const tenantName = sessions.get(token).tenantName || 'Customer Tenant';
        const generatedDate = new Date().toLocaleDateString('en-AU', { day:'2-digit', month:'short', year:'numeric' });

        let emailHtml = '';

        if (isStaticBanner) {
            // Extract metrics from the HTML using regex
            const extractMetric = (label) => {
                const patterns = [
                    new RegExp(`class='kpi-title'>[^<]*${label}[^<]*</div>\\s*<div class='kpi-value'>([^<]+)`, 'i'),
                    new RegExp(`class="kpi-title">[^<]*${label}[^<]*</div>\\s*<div class="kpi-value">([^<]+)`, 'i'),
                ];
                for (const p of patterns) {
                    const m = reportHtml.match(p);
                    if (m) return m[1].trim();
                }
                return 'N/A';
            };

            emailHtml = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:30px 10px">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08)">

<!-- HEADER -->
<tr><td style="background:linear-gradient(135deg,#061735 0%,#0a1f44 45%,#103a82 100%);padding:32px 36px">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td style="vertical-align:top">
<div style="font-size:10px;font-weight:700;letter-spacing:2.5px;text-transform:uppercase;color:rgba(255,255,255,0.65);margin-bottom:6px">SDMSGUY</div>
<div style="font-size:24px;font-weight:700;color:#ffffff;letter-spacing:-0.5px;line-height:1.2">Intune Master Report</div>
<div style="font-size:13px;color:rgba(255,255,255,0.75);margin-top:6px">The complete Cloud Analysis of your End user environment</div>
</td>
<td style="vertical-align:top;text-align:right">
<div style="font-size:11px;color:rgba(255,255,255,0.6);margin-bottom:4px">Generated</div>
<div style="font-size:13px;font-weight:600;color:#ffffff">${generatedDate}</div>
</td>
</tr>
</table>
</td></tr>

<!-- TENANT -->
<tr><td style="padding:28px 36px 0">
<div style="font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#64748b;margin-bottom:6px">Report For</div>
<div style="font-size:20px;font-weight:700;color:#0a1f44;margin-bottom:2px">${tenantName}</div>
<div style="font-size:13px;color:#64748b">Quarterly Security & Compliance Report</div>
</td></tr>

<!-- KPI STRIP -->
<tr><td style="padding:24px 36px 0">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td width="25%" style="padding:16px;background:#f0fdf4;border-radius:10px;text-align:center;border:1px solid #dcfce7">
<div style="font-size:28px;font-weight:800;color:#15803d">${extractMetric('Compliance')}</div>
<div style="font-size:10px;font-weight:700;color:#16a34a;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Compliance</div>
</td>
<td width="4%"></td>
<td width="25%" style="padding:16px;background:#f0fdf4;border-radius:10px;text-align:center;border:1px solid #dcfce7">
<div style="font-size:28px;font-weight:800;color:#15803d">${extractMetric('Encryption')}</div>
<div style="font-size:10px;font-weight:700;color:#16a34a;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Encryption</div>
</td>
<td width="4%"></td>
<td width="25%" style="padding:16px;background:#f0f9ff;border-radius:10px;text-align:center;border:1px solid #bae6fd">
<div style="font-size:28px;font-weight:800;color:#0369a1">${extractMetric('Defender Coverage')}</div>
<div style="font-size:10px;font-weight:700;color:#0284c7;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Defender</div>
</td>
<td width="4%"></td>
<td width="25%" style="padding:16px;background:#f0f9ff;border-radius:10px;text-align:center;border:1px solid #bae6fd">
<div style="font-size:28px;font-weight:800;color:#0369a1">${extractMetric('MFA Coverage')}</div>
<div style="font-size:10px;font-weight:700;color:#0284c7;text-transform:uppercase;letter-spacing:1px;margin-top:4px">MFA</div>
</td>
</tr>
</table>
</td></tr>

<!-- SECOND ROW -->
<tr><td style="padding:14px 36px 0">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td width="33%" style="padding:16px;background:#fafafa;border-radius:10px;text-align:center;border:1px solid #e2e8f0">
<div style="font-size:28px;font-weight:800;color:#0a1f44">${extractMetric('Patch Health')}</div>
<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Patch Health</div>
</td>
<td width="4%"></td>
<td width="33%" style="padding:16px;background:#fafafa;border-radius:10px;text-align:center;border:1px solid #e2e8f0">
<div style="font-size:28px;font-weight:800;color:#0a1f44">${extractMetric('Managed Devices')}</div>
<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Devices</div>
</td>
<td width="4%"></td>
<td width="26%" style="padding:16px;background:#fafafa;border-radius:10px;text-align:center;border:1px solid #e2e8f0">
<div style="font-size:28px;font-weight:800;color:#0a1f44">${extractMetric('Secure Score')}</div>
<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Secure Score</div>
</td>
</tr>
</table>
</td></tr>

<!-- OVERALL STATUS -->
<tr><td style="padding:24px 36px 0">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td style="padding:20px 24px;background:linear-gradient(135deg,#0a1f44,#103a82);border-radius:12px;text-align:center">
<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:rgba(255,255,255,0.65);margin-bottom:6px">Overall Health Score</div>
<div style="font-size:42px;font-weight:800;color:#ffffff;letter-spacing:-1px">${extractMetric('Overall Health')}</div>
</td></tr>
</table>
</td></tr>

<!-- VIEW FULL REPORT -->
<tr><td style="padding:24px 36px 0;text-align:center">
<a href="http://${req.hostname || 'localhost'}:${PORT}/" style="display:inline-block;padding:14px 36px;background:#0a1f44;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;letter-spacing:0.3px">View Full Interactive Report &rarr;</a>
<div style="font-size:11px;color:#94a3b8;margin-top:10px">Login to the dashboard to view the complete interactive report with drill-down capability</div>
</td></tr>

<!-- SEPARATOR -->
<tr><td style="padding:28px 36px 0"><hr style="border:none;border-top:1px solid #e2e8f0;margin:0"></td></tr>

<!-- DESCRIPTION -->
<tr><td style="padding:20px 36px 0">
<div style="font-size:14px;font-weight:700;color:#0a1f44;margin-bottom:10px">About This Report</div>
<div style="font-size:13px;color:#475569;line-height:1.7">
This automated security dashboard provides a comprehensive view of your organisation's security posture using read-only Microsoft Graph and Microsoft Defender for Endpoint APIs. It covers device compliance, encryption status, patch health, identity protection, vulnerability assessment, and Essential Eight maturity alignment.
</div>
</td></tr>

<!-- FOOTER -->
<tr><td style="padding:28px 36px 0"><hr style="border:none;border-top:1px solid #e2e8f0;margin:0"></td></tr>
<tr><td style="padding:18px 36px 28px">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td style="font-size:12px;color:#94a3b8">
<b style="color:#000000">Intune Master Report by SDMSGUY</b><br>
This is an automated report generated from Microsoft cloud APIs. All data is read-only.
</td>
<td style="text-align:right;font-size:11px;color:#94a3b8">
Generated ${generatedDate}<br>
Confidential
</td>
</tr>
</table>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;

        } else {
            // Send full report content
            emailHtml = reportHtml;
        }

        // Determine transport based on user email domain or explicit choice
        // For Exchange Online, use host: 'smtp.office365.com', port: 587, secure: false
        const isExchange = gmailUser.toLowerCase().endsWith('.onmicrosoft.com') || 
                          gmailUser.toLowerCase().includes('outlook') ||
                          req.body.isExchange;

        const transportConfig = isExchange ? {
            host: 'smtp.office365.com',
            port: 587,
            secure: false,
            auth: { user: gmailUser, pass: gmailPass },
            tls: { ciphers: 'SSLv3' }
        } : {
            service: 'gmail',
            auth: { user: gmailUser, pass: gmailPass }
        };

        const transporter = nodemailer.createTransport(transportConfig);

        await transporter.sendMail({
            from: `"Intune Master Report" <${gmailUser}>`,
            to: to,
            subject: `Intune Master Report - ${tenantName} - ${generatedDate}`,
            html: emailHtml
        });

        console.log(`[${new Date().toISOString()}] Email sent to ${to}`);
        res.json({ success: true, message: `Email sent to ${to}` });
    } catch (err) {
        console.error('Email error:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==================== SAVE TENANT ====================
app.post('/api/save-tenant', (req, res) => {
    const { tenantId, clientId, name, email } = req.body;
    if (!tenantId || !clientId || !name) {
        return res.status(400).json({ success: false, error: 'Tenant ID, Client ID, and Name are required' });
    }
    let tenants = loadTenants();
    const existing = tenants.findIndex(t => t.tenantId === tenantId);
    const entry = { tenantId, clientId, name, email: email || '' };
    if (existing >= 0) {
        tenants[existing] = entry;
    } else {
        tenants.push(entry);
    }
    fs.writeFileSync(TENANTS_FILE, JSON.stringify(tenants, null, 2), 'utf8');
    res.json({ success: true });
});

app.delete('/api/tenants/:tenantId', (req, res) => {
    let tenants = loadTenants();
    tenants = tenants.filter(t => t.tenantId !== req.params.tenantId);
    fs.writeFileSync(TENANTS_FILE, JSON.stringify(tenants, null, 2), 'utf8');
    res.json({ success: true });
});

// ==================== SCHEDULING ====================
let activeCron = null;

function loadSchedule() {
    try {
        if (fs.existsSync(SCHEDULE_FILE)) {
            return JSON.parse(fs.readFileSync(SCHEDULE_FILE, 'utf8'));
        }
    } catch (e) {}
    return null;
}

function saveSchedule(config) {
    fs.writeFileSync(SCHEDULE_FILE, JSON.stringify(config, null, 2), 'utf8');
}

async function runScheduledTask() {
    const config = loadSchedule();
    if (!config) return;

    console.log(`[${new Date().toISOString()}] Starting scheduled report & email...`);
    
    // 1. Generate Report
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const outputDir = path.join(REPORTS_DIR, timestamp);
    fs.mkdirSync(outputDir, { recursive: true });

    const env = {
        ...process.env,
        REPORT_TENANT_ID: config.tenantId,
        REPORT_CLIENT_ID: config.clientId,
        REPORT_CLIENT_SECRET: config.clientSecret,
        REPORT_OUTPUT_PATH: outputDir
    };

    const ps = spawn('pwsh.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT], { env, cwd: __dirname, shell: true });

    ps.on('close', async (code) => {
        if (code !== 0) {
            console.error(`Scheduled report failed with code ${code}`);
            return;
        }

        // 2. Find generated HTML
        const files = fs.readdirSync(outputDir);
        const htmlFile = files.find(f => f.endsWith('.html'));
        if (!htmlFile) return;

        // 3. Send Email
        try {
            const htmlPath = path.join(outputDir, htmlFile);
            const reportHtml = fs.readFileSync(htmlPath, 'utf8');
            const generatedDate = new Date().toLocaleDateString('en-AU', { day:'2-digit', month:'short', year:'numeric' });

            const transportConfig = config.isExchange ? {
                host: 'smtp.office365.com', port: 587, secure: false,
                auth: { user: config.gmailUser, pass: config.gmailPass },
                tls: { ciphers: 'SSLv3' }
            } : {
                service: 'gmail',
                auth: { user: config.gmailUser, pass: config.gmailPass }
            };

            const transporter = nodemailer.createTransport(transportConfig);
            await transporter.sendMail({
                from: `"EndUserRepo Scheduled" <${config.gmailUser}>`,
                to: config.to,
                subject: `Daily Intune Report - ${config.tenantName} - ${generatedDate}`,
                html: reportHtml
            });
            console.log(`Scheduled email sent to ${config.to}`);
        } catch (err) {
            console.error('Scheduled email failed:', err.message);
        }
    });
}

function initSchedule() {
    const config = loadSchedule();
    if (config) {
        if (activeCron) activeCron.stop();
        // Schedule for 8 AM daily
        activeCron = cron.schedule('0 8 * * *', runScheduledTask);
        console.log('Daily 8 AM schedule initialized.');
    }
}

app.post('/api/schedule', (req, res) => {
    if (loadSchedule()) {
        return res.status(400).json({ success: false, error: 'A schedule already exists on this machine. Delete it first to create a new one.' });
    }
    const { to, gmailUser, gmailPass, isExchange, tenantId, clientId, clientSecret, tenantName } = req.body;
    const config = { to, gmailUser, gmailPass, isExchange, tenantId, clientId, clientSecret, tenantName, created: Date.now() };
    saveSchedule(config);
    initSchedule();
    res.json({ success: true });
});

app.get('/api/schedule', (req, res) => {
    const config = loadSchedule();
    res.json(config ? { exists: true, to: config.to, tenantName: config.tenantName } : { exists: false });
});

app.delete('/api/schedule', (req, res) => {
    if (fs.existsSync(SCHEDULE_FILE)) fs.unlinkSync(SCHEDULE_FILE);
    if (activeCron) {
        activeCron.stop();
        activeCron = null;
    }
    res.json({ success: true });
});

// ==================== START ====================
app.listen(PORT, () => {
    initSchedule();
    console.log(`\n${'='.repeat(50)}`);
    console.log(`  Intune Master Report by SDMSGUY`);
    console.log(`  The complete Cloud Analysis of your End user environment`);
    console.log(`  http://localhost:${PORT}`);
    console.log(`${'='.repeat(50)}\n`);

    // Initialize tenants.json if not exists
    if (!fs.existsSync(TENANTS_FILE)) {
        fs.writeFileSync(TENANTS_FILE, JSON.stringify([], null, 2), 'utf8');
        console.log('Created config/tenants.json - add your tenant configurations there.');
    }
});
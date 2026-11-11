// Browser test: the admin Configuration Assistant results page and its
// "Apply Immediate Settings" button, against a mocked admin API.
// Run with SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('config-assistant.test.js');

const BASELINE = ['.exe', '.bat', '.sh'];

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    // Mocked server state
    let blocked = ['.exe', '.iso'];
    let securityReply = null; // { status, body } to force a rejection
    const posts = [];

    const config = () => ({
        max_file_size: 104857600, quota_limit_gb: 0, default_expiration_hours: 24, max_expiration_hours: 168,
        rate_limit_upload: 10, rate_limit_download: 100, blocked_extensions: blocked.slice(),
        chunked_upload_threshold: 104857600, partial_upload_expiry_hours: 24,
        session_expiry_hours: 24, cleanup_interval_minutes: 60, require_auth_for_upload: false,
        https_enabled: false, chunked_upload_enabled: true, public_url: '',
    });
    let analyzeBody = null;
    const analysis = () => {
        const cur = config();
        const merged = blocked.concat(BASELINE.filter((e) => !blocked.includes(e)));
        return {
            current_config: cur,
            recommendations: Object.assign({}, cur, { quota_limit_gb: 400, blocked_extensions: merged }),
            analysis: { summary: 'Optimized for testing.', impacts: {}, additional_recommendations: [] },
        };
    };

    try {
        const context = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        await context.route(/\/admin\/assets\/[^/?]+\.(js|css)(\?.*)?$/, (route) => {
            const name = new URL(route.request().url()).pathname.replace(/^\/admin\/assets\//, '');
            route.fulfill({ status: 200, contentType: name.endsWith('.css') ? 'text/css' : 'application/javascript',
                body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/admin/assets', name)) });
        });
        await context.route(base + '/admin/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/admin/dashboard.html')),
        }));
        await context.route(/\/admin\/api\//, (route) => {
            const url = new URL(route.request().url());
            const json = (body) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
            if (url.pathname === '/admin/api/config-assistant/analyze') {
                analyzeBody = JSON.parse(route.request().postData());
                return json(analysis());
            }
            if (url.pathname === '/admin/api/config') return json(config());
            if (url.pathname === '/admin/api/settings/storage') {
                posts.push('storage');
                return json({ success: true, message: 'Storage settings updated successfully' });
            }
            if (url.pathname === '/admin/api/settings/security') {
                posts.push('security');
                if (securityReply) return route.fulfill({ status: securityReply.status, contentType: 'text/plain', body: securityReply.body });
                blocked = new URLSearchParams(route.request().postData()).get('blocked_extensions').split(',');
                return json({ success: true, message: 'Security settings updated successfully' });
            }
            if (url.pathname === '/admin/api/dashboard') {
                return json({ files: [], pagination: { page: 1, page_size: 20, total: 0, total_pages: 0, unfiltered_total: 0 },
                    stats: { total_files: 0, storage_used_bytes: 0, quota_limit_bytes: 0, quota_used_percent: 0, partial_uploads_bytes: 0, partial_uploads_count: 0 },
                    blocked_ips: [], system_info: {} });
            }
            return json({});
        });

        const page = await context.newPage();
        const toasts = () => page.$$eval('.toast', (els) => els.map((e) => e.className + ' :: ' + e.querySelector('.toast-message').textContent));
        const clearToasts = () => page.evaluate(() => document.querySelectorAll('.toast').forEach((t) => t.remove()));
        const blockedRow = () => page.$$eval('#immediateSettingsTableBody tr', (rows) => {
            const r = rows.find((x) => x.querySelector('.cmp-setting').textContent.includes('Blocked File Types'));
            return r && { changed: r.classList.contains('row-changed'), current: r.querySelector('.cmp-current').textContent, rec: r.querySelector('.cmp-recommended').textContent, impact: r.querySelector('.cmp-impact').textContent };
        });
        const analyze = async () => {
            await clearToasts();
            await page.click('#configAssistantForm button[type="submit"]');
            await page.waitForSelector('#recommendationsSection', { state: 'visible' });
        };
        const apply = async () => {
            await clearToasts();
            await page.click('#applyRecommendationsBtn');
            await page.click('#confirmYes');
            await page.waitForSelector('.toast', { timeout: 10000 });
            await page.waitForTimeout(500);
            return toasts();
        };

        await page.goto(base + '/admin/dashboard');
        await page.click('#tab-configAssistant');
        await page.fill('#uploadSpeed', '100');
        await page.fill('#downloadSpeed', '200');
        await page.selectOption('#networkLatency', 'low');
        await page.selectOption('#typicalFileSize', 'medium');
        await page.selectOption('#deploymentType', 'Internet');
        await page.selectOption('#userLoad', 'moderate');

        // Results page lists exactly what Apply adds to the blocked types
        await analyze();
        H.check('form no longer sends retired fields',
            analyzeBody && !('cdn_timeout' in analyzeBody) && !('encryption_enabled' in analyzeBody) && analyzeBody.using_cdn === false,
            JSON.stringify(analyzeBody));
        H.check('retired questions are gone from the form',
            (await page.$$('#cdnTimeout, #encryptionEnabled, #cdnTimeoutGroup')).length === 0);
        const tableText = (await page.$$eval('#recommendationsSection tbody', (bs) => bs.map((b) => b.textContent).join(' ')));
        H.check('no row shows undefined or NaN', !/undefined|NaN/.test(tableText), tableText.slice(0, 200));
        const rowNames = await page.$$eval('#recommendationsSection .cmp-setting', (cs) => cs.map((c) => c.textContent.replace('Changed', '').trim()));
        H.check('no chunk size or timeout rows', !rowNames.some((n) => /Chunk Size|Timeout/.test(n)), JSON.stringify(rowNames));
        const envText = await page.textContent('#envFileContent');
        H.check('settings block has no retired settings', !/CHUNK_SIZE=|READ_TIMEOUT=|WRITE_TIMEOUT=/.test(envText), envText);
        H.check('settings block keeps the others',
            /CHUNKED_UPLOAD_THRESHOLD=104857600/.test(envText) && /SESSION_EXPIRY_HOURS=24/.test(envText), envText);
        let row = await blockedRow();
        H.check('blocked types row is shown', !!row);
        H.check('row counts current types', row && row.current === '2 types', row && row.current);
        H.check('row names only the added types', row && row.rec === '4 types (adds .bat, .sh)', row && row.rec);
        H.check('row says existing types stay', row && row.impact.includes('Types you already block stay blocked'), row && row.impact);
        H.check('row is marked changed', row && row.changed);

        // Stale apply: settings changed after Analyze -> refused, nothing saved
        blocked = blocked.concat(['.xyz']);
        let t = await apply();
        H.check('stale apply is refused with an explanation', t.some((x) => x.includes('toast-error') && x.includes('changed since the analysis')), JSON.stringify(t));
        H.check('stale apply saves nothing', posts.length === 0, JSON.stringify(posts));
        row = await blockedRow();
        H.check('table refreshes after stale apply', row && row.current === '3 types' && row.rec === '5 types (adds .bat, .sh)', row && JSON.stringify(row));

        // Rejected security save -> real reason, no success claim
        securityReply = { status: 400, body: 'Upload rate limit: simulated rejection\n' };
        t = await apply();
        H.check('rejection names the server reason', t.some((x) => x.includes('security settings were rejected: Upload rate limit: simulated rejection')), JSON.stringify(t));
        H.check('no success toast after rejection', !t.some((x) => x.includes('applied successfully')), JSON.stringify(t));
        securityReply = null;

        // Successful apply keeps the admin's own types (the results stay
        // open after a rejection, so apply again from there)
        t = await apply();
        H.check('apply succeeds', t.some((x) => x.includes('Recommended settings applied successfully')) && !t.some((x) => x.includes('toast-error')), JSON.stringify(t));
        H.check('own types kept and baseline added', ['.exe', '.iso', '.xyz', '.bat', '.sh'].every((e) => blocked.includes(e)), JSON.stringify(blocked));

        // Nothing left to add -> "no change", not marked
        await analyze();
        row = await blockedRow();
        H.check('no change when everything is already blocked', row && row.rec === '5 types (no change)' && !row.changed, row && JSON.stringify(row));
        H.check('impact says so', row && row.impact === 'You already block every recommended type.', row && row.impact);

        // Phone: no sideways scrolling with the long row
        await page.setViewportSize({ width: 390, height: 844 });
        await page.waitForTimeout(300);
        H.check('phone: no sideways scrolling', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

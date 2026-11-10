// Browser test: compact phone cards for the dashboard's API Tokens and the
// admin Files and Users tabs (closed by default, tap to open, Expand all;
// wider screens keep their tables). Pages run against mocked APIs. Run with
// SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('compact-cards.test.js');

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });
    const hour = 3600 * 1000;
    const iso = (ms) => new Date(Date.now() + ms).toISOString();

    try {
        // ---------------- Dashboard: API tokens ----------------
        const tokens = [
            { id: 11, name: 'home-pc', scopes: ['upload', 'manage'], created_at: iso(-48 * hour), expires_at: iso(30 * 24 * hour), last_used_at: iso(-hour), usage_stats: null },
            { id: 12, name: 'old-script', scopes: ['download'], created_at: iso(-90 * 24 * hour), expires_at: iso(-24 * hour), last_used_at: null, usage_stats: null },
            { id: 13, name: 'forever', scopes: ['upload'], created_at: iso(-hour), expires_at: '9999-12-31T23:59:59Z', last_used_at: null, usage_stats: null },
        ];
        const ctx = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        await ctx.route(base + '/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/dashboard.html')),
        }));
        let tokenLoads = 0;
        await ctx.route(/\/api\/(?!config)/, (route) => {
            const p = new URL(route.request().url()).pathname;
            const json = (body) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
            if (p === '/api/auth/user') return json({ id: 1, username: 'alice', role: 'user' });
            if (p === '/api/user/files') return json({ files: [{ id: 31, claim_code: 'UpCode000031', original_filename: 'notes.txt', file_size: 2048,
                created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null, download_count: 0, completed_downloads: 0,
                download_url: base + '/api/claim/UpCode000031', is_expired: false, is_password_protected: false, client_encrypted: false }], total: 1, limit: 100, offset: 0 });
            if (p === '/api/user/bundles') return json({ bundles: [{ id: 41, bundle_code: 'BundleCode41', created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null,
                password_protected: false, client_encrypted: false, file_count: 1, total_size: 3, files: [{ position: 0, name: 'cover.png', size: 3, completed_downloads: 0 }] }], total: 1, limit: 100, offset: 0 });
            if (p === '/api/tokens') { tokenLoads++; return json({ tokens }); }
            return json({});
        });
        const page = await ctx.newPage();
        await page.goto(base + '/dashboard');
        await page.waitForSelector('#tokensContainer table.tokens-table');
        const trow = (id) => `#tokensContainer tr.token-row[data-token-id="${id}"]`;
        const vis = (sel) => page.isVisible(sel);

        H.check('tokens desktop: table shows scopes and actions', (await vis(`${trow(11)} .scopes-cell`)) && (await vis(`${trow(11)} [data-action="revokeToken"]`)));
        H.check('uploads desktop: phone card pieces stay hidden',
            !(await vis('#filesContainer tr.upload-row[data-file-id="31"] .upload-card-toggle')) && !(await vis('#filesContainer tr.upload-row[data-file-id="31"] .upload-card-meta')));
        H.check('tokens desktop: no arrow, no summary line, no Expand all',
            !(await vis(`${trow(11)} .upload-card-toggle`)) && !(await vis(`${trow(11)} .upload-card-meta`)) && !(await vis('#tokensExpandAllBtn')));

        await page.setViewportSize({ width: 800, height: 900 });
        H.check('tokens tablet: table, no arrow or Expand all',
            (await vis(`${trow(11)} .scopes-cell`)) && !(await vis(`${trow(11)} .upload-card-toggle`)) && !(await vis('#tokensExpandAllBtn')));
        await page.setViewportSize({ width: 390, height: 844 });
        H.check('tokens phone: cards start closed', !(await vis(`${trow(11)} .scopes-cell`)) && !(await vis(`${trow(11)} [data-action="revokeToken"]`)));
        H.check('tokens phone: closed card shows name and expiry',
            (await vis(`${trow(11)} .token-name`)) && /Expires/.test(await page.textContent(`${trow(11)} .upload-card-meta`)));
        H.check('tokens phone: never-expiring token says Never', /Never/.test(await page.textContent(`${trow(13)} .upload-card-meta`)));
        H.check('tokens phone: expired token is flagged on the closed card', /xpired/.test(await page.textContent(`${trow(12)} .upload-card-meta`)));
        const closedH = await page.$eval(trow(11), (r) => r.getBoundingClientRect().height);
        H.check('tokens phone: closed cards are compact', closedH < 100, String(closedH));

        await page.click(`${trow(11)} .token-name`);
        H.check('tokens phone: tapping the name opens it',
            (await vis(`${trow(11)} .scopes-cell`)) && (await vis(`${trow(11)} [data-action="rotateToken"]`)) && (await page.getAttribute(`${trow(11)} .upload-card-toggle`, 'aria-expanded')) === 'true');
        H.check('tokens phone: Expires is not repeated when open', !(await vis(`${trow(11)} td[data-label="Expires"]`)));
        await page.click(`${trow(11)} .upload-card-toggle`);
        H.check('tokens phone: the arrow closes it', !(await vis(`${trow(11)} .scopes-cell`)));

        await page.click('#tokensExpandAllBtn');
        H.check('tokens phone: Expand all opens every card', (await page.$$('#tokensContainer tr.token-row.is-open')).length === 3 && /Collapse all/.test(await page.textContent('#tokensExpandAllText')));
        await page.click('#tokensExpandAllBtn');
        H.check('tokens phone: Collapse all closes them', (await page.$$('#tokensContainer tr.token-row.is-open')).length === 0);

        await page.click(`${trow(12)} .upload-card-toggle`);
        const before = tokenLoads;
        await page.click('#refreshTokensBtn');
        await page.waitForTimeout(400);
        H.check('tokens phone: an open card stays open after reload', tokenLoads > before && await vis(`${trow(12)} .scopes-cell`));
        // The shared card styles still work for My Uploads and stay out of My Bundles.
        const up = '#filesContainer tr.upload-row[data-file-id="31"]';
        H.check('uploads phone: upload card still starts closed with its arrow',
            !(await vis(`${up} .claim-code`)) && (await vis(`${up} .upload-card-toggle`)) && (await vis(`${up} .upload-card-meta`)));
        await page.click(`${up} .upload-card-toggle`);
        H.check('uploads phone: upload card still opens', await vis(`${up} .claim-code`));
        H.check('bundles phone: My Bundles gets no upload/token card pieces',
            (await page.$$('#bundlesContainer .upload-card-toggle, #bundlesContainer .upload-card-meta')).length === 0 && await vis('#bundlesContainer .bundle-toggle-mobile'));
        H.check('tokens phone: no sideways scrolling', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
        await ctx.close();

        // ---------------- Admin: Files and Users ----------------
        const files = [
            { id: 1, claim_code: 'AdmFile00001', original_filename: 'quarterly-report.pdf', file_size: 2400000, username: 'alice', user_id: 1, uploader_ip: '10.0.0.1',
              created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null, download_count: 0, completed_downloads: 0, password_protected: false, scan_status: 'clean', scan_result: '' },
            { id: 2, claim_code: 'AdmFile00002', original_filename: 'setup.exe', file_size: 14000000, username: null, user_id: null, uploader_ip: '203.0.113.9',
              created_at: iso(-2 * hour), expires_at: iso(20 * hour), max_downloads: 1, download_count: 0, completed_downloads: 0, password_protected: true, scan_status: 'infected', scan_result: 'Eicar' },
        ];
        const users = [
            { id: 1, username: 'alice', email: 'alice@example.com', role: 'user', is_active: true, file_count: 1, created_at: iso(-100 * hour), last_login: iso(-hour) },
            { id: 2, username: 'boss', email: 'boss@example.com', role: 'admin', is_active: false, file_count: 0, created_at: iso(-200 * hour), last_login: null },
        ];
        const actx = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        await actx.route(/\/admin\/assets\/[^/?]+\.(js|css)(\?.*)?$/, (route) => {
            const name = new URL(route.request().url()).pathname.replace(/^\/admin\/assets\//, '');
            route.fulfill({ status: 200, contentType: name.endsWith('.css') ? 'text/css' : 'application/javascript',
                body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/admin/assets', name)) });
        });
        await actx.route(base + '/admin/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/admin/dashboard.html')),
        }));
        await actx.route(/\/admin\/api\//, (route) => {
            const url = new URL(route.request().url());
            const json = (body) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
            if (url.pathname === '/admin/api/files/uploaders') return json({ anonymous_count: 1, users: [{ user_id: 1, username: 'alice', file_count: 1 }] });
            if (url.pathname === '/admin/api/users') return json({ users, total: users.length });
            if (url.pathname === '/admin/api/dashboard') {
                if (url.searchParams.get('search') === 'nomatch') {
                    return json({ files: [], pagination: { page: 1, page_size: 20, total: 0, total_pages: 0, unfiltered_total: files.length },
                        stats: { total_files: 2, storage_used_bytes: 1, quota_limit_bytes: 0, quota_used_percent: 0, partial_uploads_bytes: 0, partial_uploads_count: 0 },
                        blocked_ips: [], system_info: {} });
                }
                return json({ files, pagination: { page: 1, page_size: 20, total: files.length, total_pages: 1, unfiltered_total: files.length },
                    stats: { total_files: 2, storage_used_bytes: 1, quota_limit_bytes: 0, quota_used_percent: 0, partial_uploads_bytes: 0, partial_uploads_count: 0 },
                    blocked_ips: [], system_info: {} });
            }
            return json({});
        });
        const ap = await actx.newPage();
        await ap.goto(base + '/admin/dashboard');
        await ap.waitForSelector('#filesTableBody code');
        const frow = (code) => `#filesTableBody tr.cc-row[data-cc-key="${code}"]`;
        const avis = (sel) => ap.isVisible(sel);

        H.check('admin desktop: files table keeps its columns', (await avis(`${frow('AdmFile00001')} td[data-label="Uploader IP"]`)) && !(await avis(`${frow('AdmFile00001')} .cc-summary`)));
        H.check('admin desktop: no Expand all', !(await avis('#filesExpandAllBtn')));

        await ap.setViewportSize({ width: 900, height: 900 });
        H.check('admin tablet: table, no summary cell or Expand all',
            (await avis(`${frow('AdmFile00001')} td[data-label="Claim Code"]`)) && !(await avis(`${frow('AdmFile00001')} .cc-summary`)) && !(await avis('#filesExpandAllBtn')));
        await ap.setViewportSize({ width: 390, height: 844 });
        H.check('admin phone: file cards start closed', !(await avis(`${frow('AdmFile00001')} td[data-label="Uploader IP"]`)) && !(await avis(`${frow('AdmFile00001')} [data-action="deleteFile"]`)));
        const meta = await ap.textContent(`${frow('AdmFile00002')} .cc-meta`);
        H.check('admin phone: closed file card shows name, size, user and scan',
            (await ap.textContent(`${frow('AdmFile00002')} .cc-title`)) === 'setup.exe' && /MB/.test(meta) && /Anonymous/.test(meta) && /nfected/i.test(meta), meta);
        H.check('admin phone: select checkbox stays on the closed card', await avis(`${frow('AdmFile00001')} .file-checkbox`));
        const box = await ap.$eval(`${frow('AdmFile00001')} .file-checkbox`, (b) => b.getBoundingClientRect());
        const arrow = await ap.$eval(`${frow('AdmFile00001')} .cc-toggle`, (b) => b.getBoundingClientRect());
        const apart = arrow.right <= box.left || box.right <= arrow.left || arrow.bottom <= box.top || box.bottom <= arrow.top;
        H.check('admin phone: arrow and checkbox do not overlap', apart, JSON.stringify({ arrow, box }));
        H.check('admin phone: closed file cards are compact', (await ap.$eval(frow('AdmFile00001'), (r) => r.getBoundingClientRect().height)) < 110);

        await ap.click(`${frow('AdmFile00001')} .cc-title`);
        H.check('admin phone: tapping a file card opens it',
            (await avis(`${frow('AdmFile00001')} td[data-label="Uploader IP"]`)) && (await avis(`${frow('AdmFile00001')} [data-action="deleteFile"]`)));
        H.check('admin phone: summary details not repeated when open',
            !(await avis(`${frow('AdmFile00001')} td[data-label="Filename"]`)) && !(await avis(`${frow('AdmFile00001')} td[data-label="Size"]`)) && !(await avis(`${frow('AdmFile00001')} td[data-label="Scan"]`)));
        await ap.check(`${frow('AdmFile00002')} .file-checkbox`);
        H.check('admin phone: ticking a closed card does not open it',
            !(await ap.$eval(frow('AdmFile00002'), (r) => r.classList.contains('is-open'))) && await avis('#deleteSelectedBtn'));
        await ap.click('#filesExpandAllBtn');
        H.check('admin phone: Expand all opens every file card', (await ap.$$('#filesTableBody tr.cc-row.is-open')).length === 2);
        await ap.click('#refreshBtn');
        await ap.waitForTimeout(500);
        H.check('admin phone: open cards survive Refresh', (await ap.$$('#filesTableBody tr.cc-row.is-open')).length === 2);
        await ap.click('#filesExpandAllBtn');
        H.check('admin phone: Collapse all closes them', (await ap.$$('#filesTableBody tr.cc-row.is-open')).length === 0);

        await ap.fill('#searchInput', 'nomatch');
        await ap.waitForFunction(() => !document.querySelector('#filesTableBody tr.cc-row'), null, { timeout: 5000 });
        H.check('admin phone: Expand all hides when no files match', !(await avis('#filesExpandAllBtn')));
        await ap.fill('#searchInput', '');
        await ap.waitForSelector('#filesTableBody tr.cc-row');
        H.check('admin phone: Expand all returns with results', await avis('#filesExpandAllBtn'));

        await ap.click('#tab-users');
        await ap.waitForSelector('#usersTableBody tr.cc-row');
        const urow = (id) => `#usersTableBody tr.cc-row[data-cc-key="${id}"]`;
        const umeta = await ap.textContent(`${urow(2)} .cc-meta`);
        H.check('admin phone: user cards start closed', !(await avis(`${urow(1)} td[data-label="Email"]`)) && !(await avis(`${urow(1)} [data-action="editUser"]`)));
        H.check('admin phone: closed user card shows name, role, status and files',
            (await ap.textContent(`${urow(2)} .cc-title`)) === 'boss' && /admin/.test(umeta) && /Disabled/.test(umeta) && /0 files/.test(umeta), umeta);
        await ap.click(`${urow(1)} .cc-toggle`);
        H.check('admin phone: the arrow opens a user card',
            (await avis(`${urow(1)} td[data-label="Email"]`)) && (await avis(`${urow(1)} [data-action="editUser"]`)) && !(await avis(`${urow(1)} td[data-label="Username"]`)) && !(await avis(`${urow(1)} td[data-label="Role"]`)));
        H.check('admin phone: users Expand all is shown', await avis('#usersExpandAllBtn'));
        H.check('admin phone: no sideways scrolling', await ap.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));

        await actx.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

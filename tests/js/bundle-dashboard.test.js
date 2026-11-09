// Browser test: bundles in the user dashboard. The page runs against a
// mocked API (the dashboard needs a signed-in session). Run with
// SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('bundle-dashboard.test.js');

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    let bundles = [{
        id: 7, bundle_code: 'BundleDash01', created_at: '2026-11-09T10:00:00Z', expires_at: '2026-11-10T10:00:00Z',
        max_downloads: null, password_protected: false, client_encrypted: false, file_count: 2, total_size: 7,
        files: [{ position: 0, name: 'cover.png', size: 3, completed_downloads: 1 }, { position: 1, name: 'slide-2.png', size: 4, completed_downloads: 0 }],
    }, {
        id: 8, bundle_code: 'BundleDash02', created_at: '2026-11-09T09:00:00Z', expires_at: '2026-11-10T09:00:00Z',
        max_downloads: 1, password_protected: true, client_encrypted: true, file_count: 1, total_size: 5,
        files: [{ position: 0, name: 'secret.pdf', size: 5, completed_downloads: 0 }],
    }];
    const calls = [];

    try {
        const context = await H.newBrowserContext(browser, base);
        await context.route(base + '/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/dashboard.html')),
        }));
        await context.route(/\/api\/(?!config)/, (route) => {
            const req = route.request();
            const p = new URL(req.url()).pathname;
            calls.push(req.method() + ' ' + p);
            const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
            if (p === '/api/auth/user') return json({ id: 1, username: 'alice', role: 'user' });
            if (p === '/api/user/files') return json({ files: [{ id: 3, claim_code: 'PlainFile01', original_filename: 'single.txt', file_size: 9,
                created_at: '2026-11-09T08:00:00Z', expires_at: '2026-11-10T08:00:00Z', completed_downloads: 0, download_count: 0,
                max_downloads: null, password_protected: false, download_url: base + '/api/claim/PlainFile01' }], total: 1, limit: 100, offset: 0 });
            if (p === '/api/user/bundles') return json({ bundles, total: bundles.length, limit: 100, offset: 0 });
            const del = /^\/api\/user\/bundles\/(\d+)$/.exec(p);
            if (del && req.method() === 'DELETE') {
                bundles = bundles.filter((b) => b.id !== Number(del[1]));
                return json({ success: true, deleted_files: 2 });
            }
            if (/^\/api\/user\/bundles\/\d+\/expiration$/.test(p)) return json({ success: true });
            return json({});
        });
        const page = await context.newPage();
        await page.goto(base + '/dashboard');
        await page.waitForSelector('#bundlesSection:not(.hidden)', { timeout: 15000 });

        const rows = await page.$$('#bundlesContainer .bundle-row');
        H.check('one row per bundle', rows.length === 2, rows.length + ' rows');
        const firstText = await rows[0].textContent();
        H.check('row shows code, count and size', firstText.includes('BundleDash01') && /2 files/.test(firstText), firstText);
        await page.click('#bundlesContainer .bundle-row:first-child summary');
        H.check('expanding lists its files', (await rows[0].textContent()).includes('slide-2.png'));
        H.check('plain bundle can copy its link', await page.isEnabled('#bundlesContainer .bundle-row:first-child [data-action="copyBundleLink"]'));
        H.check('encrypted bundle cannot copy a link (key not stored)', await page.isDisabled('#bundlesContainer .bundle-row:nth-child(2) [data-action="copyBundleLink"]'));
        H.check('single files still listed', (await page.textContent('#filesContainer')).includes('single.txt'));
        H.check('bundle members are not in the file list', !(await page.textContent('#filesContainer')).includes('cover.png'));

        await page.click('#bundlesContainer .bundle-row:first-child [data-action="deleteBundle"]');
        await page.waitForSelector('#deleteModal.show');
        await page.click('#deleteConfirmBtn');
        await page.waitForFunction(() => document.querySelectorAll('#bundlesContainer .bundle-row').length === 1, null, { timeout: 10000 });
        H.check('delete calls the bundle endpoint', calls.includes('DELETE /api/user/bundles/7'), JSON.stringify(calls));
        H.check('deleting a bundle leaves single files alone', !calls.some((c) => c.startsWith('DELETE /api/user/files')));
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

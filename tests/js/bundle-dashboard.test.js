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

    const hour = 3600 * 1000;
    const iso = (ms) => new Date(Date.now() + ms).toISOString();
    let bundles = [{
        id: 7, bundle_code: 'BundleDash01', created_at: iso(-2 * hour), expires_at: iso(22 * hour),
        max_downloads: null, password_protected: false, client_encrypted: false, file_count: 2, total_size: 7,
        files: [{ position: 0, name: 'cover.png', size: 3, completed_downloads: 1 }, { position: 1, name: 'slide-2.png', size: 4, completed_downloads: 0 }],
    }, {
        id: 8, bundle_code: 'BundleDash02', created_at: iso(-3 * hour), expires_at: iso(21 * hour),
        max_downloads: 2, password_protected: true, client_encrypted: true, file_count: 1, total_size: 5,
        files: [{ position: 0, name: 'secret.pdf', size: 5, completed_downloads: 1 }],
    }, {
        id: 9, bundle_code: 'BundleDash03', created_at: iso(-30 * hour), expires_at: iso(-6 * hour),
        max_downloads: null, password_protected: false, client_encrypted: false, file_count: 1, total_size: 9,
        files: [{ position: 0, name: 'old-recap.mp4', size: 9, completed_downloads: 0 }],
    }, {
        // "Never expires" is 9999-12-31T23:59:59Z: already the year 10000 east of UTC.
        id: 10, bundle_code: 'BundleDash04', created_at: iso(-4 * hour), expires_at: '9999-12-31T23:59:59Z',
        max_downloads: null, password_protected: false, client_encrypted: false, file_count: 1, total_size: 4,
        files: [{ position: 0, name: 'forever.txt', size: 4, completed_downloads: 0 }],
    }];
    const calls = [];

    try {
        // A zone east of UTC, where 9999-12-31T23:59:59Z is already the year 10000.
        const context = await H.newBrowserContext(browser, base, { timezoneId: 'Europe/Berlin' });
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
                created_at: '2026-11-09T08:00:00Z', expires_at: '9999-12-31T23:59:59Z', completed_downloads: 0, download_count: 0,
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

        const T = '#bundlesContainer table.files-table';
        const rowFor = (code) => `${T} tr.bundle-row[data-bundle-code="${code}"]`;
        const filesOf = (code) => `${T} tr.bundle-file-row[data-bundle-code="${code}"]`;
        const visibleCount = (sel) => page.$$eval(sel, (els) => els.filter((e) => e.offsetParent !== null).length);

        H.check('bundles are a table like My Uploads', (await page.$$(`${T} tbody tr.bundle-row`)).length === 4);
        const headers = await page.$$eval(`${T} thead th`, (ths) => ths.map((th) => th.textContent.trim()));
        H.check('same columns as My Uploads', JSON.stringify(headers) === JSON.stringify(['Bundle', 'Size', 'Claim code', 'Created', 'Expires', 'Downloads', 'Status', 'Actions']), JSON.stringify(headers));
        const firstText = await page.textContent(rowFor('BundleDash01'));
        H.check('row shows code, file count and size', firstText.includes('BundleDash01') && /2 files/.test(firstText) && firstText.includes('7 B'), firstText);
        H.check('row previews its file names', firstText.includes('cover.png'), firstText);

        H.check('files start hidden', (await visibleCount(filesOf('BundleDash01'))) === 0);
        const toggle = `${rowFor('BundleDash01')} button.bundle-toggle`;
        H.check('toggle says it is collapsed', (await page.getAttribute(toggle, 'aria-expanded')) === 'false');
        const controls = (await page.getAttribute(toggle, 'aria-controls') || '').split(' ').filter(Boolean);
        H.check('toggle points at its file rows', controls.length === 2, JSON.stringify(controls));
        await page.click(toggle);
        H.check('expanding shows one row per file', (await visibleCount(filesOf('BundleDash01'))) === 2);
        H.check('toggle says it is expanded', (await page.getAttribute(toggle, 'aria-expanded')) === 'true');
        H.check('file rows show name and downloads', /slide-2\.png[\s\S]*0\/∞/.test(await page.textContent('#bundle-7-file-1')));
        await page.click(toggle);
        H.check('collapsing hides the files again', (await visibleCount(filesOf('BundleDash01'))) === 0);

        await page.click('#bundlesToggleAllBtn');
        H.check('Expand all opens every bundle', (await visibleCount(`${T} tr.bundle-file-row`)) === 5);
        H.check('button then offers Collapse all', /Collapse all/.test(await page.textContent('#bundlesToggleAllBtn')));
        await page.click('#bundlesToggleAllBtn');
        H.check('Collapse all closes every bundle', (await visibleCount(`${T} tr.bundle-file-row`)) === 0);

        const secret = await page.textContent(rowFor('BundleDash02'));
        H.check('encrypted and password bundles are marked', /Encrypted/.test(secret) && /Password/.test(secret), secret);
        H.check('limited bundle shows downloads against its limit', /1 of 2/.test(secret) && /limit 2 per file/.test(secret), secret);
        H.check('plain bundle can copy its link', await page.isEnabled(`${rowFor('BundleDash01')} [data-action="copyBundleLink"]`));
        H.check('encrypted bundle cannot copy a link (key not stored)', await page.isDisabled(`${rowFor('BundleDash02')} [data-action="copyBundleLink"]`));
        H.check('active bundle is Active', /Active/.test(firstText));
        H.check('past-expiry bundle is Expired', /Expired/.test(await page.textContent(rowFor('BundleDash03'))));
        H.check('expiration and new-code actions still there',
            !!(await page.$(`${rowFor('BundleDash01')} [data-action="editBundleExpiration"]`)) && !!(await page.$(`${rowFor('BundleDash01')} [data-action="regenerateBundleCode"]`)));
        const bundleExpires = await page.textContent(`${rowFor('BundleDash04')} [data-label="Expires"]`);
        H.check('never-expiring bundle says Never (east of UTC too)', /Never/.test(bundleExpires), bundleExpires);
        const uploadExpires = await page.textContent('#filesContainer td[data-label="Expires"]');
        H.check('never-expiring upload says Never (east of UTC too)', /Never/.test(uploadExpires), uploadExpires);
        H.check('phone toggle names its bundle for screen readers',
            /BundleDash01/.test(await page.getAttribute(`${rowFor('BundleDash01')} button.bundle-toggle-mobile`, 'aria-label') || ''));
        H.check('single files still listed', (await page.textContent('#filesContainer')).includes('single.txt'));
        H.check('bundle members are not in the file list', !(await page.textContent('#filesContainer')).includes('cover.png'));

        // An open bundle stays open when the list reloads (here: after deleting another one).
        await page.click(`${rowFor('BundleDash02')} button.bundle-toggle`);
        await page.click(`${rowFor('BundleDash01')} [data-action="deleteBundle"]`);
        await page.waitForSelector('#deleteModal.show');
        await page.click('#deleteConfirmBtn');
        await page.waitForFunction((sel) => document.querySelectorAll(sel).length === 3, `${T} tr.bundle-row`, { timeout: 10000 });
        H.check('delete calls the bundle endpoint', calls.includes('DELETE /api/user/bundles/7'), JSON.stringify(calls));
        H.check('deleting a bundle leaves single files alone', !calls.some((c) => c.startsWith('DELETE /api/user/files')));
        H.check('open bundle stays open after the list reloads', (await visibleCount(filesOf('BundleDash02'))) === 1);

        // Phone: cards, with a labelled full-width toggle instead of the chevron.
        await page.setViewportSize({ width: 390, height: 844 });
        const mobileToggle = `${rowFor('BundleDash03')} button.bundle-toggle-mobile`;
        H.check('phone shows a labelled toggle', (await page.isVisible(mobileToggle)) && /Show 1 file/.test(await page.textContent(mobileToggle)));
        H.check('phone hides the chevron', !(await page.isVisible(`${rowFor('BundleDash03')} button.bundle-toggle`)));
        await page.click(mobileToggle);
        H.check('phone toggle opens the files', (await visibleCount(filesOf('BundleDash03'))) === 1 && /Hide 1 file/.test(await page.textContent(mobileToggle)));
        H.check('no sideways scrolling on a phone', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

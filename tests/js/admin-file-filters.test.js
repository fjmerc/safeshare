// Browser test: the admin Files tab filter row (filters, chips, result line,
// empty state, bundle warning on Delete Selected). The page runs against a
// mocked admin API. Run with SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('admin-file-filters.test.js');

const MB = 1024 * 1024;

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    const hour = 3600 * 1000;
    const iso = (ms) => new Date(Date.now() + ms).toISOString();
    const file = (id, code, size, userId, username, extra) => Object.assign({
        id, claim_code: code, original_filename: code + '.bin', file_size: size, mime_type: 'application/octet-stream',
        created_at: iso(-id * hour), expires_at: iso(24 * hour), max_downloads: null, download_count: 0, completed_downloads: 0,
        username, user_id: userId, uploader_ip: '10.0.0.1', password_protected: false, scan_status: 'clean', scan_result: '',
    }, extra);
    const files = [
        file(1, 'AliceSmall01', 100, 1, 'alice'),
        file(2, 'AliceHuge001', 2048 * MB, 1, 'alice', { bundle_id: 9 }),
        file(3, 'BobFile00001', 5 * MB, 2, 'bob'),
        file(4, 'AnonFile0001', 300, null, null),
        file(5, 'AnonFile0002', 400, null, null),
    ];
    const queries = [];

    try {
        const context = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        // Registered after the harness's /assets/ route, so these win for /admin/assets/.
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
            if (url.pathname === '/admin/api/files/uploaders') {
                return json({ anonymous_count: 2, users: [{ user_id: 1, username: 'alice', file_count: 2 }, { user_id: 2, username: 'bob', file_count: 1 }] });
            }
            if (url.pathname === '/admin/api/dashboard') {
                const q = url.searchParams;
                queries.push(q.toString());
                const match = files.filter((f) =>
                    (!q.get('user_id') || String(f.user_id) === q.get('user_id')) &&
                    (q.get('user') !== 'anonymous' || f.user_id === null) &&
                    (!q.get('min_size') || f.file_size >= Number(q.get('min_size'))) &&
                    (!q.get('max_size') || f.file_size < Number(q.get('max_size'))));
                return json({
                    files: match,
                    pagination: { page: 1, page_size: 20, total: match.length, total_pages: match.length ? 1 : 0, unfiltered_total: files.length },
                    stats: { total_files: 5, storage_used_bytes: 1, quota_limit_bytes: 0, quota_used_percent: 0, partial_uploads_bytes: 0, partial_uploads_count: 0 },
                    blocked_ips: [], system_info: {},
                });
            }
            return json({});
        });

        const page = await context.newPage();
        const lastQuery = () => queries[queries.length - 1];
        const rowCodes = () => page.$$eval('#filesTableBody tr code', (cs) => cs.map((c) => c.textContent));
        const settle = () => page.waitForTimeout(300);

        await page.goto(base + '/admin/dashboard');
        await page.waitForSelector('#filesTableBody code');
        await page.waitForFunction(() => document.querySelectorAll('#fileFilterUser option').length > 1);

        const userOptions = await page.$$eval('#fileFilterUser option', (os) => os.map((o) => o.textContent));
        H.check('user filter lists uploaders with counts',
            JSON.stringify(userOptions) === JSON.stringify(['All users', 'Anonymous (no account) · 2', 'alice · 2', 'bob · 1']), JSON.stringify(userOptions));
        const labelled = await page.$$eval('[data-file-filter]', (ss) => ss.every((s) => {
            const l = document.querySelector(`label[for="${s.id}"]`);
            return l && l.offsetParent !== null && l.textContent.trim().length > 0;
        }));
        H.check('every filter has a visible label', labelled);
        H.check('no summary without filters', await page.isHidden('#fileFilterSummary'));

        await page.selectOption('#fileFilterUser', '1');
        await settle();
        H.check('user filter sends user_id and page 1', /(^|&)user_id=1(&|$)/.test(lastQuery()) && /(^|&)page=1(&|$)/.test(lastQuery()), lastQuery());
        H.check('table shows only that user', JSON.stringify(await rowCodes()) === JSON.stringify(['AliceSmall01', 'AliceHuge001']));
        H.check('active select is marked', await page.$eval('#fileFilterUser', (s) => s.classList.contains('is-active')));
        H.check('result line counts against all files', (await page.textContent('#fileFilterCount')) === '2 of 5 files match', await page.textContent('#fileFilterCount'));
        H.check('chip names the user without the count', (await page.textContent('#fileFilterChips')).includes('User: alice') && !(await page.textContent('#fileFilterChips')).includes('·'));
        H.check('no Clear all for one filter', (await page.$$('#fileFilterChips .filter-clear-all')).length === 0);

        await page.selectOption('#fileFilterSize', 'gt1g');
        await settle();
        H.check('size preset sends bytes', /min_size=1073741824/.test(lastQuery()) && !/max_size/.test(lastQuery()) && /user_id=1/.test(lastQuery()), lastQuery());
        H.check('filters combine', JSON.stringify(await rowCodes()) === JSON.stringify(['AliceHuge001']));
        H.check('Clear all appears with two filters', (await page.$$('#fileFilterChips .filter-clear-all')).length === 1);

        await page.selectOption('#fileFilterSort', 'largest');
        await settle();
        H.check('sort is sent', /sort=largest/.test(lastQuery()), lastQuery());
        H.check('sort is marked but gets no chip', await page.$eval('#fileFilterSort', (s) => s.classList.contains('is-active')) &&
            (await page.$$('#fileFilterChips .filter-chip')).length === 2);

        // Bundle warning on Delete Selected
        await page.check('#filesTableBody .file-checkbox[data-claim-code="AliceHuge001"]');
        await page.click('#deleteSelectedBtn');
        await page.waitForSelector('#confirmModal', { state: 'visible' });
        const detail = await page.textContent('#confirmDetail');
        H.check('bundle member selected: confirm warns about the whole bundle',
            await page.isVisible('#confirmDetail') && /deletes the whole bundle, including files not shown by your filters/.test(detail), detail);
        await page.click('#confirmNo');

        // The single Delete button removes a member's whole bundle too
        await page.click('#filesTableBody [data-action="deleteFile"][data-claim-code="AliceHuge001"]');
        await page.waitForSelector('#confirmModal', { state: 'visible' });
        const one = await page.textContent('#confirmDetail');
        H.check('single delete of a bundle file warns about the whole bundle',
            await page.isVisible('#confirmDetail') && /whole bundle/.test(one), one);
        await page.click('#confirmNo');

        // Remove one chip: its filter goes, focus lands on its select
        await page.click('#fileFilterChips .filter-chip[data-filter="size"]');
        await settle();
        H.check('removing a chip clears that filter', !/min_size/.test(lastQuery()) && /user_id=1/.test(lastQuery()), lastQuery());
        H.check('focus moves to the cleared select', await page.evaluate(() => document.activeElement && document.activeElement.id) === 'fileFilterSize');
        H.check('cleared select is no longer marked', !(await page.$eval('#fileFilterSize', (s) => s.classList.contains('is-active'))));

        await page.check('#filesTableBody .file-checkbox[data-claim-code="AliceSmall01"]');
        await page.click('#deleteSelectedBtn');
        await page.waitForSelector('#confirmModal', { state: 'visible' });
        H.check('no bundle member selected: no bundle warning', await page.isHidden('#confirmDetail'));
        await page.click('#confirmNo');
        await page.click('#filesTableBody [data-action="deleteFile"][data-claim-code="AliceSmall01"]');
        await page.waitForSelector('#confirmModal', { state: 'visible' });
        H.check('single delete of a plain file: no bundle warning', await page.isHidden('#confirmDetail'));
        await page.click('#confirmNo');

        // Empty result
        await page.selectOption('#fileFilterUser', 'anonymous');
        await page.selectOption('#fileFilterSize', '1m-10m');
        await settle();
        H.check('anonymous sends user=anonymous', /user=anonymous/.test(lastQuery()) && !/user_id/.test(lastQuery()) && /min_size=1048576&max_size=10485760/.test(lastQuery()), lastQuery());
        H.check('empty result says so', /No files match these filters\./.test(await page.textContent('#filesTableBody')));
        H.check('result line shows zero', (await page.textContent('#fileFilterCount')) === '0 of 5 files match');
        await page.click('#filesTableBody [data-action="clearFileFilters"]');
        await settle();
        H.check('Clear filters drops every filter but keeps the sort',
            !/user|min_size|max_size/.test(lastQuery()) && /sort=largest/.test(lastQuery()), lastQuery());
        H.check('all files back', (await rowCodes()).length === 5);
        H.check('summary hidden again', await page.isHidden('#fileFilterSummary'));

        // Tab switch keeps filters
        await page.selectOption('#fileFilterUser', '2');
        await settle();
        await page.click('#tab-users');
        await page.click('#tab-files');
        H.check('filters survive a tab switch', (await page.inputValue('#fileFilterUser')) === '2' && JSON.stringify(await rowCodes()) === JSON.stringify(['BobFile00001']));
        const before = queries.length;
        await page.click('#refreshBtn');
        await settle();
        H.check('refresh keeps filters', queries.length > before && /user_id=2/.test(lastQuery()), lastQuery());

        // Dark mode: the active marker stays visible
        await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'));
        const [activeBg, plainBg] = await page.evaluate(() => [
            getComputedStyle(document.getElementById('fileFilterUser')).backgroundColor,
            getComputedStyle(document.getElementById('fileFilterScan')).backgroundColor,
        ]);
        H.check('dark mode: active select differs from the rest', activeBg !== plainBg, activeBg + ' vs ' + plainBg);

        // Phone: filters wrap into a grid, no sideways scrolling
        await page.setViewportSize({ width: 390, height: 844 });
        await settle();
        const lefts = await page.$$eval('.file-filter', (els) => els.map((e) => Math.round(e.getBoundingClientRect().left)));
        H.check('phone: filters sit two to a row', new Set(lefts).size === 2, JSON.stringify(lefts));
        H.check('phone: no sideways scrolling', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

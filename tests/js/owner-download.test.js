// Browser test: downloading your own files from the dashboard (owner
// download). The page runs against a mocked API. Run with
// SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('owner-download.test.js');

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    const hour = 3600 * 1000;
    const iso = (ms) => new Date(Date.now() + ms).toISOString();
    const file = (id, code, name, extra) => Object.assign({
        id, claim_code: code, original_filename: name, file_size: 10, mime_type: 'text/plain',
        created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null, download_count: 0, completed_downloads: 0,
        download_url: base + '/api/claim/' + code, is_expired: false, is_password_protected: false, client_encrypted: false,
    }, extra);
    const files = [
        file(1, 'PlainFile01', 'report.pdf'),
        // The server sets is_expired for a file at its download limit too.
        file(2, 'LimitFile01', 'photo.jpg', { max_downloads: 1, download_count: 1, completed_downloads: 1, is_password_protected: true, is_expired: true }),
        file(3, 'CryptFile01', 'contract.pdf', { client_encrypted: true }),
        file(4, 'OldFile0001', 'notes.txt', { expires_at: iso(-hour), is_expired: true }),
        file(5, 'GoneFile001', 'gone.txt'),
    ];
    const bundles = [{
        id: 7, bundle_code: 'BundleOwn01', created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null,
        password_protected: false, client_encrypted: false, file_count: 2, total_size: 7,
        files: [{ position: 0, name: 'cover.png', size: 3, completed_downloads: 0 }, { position: 1, name: 'slide-2.png', size: 4, completed_downloads: 0 }],
    }, {
        id: 8, bundle_code: 'BundleOwn02', created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null,
        password_protected: false, client_encrypted: true, file_count: 1, total_size: 5,
        files: [{ position: 0, name: 'secret.bin', size: 5, completed_downloads: 0 }],
    }];
    const calls = [];

    try {
        const context = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        await context.route(base + '/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/dashboard.html')),
        }));
        await context.route(/\/api\/(?!config)/, (route) => {
            const req = route.request();
            const p = new URL(req.url()).pathname;
            const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
            if (p.endsWith('/download')) {
                calls.push(req.method() + ' ' + p);
                if (p.includes('GoneFile001')) return route.fulfill({ status: 404, body: '' });
                const name = p.includes('/bundles/') ? 'slide-2.png' : 'report.pdf';
                return route.fulfill({ status: 200, contentType: 'application/octet-stream', body: 'owner bytes',
                    headers: { 'Content-Disposition': `attachment; filename="${name}"` } });
            }
            if (p === '/api/auth/user') return json({ id: 1, username: 'alice', role: 'user' });
            if (p === '/api/user/files') return json({ files, total: files.length, limit: 100, offset: 0 });
            if (p === '/api/user/bundles') return json({ bundles, total: bundles.length, limit: 100, offset: 0 });
            return json({});
        });
        const page = await context.newPage();
        await page.goto(base + '/dashboard');
        await page.waitForSelector('#filesContainer table.files-table');
        await page.waitForSelector('#bundlesSection:not(.hidden)');

        const rowOf = (name) => `#filesContainer tr:has(.file-name-text:text-is("${name}"))`;
        const dlOf = (name) => `${rowOf(name)} .actions-cell [data-action="ownerDownload"]`;

        const firstActions = await page.$$eval('#filesContainer tbody tr', (trs) => trs.map((tr) => tr.querySelector('.actions-cell button')?.getAttribute('data-action')));
        H.check('download is the first action on every upload', firstActions.every((a) => a === 'ownerDownload'), JSON.stringify(firstActions));
        H.check('plain file can be downloaded', await page.isEnabled(dlOf('report.pdf')));
        H.check('file at its download limit can still be downloaded', await page.isEnabled(dlOf('photo.jpg')));
        H.check('encrypted file cannot', await page.isDisabled(dlOf('contract.pdf')));
        H.check('expired file cannot', await page.isDisabled(dlOf('notes.txt')));
        H.check('encrypted file is tagged', /Encrypted/.test(await page.textContent(rowOf('contract.pdf'))));
        H.check('password file is tagged', /Password/.test(await page.textContent(rowOf('photo.jpg'))));
        const tops = await page.$$eval(`${rowOf('report.pdf')} .actions-cell button`, (bs) => bs.map((b) => Math.round(b.getBoundingClientRect().top)));
        H.check('upload actions fit on one line', tops.length === 3 && new Set(tops).size === 1, JSON.stringify(tops));

        // Playwright doesn't pass a link-triggered download through
        // context.route, so the download itself is checked by its URL here
        // (the Go tests cover what the server sends).
        const [download] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click(dlOf('report.pdf'))]);
        H.check('click downloads the file', new URL(download.url()).pathname === '/api/user/files/PlainFile01/download', download.url());
        H.check('checks with HEAD before downloading',
            JSON.stringify(calls) === JSON.stringify(['HEAD /api/user/files/PlainFile01/download']), JSON.stringify(calls));
        await page.waitForFunction(() => /count/.test(document.getElementById('toastContainer').textContent), null, { timeout: 5000 });
        H.check('says your downloads are not counted', /don.t count/.test(await page.textContent('#toastContainer')));

        calls.length = 0;
        let downloaded = false;
        page.once('download', () => { downloaded = true; });
        await page.click(dlOf('gone.txt'));
        await page.waitForFunction(() => /no longer available/.test(document.getElementById('toastContainer').textContent), null, { timeout: 5000 });
        H.check('a refused check shows a message and downloads nothing', !downloaded && calls.length === 1 && calls[0].startsWith('HEAD'), JSON.stringify(calls));

        // Bundles: each file row gets the button; an encrypted bundle's are greyed out.
        await page.click('#bundlesToggleAllBtn');
        const bundleDl = '#bundlesContainer tr.bundle-file-row[data-bundle-id="7"]:not([hidden]) [data-action="ownerDownload"]';
        H.check('each bundle file has a download button', (await page.$$(bundleDl)).length === 2);
        H.check('encrypted bundle files cannot be downloaded',
            await page.isDisabled('#bundlesContainer tr.bundle-file-row[data-bundle-id="8"] [data-action="ownerDownload"]'));
        calls.length = 0;
        const [bdl] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#bundle-7-file-1 [data-action="ownerDownload"]')]);
        H.check('bundle file downloads through the bundle route',
            new URL(bdl.url()).pathname === '/api/user/bundles/7/files/1/download' && calls[0] === 'HEAD /api/user/bundles/7/files/1/download', bdl.url() + ' ' + JSON.stringify(calls));

        // Phone: the button sits on each closed upload card too.
        await page.setViewportSize({ width: 390, height: 844 });
        H.check('phone cards show the button', await page.isVisible(`${rowOf('report.pdf')} .upload-quick-download`));
        H.check('the phone button is greyed out where downloads are', await page.isDisabled(`${rowOf('contract.pdf')} .upload-quick-download`));
        H.check('no sideways scrolling on a phone', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

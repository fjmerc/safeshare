// Browser test: My Uploads on the dashboard. Picking several files to delete
// at once (all screen sizes) and compact, tap-to-open cards on phones. The
// page runs against a mocked API. Run with SAFESHARE_BROWSER_TESTS=1 (see
// bundle-harness.js).

const fs = require('fs');
const path = require('path');
const H = require('./bundle-harness');
H.requireBrowserTests('uploads-compact-bulk.test.js');

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    const hour = 3600 * 1000;
    const iso = (ms) => new Date(Date.now() + ms).toISOString();
    const file = (id, code, name, extra) => Object.assign({
        id, claim_code: code, original_filename: name, file_size: 2048, mime_type: 'text/plain',
        created_at: iso(-hour), expires_at: iso(24 * hour), max_downloads: null, download_count: 0, completed_downloads: 0,
        download_url: base + '/api/claim/' + code, is_expired: false, is_password_protected: false, client_encrypted: false,
    }, extra);
    let files = [];
    for (let i = 1; i <= 8; i++) files.push(file(i, 'BulkCode0' + i, `file-${i}.txt`));
    const bulkBodies = [];
    let filesLoads = 0;

    try {
        const context = await H.newBrowserContext(browser, base, { viewport: { width: 1280, height: 900 } });
        await context.route(base + '/dashboard', (route) => route.fulfill({
            status: 200, contentType: 'text/html', body: fs.readFileSync(path.join(H.repoRoot, 'internal/static/web/dashboard.html')),
        }));
        await context.route(/\/api\/(?!config)/, (route) => {
            const req = route.request();
            const p = new URL(req.url()).pathname;
            const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
            if (p === '/api/auth/user') return json({ id: 1, username: 'alice', role: 'user' });
            if (p === '/api/user/files') { filesLoads++; return json({ files, total: files.length, limit: 100, offset: 0 }); }
            if (p === '/api/user/bundles') return json({ bundles: [], total: 0, limit: 100, offset: 0 });
            if (p === '/api/user/files/delete/bulk' && req.method() === 'POST') {
                const ids = JSON.parse(req.postData()).file_ids;
                bulkBodies.push(ids);
                // The last id "fails" (say it was deleted elsewhere): partial success.
                const deleted = ids.slice(0, -1);
                files = files.filter((f) => !deleted.includes(f.id));
                return json({ requested_count: ids.length, deleted_count: deleted.length, deleted,
                    failed: [{ file_id: ids[ids.length - 1], error: 'File not found or does not belong to you' }] });
            }
            return json({});
        });
        const page = await context.newPage();
        await page.goto(base + '/dashboard');
        await page.waitForSelector('#filesContainer table.uploads-table');

        const row = (id) => `#filesContainer tr.upload-row[data-file-id="${id}"]`;
        const visible = (sel) => page.isVisible(sel);
        const text = (sel) => page.textContent(sel);

        // ---- Wider screens: checkboxes always there, bar once something is ticked ----
        H.check('desktop: every row has a checkbox', await page.$$eval('#filesContainer .upload-check', (b) => b.filter((x) => x.offsetParent).length) === 8);
        H.check('desktop: no Select / Expand all buttons', !(await visible('#filesSelectBtn')) && !(await visible('#filesExpandAllBtn')));
        H.check('desktop: bar hidden with nothing ticked', !(await visible('#filesBulkBar')));
        H.check('desktop: details are shown (table, not cards)', await visible(`${row(1)} .claim-code`));
        H.check('desktop: phone-only pieces stay hidden',
            !(await visible(`${row(1)} .upload-quick-download`)) && !(await visible(`${row(1)} .upload-card-toggle`)) && !(await visible(`${row(1)} .upload-card-meta`)));

        await page.check(`${row(1)} .upload-check`);
        await page.check(`${row(2)} .upload-check`);
        H.check('ticking shows the bar with the count', (await visible('#filesBulkBar')) && /2 files selected/.test(await text('#filesBulkCount')));
        H.check('delete button names the count', (await text('#filesBulkDeleteBtn')).trim() === 'Delete 2 files');
        H.check('ticked rows are highlighted', (await page.$$('#filesContainer tr.upload-row.is-selected')).length === 2);
        H.check('select-all shows a partial state', await page.$eval('#filesSelectAll', (b) => b.indeterminate && !b.checked));

        await page.check('#filesSelectAll');
        H.check('select all ticks every file', (await page.$$('#filesContainer .upload-check:checked')).length === 8 && /8 files/.test(await text('#filesBulkCount')));
        await page.uncheck('#filesSelectAll');
        H.check('unticking select all clears the bar', !(await visible('#filesBulkBar')));

        await page.check(`${row(3)} .upload-check`);
        await page.click('#filesBulkClearBtn');
        H.check('clear selection unticks and hides the bar', !(await visible('#filesBulkBar')) && (await page.$$('#filesContainer .upload-check:checked')).length === 0);

        // Delete three, one of which fails.
        for (const id of [2, 4, 6]) await page.check(`${row(id)} .upload-check`);
        await page.click('#filesBulkDeleteBtn');
        await page.waitForSelector('#deleteModal.show');
        H.check('confirm names how many', (await text('#deleteModalTitle')).trim() === 'Delete 3 files?');
        const listed = await page.$$eval('#deleteModalList li', (lis) => lis.map((li) => li.textContent));
        H.check('confirm lists the files', JSON.stringify(listed) === JSON.stringify(['file-2.txt', 'file-4.txt', 'file-6.txt']), JSON.stringify(listed));
        H.check('confirm button names the count', (await text('#deleteConfirmBtn')).trim() === 'Delete 3 files');
        const loadsBefore = filesLoads;
        await page.click('#deleteConfirmBtn');
        await page.waitForFunction(() => /Deleted 2 of 3 files/.test(document.getElementById('toastContainer').textContent), null, { timeout: 5000 });
        H.check('one request with the picked ids', bulkBodies.length === 1 && JSON.stringify(bulkBodies[0]) === '[2,4,6]', JSON.stringify(bulkBodies));
        H.check('partial failure is reported', /1 couldn.t be deleted/.test(await text('#toastContainer')));
        await page.waitForFunction((n) => document.querySelectorAll('#filesContainer tr.upload-row').length === n, 6, { timeout: 5000 });
        H.check('list reloads after deleting', filesLoads > loadsBefore);
        H.check('selection is cleared afterwards', !(await visible('#filesBulkBar')) && (await page.$$('#filesContainer .upload-check:checked')).length === 0);

        // The single delete still reads as before (bulk wording doesn't stick).
        await page.click(`${row(1)} [data-action="deleteFile"]`);
        await page.waitForSelector('#deleteModal.show');
        H.check('single delete keeps its own wording',
            (await text('#deleteModalTitle')).trim() === 'Delete File' && (await text('#deleteConfirmBtn')).trim() === 'Delete' && !(await visible('#deleteModalList')));
        await page.click('#deleteCancelBtn');

        // ---- Phones: compact cards ----
        await page.setViewportSize({ width: 390, height: 844 });
        H.check('phone: cards start closed (no claim code)', !(await visible(`${row(1)} .claim-code`)));
        H.check('phone: closed card shows name, size and status',
            (await visible(`${row(1)} .file-name-text`)) && /2\.00 KB/.test(await text(`${row(1)} .upload-card-meta`)) && /Active/.test(await text(`${row(1)} .upload-card-meta`)));
        H.check('phone: closed card keeps one-tap download', await visible(`${row(1)} .upload-quick-download`));
        H.check('phone: closed card has an open arrow', (await visible(`${row(1)} .upload-card-toggle`)) && (await page.getAttribute(`${row(1)} .upload-card-toggle`, 'aria-expanded')) === 'false');
        H.check('phone: no checkboxes until Select', !(await visible(`${row(1)} .upload-check`)));
        H.check('phone: rename hidden on a closed card', !(await visible(`${row(1)} [data-action="renameFile"]`)));
        const closedH = await page.$eval(row(1), (r) => r.getBoundingClientRect().height);

        await page.click(`${row(1)} .file-name-text`);
        H.check('phone: tapping the name opens the card', (await visible(`${row(1)} .claim-code`)) && (await page.getAttribute(`${row(1)} .upload-card-toggle`, 'aria-expanded')) === 'true');
        H.check('phone: open card shows its buttons', (await visible(`${row(1)} .actions-cell [data-action="deleteFile"]`)) && (await visible(`${row(1)} [data-action="renameFile"]`)));
        H.check('phone: closed cards are compact', closedH < 90, String(closedH));
        await page.click(`${row(1)} .upload-card-toggle`);
        H.check('phone: the arrow closes it again', !(await visible(`${row(1)} .claim-code`)));

        await page.click('#filesExpandAllBtn');
        H.check('phone: expand all opens every card', (await page.$$('#filesContainer tr.upload-row.is-open')).length === 6 && /Collapse all/.test(await text('#filesExpandAllText')));
        await page.click('#filesExpandAllBtn');
        H.check('phone: collapse all closes them', (await page.$$('#filesContainer tr.upload-row.is-open')).length === 0 && /Expand all/.test(await text('#filesExpandAllText')));

        await page.click(`${row(3)} .upload-card-toggle`);
        await page.click('#refreshBtn');
        await page.waitForFunction(() => document.querySelector('#filesContainer tr.upload-row[data-file-id="3"]'), null, { timeout: 5000 });
        await page.waitForTimeout(300);
        H.check('phone: an open card stays open after the list reloads', await visible(`${row(3)} .claim-code`));
        await page.click(`${row(3)} .upload-card-toggle`);

        // ---- Phones: choosing files ----
        await page.click('#filesSelectBtn');
        H.check('phone: Select shows checkboxes and the bottom bar', (await visible(`${row(1)} .upload-check`)) && (await visible('#filesBulkBar')));
        H.check('phone: bar sits at the bottom of the screen', await page.$eval('#filesBulkBar', (b) => getComputedStyle(b).position === 'fixed' && Math.abs(b.getBoundingClientRect().bottom - window.innerHeight) < 2));
        H.check('phone: nothing picked yet, delete disabled', /0 selected/.test(await text('#filesBulkCount')) && await page.isDisabled('#filesBulkDeleteBtn'));
        H.check('phone: arrows and quick download step aside', !(await visible(`${row(1)} .upload-card-toggle`)) && !(await visible(`${row(1)} .upload-quick-download`)));
        H.check('phone: Expand all hidden while choosing', !(await visible('#filesExpandAllBtn')));
        await page.click(`${row(1)} .file-name-text`);
        H.check('phone: tapping a card ticks it', (await page.isChecked(`${row(1)} .upload-check`)) && /1 selected/.test(await text('#filesBulkCount')));
        H.check('phone: tapping a card does not open it', !(await visible(`${row(1)} .claim-code`)));
        await page.click(`${row(1)} .upload-check`);
        H.check('phone: the checkbox unticks it', !(await page.isChecked(`${row(1)} .upload-check`)));
        H.check('phone: Select turns into Select all', /Select all/.test(await text('#filesSelectText')));
        await page.click('#filesSelectBtn');
        H.check('phone: Select all ticks everything', /6 selected/.test(await text('#filesBulkCount')) && /Select none/.test(await text('#filesSelectText')));

        await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
        const covered = await page.evaluate(() => {
            const rows = document.querySelectorAll('#filesContainer tr.upload-row');
            const last = rows[rows.length - 1].getBoundingClientRect();
            return last.bottom > document.getElementById('filesBulkBar').getBoundingClientRect().top;
        });
        // The files section isn't the last on the page, so also check the
        // padding that would keep the last card clear if it were.
        H.check('phone: room below the last card for the bar',
            !covered && await page.$eval('#filesContainer', (c) => parseFloat(getComputedStyle(c).paddingBottom) >= 64));
        H.check('phone: no sideways scrolling', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));

        await page.click('#filesSelectCancelBtn');
        H.check('phone: Cancel leaves select mode and clears ticks',
            !(await visible('#filesBulkBar')) && (await page.$$('#filesContainer .upload-check:checked')).length === 0 && /^Select$/.test((await text('#filesSelectText')).trim()));

        // Turning the phone sideways (wider than 640px) ends select mode, since
        // its Cancel button only shows on phones.
        await page.click('#filesSelectBtn');
        await page.click(`${row(1)} .file-name-text`);
        await page.setViewportSize({ width: 844, height: 390 });
        await page.waitForTimeout(100);
        H.check('rotating to landscape leaves select mode',
            !(await page.$eval('#filesSection', (s) => s.classList.contains('select-mode'))) && !(await visible('#filesBulkBar')));
        await page.setViewportSize({ width: 390, height: 844 });

        // Pick two on the phone and delete them.
        bulkBodies.length = 0;
        await page.click('#filesSelectBtn');
        await page.click(`${row(3)} .file-name-text`);
        await page.click(`${row(5)} .file-name-text`);
        await page.click('#filesBulkDeleteBtn');
        await page.waitForSelector('#deleteModal.show');
        await page.click('#deleteConfirmBtn');
        await page.waitForFunction(() => /Deleted 1 of 2 files/.test(document.getElementById('toastContainer').textContent), null, { timeout: 5000 });
        H.check('phone: delete sends the picked ids', JSON.stringify(bulkBodies) === '[[3,5]]', JSON.stringify(bulkBodies));
        H.check('phone: select mode ends after deleting', !(await page.$eval('#filesSection', (s) => s.classList.contains('select-mode'))));

        // Tokens keep their own cards (the compact rules are only for uploads).
        H.check('tokens table is untouched', (await page.$$('.tokens-table tr.upload-row')).length === 0);
        await context.close();
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

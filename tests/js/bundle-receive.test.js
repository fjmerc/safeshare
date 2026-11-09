// Browser test: the bundle receive page (#/bundle/CODE[/key/KEY]).
// Run with SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const H = require('./bundle-harness');
H.requireBrowserTests('bundle-receive.test.js');

// Create and publish a plain bundle through the API.
async function apiBundle(baseURL, files, settings = {}) {
    const create = await fetch(baseURL + '/api/bundles', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ file_count: files.length }, settings)),
    });
    const draft = await create.json();
    for (let i = 0; i < files.length; i++) {
        const form = new FormData();
        form.append('file', new Blob([files[i][1]]), files[i][0]);
        form.append('bundle_id', String(draft.bundle_id));
        form.append('bundle_position', String(i));
        const r = await fetch(baseURL + '/api/upload', { method: 'POST', headers: { 'X-Bundle-Upload-Token': draft.upload_token }, body: form });
        if (r.status !== 201) throw new Error('member upload: ' + r.status + ' ' + await r.text());
    }
    const pub = await fetch(baseURL + '/api/bundles/' + draft.bundle_id + '/publish', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Bundle-Upload-Token': draft.upload_token }, body: '{}',
    });
    if (!pub.ok) throw new Error('publish: ' + pub.status);
    return draft.bundle_code;
}

// Create an encrypted bundle through the upload page; returns its link.
async function e2eBundleViaPage(browser, baseURL, paths, hideFilename = true) {
    const context = await H.newBrowserContext(browser, baseURL);
    const page = await context.newPage();
    await page.goto(baseURL + '/');
    await page.evaluate((hideFilename) => {
        const t = document.getElementById('e2eEncryptionToggle');
        if (t && !t.checked) t.click();
        const h = document.getElementById('e2eHideFilenameToggle');
        if (h && h.checked !== hideFilename) h.click();
    }, hideFilename);
    await page.setInputFiles('#fileInput', paths);
    await page.waitForFunction(() => !document.getElementById('uploadButton').disabled);
    await page.click('#uploadButton');
    await page.waitForSelector('#resultsSection:not(.hidden)', { timeout: 30000 });
    const link = await page.inputValue('#downloadUrl');
    await context.close();
    return link;
}

// Open a link with navigator.share stubbed; returns page, file request log and context.
async function openReceive(browser, baseURL, link) {
    const context = await H.newBrowserContext(browser, baseURL);
    await context.addInitScript(() => {
        window.__shared = null;
        navigator.canShare = () => true;
        navigator.share = async (data) => { window.__shared = data.files.map((f) => f.name + ':' + f.size); };
    });
    const page = await context.newPage();
    const fileRequests = [];
    page.on('request', (r) => { if (/\/api\/bundle\/[^/]+\/files\/\d+/.test(r.url())) fileRequests.push(r.url()); });
    await page.goto(link);
    await page.waitForSelector('#bundleView:not(.hidden)');
    return { context, page, fileRequests };
}

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const base = server.baseURL;
    const browser = await chromium.launch({ chromiumSandbox: false });

    try {
        // Unlimited plain bundle: everything loads on open, thumbnails appear, Save all shares N files.
        {
            const code = await apiBundle(base, [['a.png', H.PNG_1PX], ['b.txt', 'hello'], ['c.png', H.PNG_1PX]]);
            const { context, page, fileRequests } = await openReceive(browser, base, base + '/#/bundle/' + code);
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled, null, { timeout: 30000 });
            H.check('unlimited: fetched each file once on open', fileRequests.length === 3, fileRequests.length + ' requests');
            const thumbs = await page.$$eval('#bundleReceiveList img.bundle-thumb', (imgs) => imgs.map((i) => i.src.startsWith('blob:')));
            H.check('unlimited: image thumbnails from blobs', thumbs.length === 2 && thumbs.every(Boolean), JSON.stringify(thumbs));
            H.check('unlimited: no Get files button', await page.isHidden('#bundleGetFilesButton'));
            H.check('fragment scrubbed from the address bar', !page.url().includes('#'), page.url());
            await page.click('#bundleSaveAllButton');
            await page.waitForFunction(() => window.__shared !== null);
            const shared = await page.evaluate(() => window.__shared);
            H.check('Save all shares every file with its name', JSON.stringify(shared) === JSON.stringify(['a.png:' + H.PNG_1PX.length, 'b.txt:5', 'c.png:' + H.PNG_1PX.length]), JSON.stringify(shared));
            await context.close();
        }

        // Limited bundle: nothing is fetched until Get files.
        {
            const code = await apiBundle(base, [['a.txt', 'one'], ['b.txt', 'two']], { max_downloads: 1 });
            const { context, page, fileRequests } = await openReceive(browser, base, base + '/#/bundle/' + code);
            await page.waitForSelector('#bundleGetFilesButton:not(.hidden)');
            await page.waitForTimeout(1000);
            H.check('limited: zero file requests on open', fileRequests.length === 0, fileRequests.length + ' requests');
            H.check('limited: names shown before fetching', (await page.textContent('#bundleReceiveList')).includes('a.txt'));
            H.check('limited: Save all disabled before Get files', await page.isDisabled('#bundleSaveAllButton'));
            await page.click('#bundleGetFilesButton');
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled, null, { timeout: 30000 });
            H.check('limited: Get files fetched each file once', fileRequests.length === 2, fileRequests.length + ' requests');
            await context.close();
        }

        // Encrypted bundle: names come from the manifest, files decrypt.
        const pngs = H.makeFiles([['first.png', H.PNG_1PX], ['second.txt', 'second file']]);
        const e2eLink = await e2eBundleViaPage(browser, base, pngs);
        {
            const { context, page } = await openReceive(browser, base, e2eLink);
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled, null, { timeout: 30000 });
            const text = await page.textContent('#bundleReceiveList');
            H.check('e2e: real names from the manifest', text.includes('first.png') && text.includes('second.txt') && !text.includes('encrypted.bin'), text);
            await page.click('#bundleSaveAllButton');
            await page.waitForFunction(() => window.__shared !== null);
            const shared = await page.evaluate(() => window.__shared);
            H.check('e2e: Save all shares the decrypted files', JSON.stringify(shared) === JSON.stringify(['first.png:' + H.PNG_1PX.length, 'second.txt:11']), JSON.stringify(shared));
            await context.close();
        }

        // Encrypted bundle with the names left visible: the server cleans up
        // "photo (1)&co.png"; the encrypted file list's real name must win.
        {
            const odd = H.makeFiles([['photo (1)&co.png', H.PNG_1PX], ['notes+draft.txt', 'abc']]);
            const link = await e2eBundleViaPage(browser, base, odd, false);
            const { context, page } = await openReceive(browser, base, link);
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled ||
                !document.getElementById('bundleError').classList.contains('hidden'), null, { timeout: 30000 });
            H.check('visible names with special characters: no false tamper alarm', await page.isHidden('#bundleError'),
                await page.textContent('#bundleError'));
            await page.click('#bundleSaveAllButton').catch(() => {});
            await page.waitForFunction(() => window.__shared !== null, null, { timeout: 5000 }).catch(() => {});
            const shared = await page.evaluate(() => window.__shared);
            H.check('visible names with special characters: saved under the real names',
                JSON.stringify(shared) === JSON.stringify(['photo (1)&co.png:' + H.PNG_1PX.length, 'notes+draft.txt:3']), JSON.stringify(shared));
            await context.close();
        }

        // Tampered encrypted bundle: the server swaps the two files.
        {
            const code = /#\/bundle\/([^/]+)/.exec(e2eLink)[1];
            const bodies = await Promise.all([0, 1].map(async (i) => Buffer.from(await (await fetch(base + '/api/bundle/' + code + '/files/' + i)).arrayBuffer())));
            const context = await H.newBrowserContext(browser, base);
            await context.route(/\/api\/bundle\/[^/]+\/files\/(\d+)$/, (route) => {
                const i = Number(/files\/(\d+)$/.exec(route.request().url())[1]);
                return route.fulfill({ status: 200, contentType: 'application/octet-stream', body: bodies[1 - i] });
            });
            const page = await context.newPage();
            await page.goto(e2eLink);
            await page.waitForSelector('#bundleError:not(.hidden)', { timeout: 30000 });
            H.check('tampered: error shown', /changed|match/i.test(await page.textContent('#bundleError')), await page.textContent('#bundleError'));
            H.check('tampered: Save all disabled', await page.isDisabled('#bundleSaveAllButton'));
            H.check('tampered: no file offered for saving', (await page.$$('#bundleReceiveList button.bundle-save:not([disabled])')).length === 0);
            await context.close();
        }

        // A link with a key for a bundle the server says is not encrypted.
        {
            const code = await apiBundle(base, [['x.txt', 'plain']]);
            const key = 'A'.repeat(43);
            const { context, page, fileRequests } = await openReceive(browser, base, base + '/#/bundle/' + code + '/key/' + key);
            await page.waitForSelector('#bundleError:not(.hidden)', { timeout: 10000 });
            H.check('keyed link to an unencrypted bundle: refused', fileRequests.length === 0 && await page.isDisabled('#bundleSaveAllButton'), fileRequests.length + ' requests');
            await context.close();
        }

        // Password: asked first; a wrong one asks again; the right one loads the files.
        {
            const code = await apiBundle(base, [['p.txt', 'protected']], { password: 'pw' });
            const { context, page, fileRequests } = await openReceive(browser, base, base + '/#/bundle/' + code);
            await page.waitForSelector('#bundlePasswordForm:not(.hidden)');
            H.check('password: nothing fetched before the password', fileRequests.length === 0);
            await page.fill('#bundlePassword', 'wrong');
            await page.press('#bundlePassword', 'Enter');
            await page.waitForSelector('#bundlePasswordError:not(.hidden)', { timeout: 10000 });
            H.check('password: wrong one asks again', await page.isVisible('#bundlePasswordForm'));
            await page.fill('#bundlePassword', 'pw');
            await page.press('#bundlePassword', 'Enter');
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled, null, { timeout: 30000 });
            H.check('password: right one loads the files', await page.isHidden('#bundlePasswordForm'));
            await context.close();
        }

        // Unknown code: the same not-found message the single-file page uses.
        {
            const { context, page } = await openReceive(browser, base, base + '/#/bundle/NoSuchCode123');
            await page.waitForSelector('#bundleError:not(.hidden)', { timeout: 10000 });
            H.check('unknown code: not found or expired', /not found|expired/i.test(await page.textContent('#bundleError')));
            await context.close();
        }

        // Desktop: no file sharing, so Save all downloads each file.
        {
            const code = await apiBundle(base, [['d1.txt', 'one'], ['d2.txt', 'two']]);
            const context = await H.newBrowserContext(browser, base);
            const page = await context.newPage();
            await page.goto(base + '/#/bundle/' + code);
            await page.waitForFunction(() => !document.getElementById('bundleSaveAllButton').disabled, null, { timeout: 30000 });
            const names = [];
            page.on('download', (d) => names.push(d.suggestedFilename()));
            await page.click('#bundleSaveAllButton');
            await page.waitForTimeout(2500);
            H.check('desktop: Save all downloads each file', JSON.stringify(names.sort()) === JSON.stringify(['d1.txt', 'd2.txt']), JSON.stringify(names));
            await context.close();
        }
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });

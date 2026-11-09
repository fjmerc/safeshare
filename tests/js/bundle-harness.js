// Shared harness for the bundle browser tests (bundle-*.test.js).
//
// These tests need a running SafeShare server, so they only run when asked:
//
//   SAFESHARE_BROWSER_TESTS=1 node tests/js/bundle-upload.test.js
//
// Otherwise they print SKIP and exit 0, so the CI loop over tests/js/*.test.js
// is unaffected. The server is a scratch container from the image
// safeshare:bundle-e2e (built from this checkout if missing; set
// SAFESHARE_E2E_REBUILD=1 to rebuild). The page and its scripts are served
// to the browser from the working tree (internal/static/web), so frontend
// edits need no rebuild.

const fs = require('fs');
const net = require('net');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const webRoot = path.join(repoRoot, 'internal/static/web');
const IMAGE = 'safeshare:bundle-e2e';

function requireBrowserTests(name) {
    if (process.env.SAFESHARE_BROWSER_TESTS !== '1') {
        console.log('SKIP ' + name + ' (set SAFESHARE_BROWSER_TESTS=1 to run; needs Docker and Playwright)');
        process.exit(0);
    }
}

function loadPlaywright() {
    const root = execFileSync('npm', ['root', '-g']).toString().trim();
    return require(path.join(root, 'playwright'));
}

function freePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.listen(0, '127.0.0.1', () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
        srv.on('error', reject);
    });
}

function ensureImage() {
    let have = false;
    try {
        execFileSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore' });
        have = true;
    } catch (e) { /* not built yet */ }
    if (!have || process.env.SAFESHARE_E2E_REBUILD === '1') {
        console.log('building ' + IMAGE + ' ...');
        execFileSync('docker', ['build', '-q', '-t', IMAGE, repoRoot], { stdio: 'inherit' });
    }
}

/**
 * Start a scratch server. env adds/overrides container variables.
 * @returns {Promise<{baseURL: string, adminPassword: string, stop: () => void}>}
 */
async function startServer(env = {}) {
    ensureImage();
    const port = await freePort();
    const name = 'safeshare-bundle-e2e-' + port;
    const adminPassword = 'BundleE2E-' + port + '!';
    const vars = Object.assign({
        ADMIN_USERNAME: 'admin',
        ADMIN_PASSWORD: adminPassword,
        QUOTA_LIMIT_GB: '5',
        RATE_LIMIT_UPLOAD: '1000',
        RATE_LIMIT_DOWNLOAD: '1000',
    }, env);
    const args = ['run', '-d', '--rm', '--name', name, '-p', '127.0.0.1:' + port + ':8080'];
    for (const [k, v] of Object.entries(vars)) args.push('-e', k + '=' + v);
    args.push(IMAGE);
    execFileSync('docker', args, { stdio: 'ignore' });
    const stop = () => { try { execFileSync('docker', ['rm', '-f', name], { stdio: 'ignore' }); } catch (e) { /* gone */ } };
    process.on('exit', stop);

    const baseURL = 'http://127.0.0.1:' + port;
    for (let i = 0; i < 120; i++) {
        try {
            const r = await fetch(baseURL + '/api/config');
            if (r.ok) return { baseURL, adminPassword, stop };
        } catch (e) { /* not up yet */ }
        await new Promise((r) => setTimeout(r, 500));
    }
    stop();
    throw new Error('scratch server did not start');
}

const CONTENT_TYPES = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };

/** Serve index.html and /assets/*.js|css from the working tree. */
async function routeWorkingTree(context, baseURL) {
    const serve = (file) => async (route) => {
        if (!fs.existsSync(file)) return route.continue();
        await route.fulfill({ status: 200, contentType: CONTENT_TYPES[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) });
    };
    await context.route(baseURL + '/', serve(path.join(webRoot, 'index.html')));
    await context.route(/\/assets\/[^/?]+\.(js|css)(\?.*)?$/, (route) => {
        const name = new URL(route.request().url()).pathname.replace(/^\/assets\//, '');
        return serve(path.join(webRoot, 'assets', name))(route);
    });
}

async function newBrowserContext(browser, baseURL, options = {}) {
    const context = await browser.newContext(Object.assign({ serviceWorkers: 'block', acceptDownloads: true }, options));
    await routeWorkingTree(context, baseURL);
    return context;
}

let failures = 0;
function check(name, ok, detail) {
    if (ok) {
        console.log('PASS ' + name);
    } else {
        failures++;
        console.log('FAIL ' + name + (detail ? ' -- ' + detail : ''));
    }
}
function finish() {
    if (failures > 0) {
        console.log(failures + ' FAILED');
        process.exit(1);
    }
    console.log('ALL PASSED');
}

/** Write small files to a temp dir and return their paths. */
function makeFiles(spec) {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'bundle-e2e-'));
    return spec.map(([name, data]) => {
        const p = path.join(dir, name);
        fs.writeFileSync(p, data);
        return p;
    });
}

// A 1x1 PNG.
const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');

module.exports = { requireBrowserTests, loadPlaywright, startServer, newBrowserContext, check, finish, makeFiles, PNG_1PX, repoRoot };

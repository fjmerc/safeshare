// The receive page for a bundle link: #/bundle/CODE, or #/bundle/CODE/key/KEY
// for an end-to-end encrypted bundle.
//
// A bundle with no download limit is fetched as soon as the page opens, so
// thumbnails appear and Save all is a single tap. A bundle with a limit waits
// for "Get files", so opening the link by accident spends nothing. Files are
// held in memory; Save all hands them to the phone's share sheet (one more
// tap saves them all to Photos) or, without file sharing, downloads each one.
// Thumbnails come only from files already fetched, never from the file URL.
// An encrypted bundle's files are checked against its encrypted file list;
// if anything differs, nothing is offered for saving.
(function () {
    'use strict';

    // Same ceiling as the E2E large-file warning: above it, files are not
    // held in memory together; each is fetched only when its button is pressed.
    var MEMORY_CEILING = 500 * 1024 * 1024;

    var MSG_NOT_FOUND = 'These files were not found or have expired. Files are deleted automatically after their expiration time. Ask the sender for a new link if you still need them.';
    var MSG_TAMPERED = 'These files don\'t match what the sender uploaded: something changed them after they were sent. Nothing was saved. Ask the sender to send them again.';
    var MSG_KEY_BUT_PLAIN = 'This link has a decryption key, but the server says these files are not encrypted. That doesn\'t match what the sender made, so nothing was downloaded.';
    var MSG_MISSING_KEY = 'This link is missing its decryption key (the part after /key/). Ask the sender for the full link.';

    var EXT_TYPES = {
        png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif',
        heic: 'image/heic', heif: 'image/heif', bmp: 'image/bmp',
        mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm',
        pdf: 'application/pdf', txt: 'text/plain'
    };

    var state = null;

    function el(id) { return document.getElementById(id); }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        var units = ['KB', 'MB', 'GB'];
        var v = bytes / 1024;
        var i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        return (v < 10 ? v.toFixed(1) : Math.round(v)) + ' ' + units[i];
    }

    function typeFor(name, serverType) {
        if (serverType && serverType !== 'application/octet-stream') return serverType;
        var m = /\.([A-Za-z0-9]+)$/.exec(name || '');
        return (m && EXT_TYPES[m[1].toLowerCase()]) || 'application/octet-stream';
    }

    function base64ToBuffer(b64) {
        var binary = atob(b64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function setStatus(text) { el('bundleStatus').textContent = text || ''; }

    function fail(message) {
        state.failed = true;
        var err = el('bundleError');
        err.textContent = message;
        err.classList.remove('hidden');
        setStatus('');
        el('bundleSaveAllButton').disabled = true;
        el('bundleGetFilesButton').classList.add('hidden');
        el('bundlePasswordForm').classList.add('hidden');
        state.entries.forEach(function (e) {
            if (e.saveButton) e.saveButton.disabled = true;
            if (e.url) { URL.revokeObjectURL(e.url); e.url = null; }
            e.file = null;
        });
    }

    // A file could not be fetched for an ordinary reason (network, server
    // busy, limit reached). Keep the files already fetched - their downloads
    // are spent - and offer to try the rest again.
    function softFail(message) {
        var err = el('bundleError');
        err.textContent = message + ' Files already downloaded are kept; try again to get the rest.';
        err.classList.remove('hidden');
        setStatus('');
        var retry = el('bundleGetFilesButton');
        retry.textContent = 'Try again';
        retry.classList.remove('hidden');
    }

    function showView() {
        var tabs = document.querySelector('.tabs');
        if (tabs) tabs.classList.add('hidden');
        document.querySelectorAll('.tab-content').forEach(function (t) {
            t.classList.remove('active');
            t.classList.add('hidden');
        });
        el('bundleView').classList.remove('hidden');
    }

    function renderList() {
        var list = el('bundleReceiveList');
        list.innerHTML = '';
        state.entries.forEach(function (entry) {
            var li = document.createElement('li');
            li.dataset.position = String(entry.position);
            var thumb = document.createElement('span');
            thumb.className = 'bundle-thumb-placeholder';
            thumb.setAttribute('aria-hidden', 'true');
            thumb.textContent = /^video\//.test(entry.type) ? '▶' : (/^image\//.test(entry.type) ? '' : '📄');
            var info = document.createElement('span');
            info.className = 'bundle-receive-info';
            var name = document.createElement('span');
            name.className = 'bundle-receive-name';
            name.textContent = entry.name;
            name.title = entry.name;
            var size = document.createElement('span');
            size.className = 'bundle-receive-size';
            size.textContent = formatSize(entry.size);
            info.append(name, size);
            var save = document.createElement('button');
            save.type = 'button';
            save.className = 'bundle-save btn-small';
            save.textContent = 'Save';
            save.disabled = true;
            save.setAttribute('aria-label', 'Save ' + entry.name);
            save.addEventListener('click', function () { saveOne(entry); });
            li.append(thumb, info, save);
            list.appendChild(li);
            entry.li = li;
            entry.thumb = thumb;
            entry.saveButton = save;
        });
    }

    async function open(fragment) {
        state = { code: fragment.bundleCode, keyText: fragment.encryptionKey, cryptoKey: null, password: '', entries: [], failed: false, busy: false };
        showView();
        setStatus('Loading...');
        bindOnce();

        var info;
        try {
            var res = await fetch('/api/bundle/' + encodeURIComponent(state.code) + '/info');
            if (res.status === 404) { fail(MSG_NOT_FOUND); return; }
            if (!res.ok) { fail('These files could not be loaded right now. Try again later.'); return; }
            info = await res.json();
        } catch (e) {
            fail('These files could not be loaded. Check your connection and try again.');
            return;
        }
        state.info = info;

        if (state.keyText && !info.client_encrypted) { fail(MSG_KEY_BUT_PLAIN); return; }
        if (info.client_encrypted && !state.keyText) { fail(MSG_MISSING_KEY); return; }

        if (info.client_encrypted) {
            try {
                state.cryptoKey = await SafeShareCrypto.importKey(state.keyText);
                state.manifest = await SafeShareCrypto.openManifest(state.cryptoKey, base64ToBuffer(info.encrypted_manifest || ''));
            } catch (e) {
                fail(MSG_TAMPERED);
                return;
            }
            if (state.manifest.files.length !== info.files.length) { fail(MSG_TAMPERED); return; }
        }

        state.entries = info.files.map(function (f, i) {
            var m = state.manifest ? state.manifest.files[i] : null;
            var name = m ? m.name : f.original_filename;
            return { position: i, name: name, size: m ? m.size : f.file_size, storedName: f.original_filename,
                storedSize: f.file_size, type: typeFor(name, m ? '' : f.mime_type), file: null, url: null };
        });
        renderList();
        state.storedTotal = info.files.reduce(function (s, f) { return s + f.file_size; }, 0);
        el('bundleTitle').textContent = info.files.length === 1 ? '1 file shared with you' : info.files.length + ' files shared with you';
        el('bundleSummary').textContent = formatSize(state.entries.reduce(function (s, e) { return s + e.size; }, 0)) +
            (info.max_downloads ? ' • each file can be downloaded ' + info.max_downloads + (info.max_downloads === 1 ? ' time' : ' times') : '');

        if (info.password_required) {
            showPasswordForm(false);
            return;
        }
        proceed();
    }

    function proceed() {
        if (state.failed) return;
        if (state.storedTotal > MEMORY_CEILING) {
            // Too much to hold at once: save each file on its own.
            setStatus('These files are too large to prepare all at once. Save them one at a time.');
            el('bundleSaveAllButton').classList.add('hidden');
            state.entries.forEach(function (e) { e.saveButton.disabled = false; e.onDemand = true; });
            return;
        }
        if (state.info.max_downloads == null) {
            fetchAll();
        } else {
            setStatus('Downloading uses up one of each file\'s downloads.');
            el('bundleGetFilesButton').classList.remove('hidden');
        }
    }

    function showPasswordForm(wrong) {
        el('bundlePasswordForm').classList.remove('hidden');
        el('bundlePasswordError').classList.toggle('hidden', !wrong);
        el('bundleGetFilesButton').classList.add('hidden');
        setStatus('');
        var input = el('bundlePassword');
        input.value = '';
        input.focus();
    }

    // Fetch, decrypt and check one file. Returns 'password' if the password
    // was refused; throws an Error with .userMessage on anything else.
    async function fetchFile(entry) {
        var headers = state.password ? { 'X-File-Password': state.password } : {};
        var res = await fetch('/api/bundle/' + encodeURIComponent(state.code) + '/files/' + entry.position, { headers: headers });
        if (res.status === 401) return 'password';
        if (!res.ok) {
            var e = new Error('fetch failed');
            e.userMessage = res.status === 410 ? 'A file has reached its download limit or is no longer available.'
                : (res.status === 404 ? MSG_NOT_FOUND : 'A file could not be downloaded right now.');
            throw e;
        }
        var buf = await res.arrayBuffer();
        var data = buf;
        var name = entry.name;
        if (state.cryptoKey) {
            var plain;
            try {
                plain = await SafeShareCrypto.decryptFile(state.cryptoKey, buf);
            } catch (err) {
                err.userMessage = MSG_TAMPERED;
                err.tampered = true;
                throw err;
            }
            var payloadName = null;
            if (entry.storedName === 'encrypted.bin' || SafeShareCrypto.hasPaddedPayloadMagic(plain)) {
                var unwrapped;
                try {
                    unwrapped = SafeShareCrypto.unwrapPayload(plain);
                } catch (err2) {
                    err2.userMessage = MSG_TAMPERED;
                    err2.tampered = true;
                    throw err2;
                }
                payloadName = unwrapped.filename;
                data = unwrapped.data;
            } else {
                data = plain;
            }
            // The name is checked only when it travelled inside the encrypted
            // payload. A name left visible was cleaned up by the server; the
            // encrypted file list holds the real one. Content is always
            // checked by size and SHA-256.
            var want = state.manifest.files[entry.position];
            var sha = await SafeShareCrypto.sha256Hex(data);
            if ((payloadName && payloadName !== want.name) || data.byteLength !== want.size || sha !== want.sha256) {
                var t = new Error('manifest mismatch');
                t.userMessage = MSG_TAMPERED;
                t.tampered = true;
                throw t;
            }
            name = want.name;
        }
        entry.file = new File([data], name, { type: entry.type });
        return 'ok';
    }

    function showThumbnail(entry) {
        if (!entry.file) return;
        if (entry.url) URL.revokeObjectURL(entry.url);
        entry.url = URL.createObjectURL(entry.file);
        if (/^image\//.test(entry.type)) {
            var img = document.createElement('img');
            img.className = 'bundle-thumb';
            img.alt = '';
            img.src = entry.url;
            entry.thumb.replaceWith(img);
            entry.thumb = img;
        }
    }

    async function fetchAll() {
        if (state.busy || state.failed) return;
        state.busy = true;
        el('bundleGetFilesButton').classList.add('hidden');
        el('bundleError').classList.add('hidden');
        try {
            for (var i = 0; i < state.entries.length; i++) {
                var entry = state.entries[i];
                if (entry.file) continue;
                setStatus('Getting file ' + (i + 1) + ' of ' + state.entries.length + '...');
                var result = await fetchFile(entry);
                if (result === 'password') {
                    state.password = '';
                    showPasswordForm(true);
                    return;
                }
                showThumbnail(entry);
                entry.saveButton.disabled = false;
            }
            setStatus('Ready to save.');
            el('bundleSaveAllButton').disabled = false;
        } catch (err) {
            if (err.tampered) {
                fail(err.userMessage);
            } else {
                softFail(err.userMessage || 'A file could not be downloaded.');
            }
        } finally {
            state.busy = false;
        }
    }

    function download(file) {
        var url = URL.createObjectURL(file);
        var a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
    }

    async function saveOne(entry) {
        if (state.failed) return;
        if (entry.onDemand && !entry.file) {
            entry.saveButton.disabled = true;
            try {
                if (await fetchFile(entry) === 'password') { showPasswordForm(true); return; }
            } catch (err) {
                if (err.tampered) {
                    fail(err.userMessage);
                } else {
                    el('bundleError').textContent = (err.userMessage || 'This file could not be downloaded.') + ' Try its Save button again.';
                    el('bundleError').classList.remove('hidden');
                    entry.saveButton.disabled = false;
                }
                return;
            }
            download(entry.file);
            entry.file = null; // don't keep large files in memory
            entry.saveButton.disabled = false;
            return;
        }
        if (entry.file) download(entry.file);
    }

    // Must run straight from the click: the share sheet only opens on a fresh tap.
    function saveAll() {
        if (state.failed) return;
        var files = state.entries.map(function (e) { return e.file; });
        if (files.some(function (f) { return !f; })) return;
        if (navigator.canShare && navigator.share && navigator.canShare({ files: files })) {
            navigator.share({ files: files }).catch(function (err) {
                if (err && err.name !== 'AbortError') {
                    setStatus('Sharing didn\'t work here; downloading the files instead.');
                    downloadEach(files);
                }
            });
            return;
        }
        downloadEach(files);
    }

    function downloadEach(files) {
        files.forEach(function (f, i) { setTimeout(function () { download(f); }, i * 400); });
    }

    var bound = false;
    function bindOnce() {
        if (bound) return;
        bound = true;
        el('bundleSaveAllButton').addEventListener('click', saveAll);
        el('bundleGetFilesButton').addEventListener('click', fetchAll);
        el('bundlePasswordForm').addEventListener('submit', function (e) {
            e.preventDefault();
            state.password = el('bundlePassword').value;
            el('bundlePasswordForm').classList.add('hidden');
            proceed();
        });
        window.addEventListener('pagehide', function () {
            if (!state) return;
            state.entries.forEach(function (e) { if (e.url) URL.revokeObjectURL(e.url); });
        });
    }

    window.SafeShareBundle = { open: open };
})();

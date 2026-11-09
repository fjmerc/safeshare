// Upload several files as one bundle: one code and one link for all of them.
//
// Flow: POST /api/bundles creates a draft and returns a one-time upload
// token; each file goes through the normal upload endpoints with the bundle
// id, its position and the token; POST /api/bundles/{id}/publish makes the
// link work. If anything fails, the draft is deleted, so there is never a
// link to part of a bundle. An end-to-end encrypted bundle uses one key for
// every file and also publishes its file list (names, sizes, SHA-256),
// encrypted under that key, so recipients can check nothing was changed.
(function () {
    'use strict';

    async function readError(response, fallback) {
        let body = {};
        try {
            body = await response.json();
        } catch (e) { /* not JSON */ }
        const err = new Error(body.error || fallback);
        err.code = body.code || '';
        err.status = response.status;
        return err;
    }

    function base64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        return btoa(binary);
    }

    // Direct upload of one member, reporting upload progress (0..1).
    function uploadDirect(file, member, clientEncrypted, onProgress) {
        return new Promise((resolve, reject) => {
            const form = new FormData();
            form.append('file', file);
            form.append('bundle_id', String(member.id));
            form.append('bundle_position', String(member.position));
            if (clientEncrypted) form.append('client_encrypted', 'true');

            const xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) onProgress(e.loaded / e.total);
            });
            xhr.addEventListener('load', () => {
                if (xhr.status === 201) {
                    resolve(JSON.parse(xhr.responseText));
                    return;
                }
                let body = {};
                try { body = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
                const err = new Error(body.error || 'Upload failed');
                err.code = body.code || '';
                reject(err);
            });
            xhr.addEventListener('error', () => reject(new Error('Upload failed: network error')));
            xhr.open('POST', '/api/upload');
            xhr.setRequestHeader('X-Bundle-Upload-Token', member.token);
            if (clientEncrypted) xhr.setRequestHeader('X-SafeShare-Client-Encrypted', 'true');
            xhr.send(form);
        });
    }

    async function uploadChunked(file, member, clientEncrypted, onProgress) {
        const uploader = new ChunkedUploader(file, {
            clientEncrypted: clientEncrypted,
            persistState: false, // a bundle is uploaded whole; no resume
            bundle: member
        });
        let failure = null;
        uploader.on('progress', (d) => onProgress(d.percentage / 100));
        uploader.on('error', (d) => {
            failure = new Error(d.error || 'Upload failed');
            failure.code = d.code || '';
        });
        try {
            await uploader.init();
            await uploader.uploadAllChunks();
            return await uploader.complete();
        } catch (e) {
            throw failure || e;
        }
    }

    async function deleteDraft(draft) {
        try {
            await fetch('/api/bundles/' + draft.bundle_id, {
                method: 'DELETE',
                headers: { 'X-Bundle-Upload-Token': draft.upload_token }
            });
        } catch (e) { /* best effort; the server's cleanup removes stale drafts */ }
    }

    /**
     * Upload files as one bundle.
     * @param {Object} opts
     * @param {File[]} opts.files
     * @param {{expiresInHours: number, maxDownloads: number, password: string}} opts.settings
     *   expiresInHours < 0 or NaN: server default; 0: never. maxDownloads 0: unlimited.
     * @param {{enabled: boolean, hideFilename: boolean, pad: boolean}} opts.e2e
     * @param {Object} opts.serverConfig - /api/config
     * @param {number} opts.maxFileSizeBytes
     * @param {function(ArrayBuffer): Promise<ArrayBuffer>} [opts.prepare] - metadata removal before encryption
     * @param {function({index: number, count: number, fraction: number, stage: string, name: string})} [opts.onProgress]
     * @returns {Promise<{bundle: Object, key: string|null, files: Array<{name: string, size: number}>}>}
     * @throws {Error} with .file (the file that failed, if any) and .code
     */
    async function uploadBundle(opts) {
        const files = opts.files;
        const e2e = opts.e2e || {};
        const report = opts.onProgress || function () {};
        const settings = opts.settings || {};

        const createBody = { file_count: files.length, client_encrypted: !!e2e.enabled };
        if (settings.expiresInHours >= 0) createBody.expires_in_hours = settings.expiresInHours;
        if (settings.maxDownloads > 0) createBody.max_downloads = settings.maxDownloads;
        if (settings.password) createBody.password = settings.password;

        const createResponse = await fetch('/api/bundles', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': 'application/json' },
                e2e.enabled ? { 'X-SafeShare-Client-Encrypted': 'true' } : {}),
            body: JSON.stringify(createBody)
        });
        if (!createResponse.ok) throw await readError(createResponse, 'Could not start the upload');
        const draft = await createResponse.json();

        let cryptoKey = null;
        let key = null;
        const manifest = { v: 1, files: [] };
        const uploaded = [];
        let current = null;
        try {
            if (e2e.enabled) {
                cryptoKey = await SafeShareCrypto.generateEncryptionKey();
                key = await SafeShareCrypto.exportKey(cryptoKey);
            }

            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                current = file;
                const member = { id: draft.bundle_id, position: i, token: draft.upload_token };
                const progress = (stage) => (fraction) => report({ index: i, count: files.length, fraction: fraction, stage: stage, name: file.name });

                let toUpload = file;
                let size = file.size;
                if (e2e.enabled) {
                    progress('preparing')(0);
                    let plain = await file.arrayBuffer();
                    if (opts.prepare) plain = await opts.prepare(plain);
                    size = plain.byteLength;
                    const sha = await SafeShareCrypto.sha256Hex(plain);
                    manifest.files.push({ position: i, name: file.name, size: size, sha256: sha });
                    const payload = e2e.pad
                        ? SafeShareCrypto.wrapPayloadPadded(e2e.hideFilename ? file.name : '', plain, opts.maxFileSizeBytes)
                        : (e2e.hideFilename ? SafeShareCrypto.wrapPayload(file.name, plain) : plain);
                    plain = null;
                    const encrypted = await SafeShareCrypto.encryptFile(cryptoKey, payload);
                    toUpload = new File([encrypted], e2e.hideFilename ? 'encrypted.bin' : file.name, { type: 'application/octet-stream' });
                }

                const chunked = opts.serverConfig.chunked_upload_enabled && toUpload.size >= opts.serverConfig.chunked_upload_threshold;
                const upload = chunked ? uploadChunked : uploadDirect;
                await upload(toUpload, member, !!e2e.enabled, progress('uploading'));
                progress('uploading')(1);
                uploaded.push({ name: file.name, size: size });
            }
            current = null;

            const publishBody = {};
            if (e2e.enabled) {
                publishBody.encrypted_manifest = base64(await SafeShareCrypto.sealManifest(cryptoKey, manifest));
            }
            const publishResponse = await fetch('/api/bundles/' + draft.bundle_id + '/publish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Bundle-Upload-Token': draft.upload_token },
                body: JSON.stringify(publishBody)
            });
            if (!publishResponse.ok) throw await readError(publishResponse, 'Could not finish the upload');
            const bundle = await publishResponse.json();
            return { bundle: bundle, key: key, files: uploaded };
        } catch (err) {
            await deleteDraft(draft);
            if (current) err.file = current.name;
            throw err;
        }
    }

    window.SafeShareBundleUpload = { uploadBundle: uploadBundle };
})();

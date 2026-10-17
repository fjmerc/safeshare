// SafeShare Client-Side Encryption Module
// Uses Web Crypto API for AES-256-GCM encryption/decryption
// Encryption format: [12-byte random IV][AES-256-GCM ciphertext + 16-byte auth tag]
// The plaintext inside is either the raw file, or a framed payload (SF01 / SF02,
// see "Payload wrapping" below). SF02 also carries the original length so the
// plaintext can be padded to a PADME size bucket (Ghost mode).

(function() {
    'use strict';

    const IV_LENGTH = 12; // 96-bit IV for AES-GCM
    const LARGE_FILE_WARNING_BYTES = 500 * 1024 * 1024; // 500MB

    /**
     * Check if the browser supports the Web Crypto API in a secure context.
     * Web Crypto requires HTTPS or localhost.
     * @returns {boolean}
     */
    function isClientEncryptionSupported() {
        return !!(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.encrypt === 'function');
    }

    /**
     * Generate a new AES-256-GCM key.
     * @returns {Promise<CryptoKey>}
     */
    async function generateEncryptionKey() {
        return await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true, // extractable — needed for export
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Export a CryptoKey to a base64url string (for URL fragment).
     * @param {CryptoKey} cryptoKey
     * @returns {Promise<string>} base64url-encoded 32 bytes
     */
    async function exportKey(cryptoKey) {
        const rawKey = await window.crypto.subtle.exportKey('raw', cryptoKey);
        return arrayBufferToBase64url(rawKey);
    }

    /**
     * Import a key from a base64url string.
     * @param {string} base64urlKey
     * @returns {Promise<CryptoKey>}
     */
    async function importKey(base64urlKey) {
        const rawKey = base64urlToArrayBuffer(base64urlKey);
        if (rawKey.byteLength !== 32) {
            throw new Error('Invalid decryption key');
        }
        return await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM', length: 256 },
            false, // not extractable — only needed for decrypt
            ['decrypt']
        );
    }

    /**
     * Encrypt file data with AES-256-GCM.
     * @param {CryptoKey} cryptoKey
     * @param {ArrayBuffer} arrayBuffer - plaintext file data
     * @returns {Promise<ArrayBuffer>} [12-byte IV][ciphertext + auth tag]
     */
    async function encryptFile(cryptoKey, arrayBuffer) {
        const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));

        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            arrayBuffer
        );

        // Prepend IV to ciphertext
        const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(ciphertext), IV_LENGTH);

        return result.buffer;
    }

    /**
     * Decrypt file data with AES-256-GCM.
     * @param {CryptoKey} cryptoKey
     * @param {ArrayBuffer} encryptedArrayBuffer - [12-byte IV][ciphertext + auth tag]
     * @returns {Promise<ArrayBuffer>} plaintext
     */
    async function decryptFile(cryptoKey, encryptedArrayBuffer) {
        if (encryptedArrayBuffer.byteLength <= IV_LENGTH) {
            throw new Error('File data is corrupted or key is wrong');
        }

        const iv = new Uint8Array(encryptedArrayBuffer, 0, IV_LENGTH);
        const ciphertext = new Uint8Array(encryptedArrayBuffer, IV_LENGTH);

        try {
            return await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                ciphertext
            );
        } catch (e) {
            throw new Error('File data is corrupted or key is wrong');
        }
    }

    /**
     * Check if a file size may cause memory issues for in-browser encryption.
     * @param {number} fileSize in bytes
     * @returns {boolean}
     */
    function isFileTooLargeForClientEncryption(fileSize) {
        return fileSize > LARGE_FILE_WARNING_BYTES;
    }

    /**
     * Parse a URL fragment for claim code and encryption key.
     * Expected format: #/claim/CODE/key/KEY
     * @param {string} hash - window.location.hash
     * @returns {{ claimCode: string, encryptionKey: string } | null}
     */
    function parseFragment(hash) {
        const match = hash.match(/^#\/claim\/([^/]+)\/key\/(.+)$/);
        if (match) {
            return { claimCode: match[1], encryptionKey: match[2] };
        }
        return null;
    }

    /**
     * Build a share URL with encryption key in the fragment.
     * @param {string} baseUrl - e.g., "https://host"
     * @param {string} claimCode
     * @param {string} base64urlKey
     * @returns {string}
     */
    function buildEncryptedUrl(baseUrl, claimCode, base64urlKey) {
        // Remove trailing slash from baseUrl
        const base = baseUrl.replace(/\/$/, '');
        return `${base}/#/claim/${claimCode}/key/${base64urlKey}`;
    }

    // === Payload wrapping ===
    //
    // Framed payload versions (the magic is "SF" + two-digit format version):
    //
    //   SF01 (filename hiding, never padded):
    //     [SF01][u32 LE name length][name UTF-8][file data]
    //   SF02 (filename hiding and/or size padding, written when the server is in
    //   anonymous mode):
    //     [SF02][u32 LE name length][u64 LE data length][name UTF-8][file data][zero padding]
    //     name length may be 0 (filename stays visible to the server); the whole
    //     payload is padded to a PADME bucket and the padding is inside the
    //     AES-GCM plaintext, so the server sees only the bucket size.
    //
    // A decrypted blob with neither magic is a legacy raw file (v1).
    // Decryption must keep understanding all three, whatever the server mode.

    var PAYLOAD_MAGIC = new Uint8Array([0x53, 0x46, 0x30, 0x31]); // "SF01"
    var PAYLOAD_MAGIC_V2 = new Uint8Array([0x53, 0x46, 0x30, 0x32]); // "SF02"
    var MAX_FILENAME_BYTES = 1024;
    var V2_FIXED_HEADER = 16; // magic(4) + name length(4) + data length(8)
    var GCM_TAG_LENGTH = 16;
    var CIPHERTEXT_OVERHEAD = IV_LENGTH + GCM_TAG_LENGTH; // what encryptFile adds
    // Smallest padded payload. PADME alone leaves tiny files (a note, a key) in
    // very fine-grained buckets; a floor puts all of them in one.
    var PAD_MIN_BYTES = 4096;
    // Room kept below the server's size limit for the multipart form around the file
    var UPLOAD_ENVELOPE_SLACK = 4096;

    function startsWith(bytes, magic) {
        if (bytes.byteLength < magic.byteLength) return false;
        for (var i = 0; i < magic.byteLength; i++) {
            if (bytes[i] !== magic[i]) return false;
        }
        return true;
    }

    /**
     * PADME padding length (Nikitin et al., "Reducing Metadata Leakage from
     * Encrypted Files and Communication with PURBs", PETS 2019). Rounds n up so
     * only the top bits of n are significant: at most ~12% overhead, and the
     * bucket reveals O(log log n) bits about n. Float arithmetic instead of
     * 32-bit bit operations so sizes above 2 GiB are handled.
     * @param {number} n non-negative integer length
     * @returns {number} padded length >= n
     */
    function padmeLength(n) {
        if (!Number.isSafeInteger(n) || n < 0) {
            throw new RangeError('Length must be a non-negative integer');
        }
        if (n < 2) return n;
        var e = Math.floor(Math.log2(n)); // floor(log2 n), corrected below
        while (Math.pow(2, e + 1) <= n) e++;
        while (Math.pow(2, e) > n) e--;
        var s = 0; // bit length of e == floor(log2 e) + 1
        for (var t = e; t > 0; t = Math.floor(t / 2)) s++;
        var lastBits = e - s;
        if (lastBits <= 0) return n;
        var unit = Math.pow(2, lastBits);
        return Math.ceil(n / unit) * unit;
    }

    /**
     * Padded payload length for an unpadded framed payload of n bytes.
     * @param {number} n header + file bytes
     * @param {number} [maxStoredBytes] the server's file size limit, which it
     *   applies to the stored (IV + ciphertext + tag) size. The bucket is capped
     *   so padding never pushes a file over it; a file that fits unpadded is
     *   never refused because of padding.
     * @returns {number}
     * @throws {Error} code PAYLOAD_TOO_LARGE if even unpadded it exceeds the limit
     */
    function paddedPayloadLength(n, maxStoredBytes) {
        var target = Math.max(padmeLength(n), PAD_MIN_BYTES);
        if (maxStoredBytes > 0) {
            var hardCap = maxStoredBytes - CIPHERTEXT_OVERHEAD;
            if (n > hardCap) {
                var err = new Error('This file is too large to upload encrypted: encryption adds a small header, and the server limit is ' +
                    maxStoredBytes + ' bytes.');
                err.code = 'PAYLOAD_TOO_LARGE';
                throw err;
            }
            // The server applies its limit to the whole upload request, not just the stored
            // file, so leave room for the form fields. A file in the last few KB below the
            // limit is therefore left unpadded rather than pushed over it.
            target = Math.min(target, Math.max(hardCap - UPLOAD_ENVELOPE_SLACK, n));
        }
        return target;
    }

    function encodeFilename(filename) {
        var nameBytes = new TextEncoder().encode(filename || '');
        if (nameBytes.byteLength > MAX_FILENAME_BYTES) {
            nameBytes = nameBytes.slice(0, MAX_FILENAME_BYTES);
        }
        return nameBytes;
    }

    /**
     * Wrap file data with filename header for encryption (SF01, unpadded).
     * Format: [SF01][4-byte name length, little-endian uint32][name UTF-8][file data]
     * @param {string} filename
     * @param {ArrayBuffer} fileArrayBuffer
     * @returns {ArrayBuffer}
     */
    function wrapPayload(filename, fileArrayBuffer) {
        var nameBytes = encodeFilename(filename);
        var headerSize = PAYLOAD_MAGIC.byteLength + 4 + nameBytes.byteLength;
        var result = new Uint8Array(headerSize + fileArrayBuffer.byteLength);
        result.set(PAYLOAD_MAGIC, 0);
        var view = new DataView(result.buffer);
        view.setUint32(PAYLOAD_MAGIC.byteLength, nameBytes.byteLength, true);
        result.set(nameBytes, PAYLOAD_MAGIC.byteLength + 4);
        result.set(new Uint8Array(fileArrayBuffer), headerSize);
        return result.buffer;
    }

    /**
     * Wrap file data in an SF02 payload padded to a PADME bucket.
     * @param {string} filename '' keeps the name out of the payload (it stays
     *   visible to the server as the upload name)
     * @param {ArrayBuffer} fileArrayBuffer
     * @param {number} [maxStoredBytes] server file size limit (see paddedPayloadLength)
     * @returns {ArrayBuffer}
     */
    function wrapPayloadPadded(filename, fileArrayBuffer, maxStoredBytes) {
        var nameBytes = encodeFilename(filename);
        var dataLength = fileArrayBuffer.byteLength;
        var used = V2_FIXED_HEADER + nameBytes.byteLength + dataLength;
        var total = paddedPayloadLength(used, maxStoredBytes);
        var result = new Uint8Array(total); // zero-filled: the padding
        result.set(PAYLOAD_MAGIC_V2, 0);
        var view = new DataView(result.buffer);
        view.setUint32(4, nameBytes.byteLength, true);
        view.setUint32(8, dataLength % 4294967296, true);
        view.setUint32(12, Math.floor(dataLength / 4294967296), true);
        result.set(nameBytes, V2_FIXED_HEADER);
        result.set(new Uint8Array(fileArrayBuffer), V2_FIXED_HEADER + nameBytes.byteLength);
        return result.buffer;
    }

    /**
     * Unwrap decrypted data to extract filename and file content. Understands
     * SF02 (padded), SF01 and legacy raw data. An SF02 payload whose lengths do
     * not fit the decrypted size, or whose padding is not all zero, is rejected.
     * @param {ArrayBuffer} decryptedArrayBuffer
     * @returns {{ filename: string|null, data: ArrayBuffer, version: number }}
     * @throws {Error} if an SF02 header is malformed
     */
    function unwrapPayload(decryptedArrayBuffer) {
        var bytes = new Uint8Array(decryptedArrayBuffer);

        if (startsWith(bytes, PAYLOAD_MAGIC_V2)) {
            if (bytes.byteLength < V2_FIXED_HEADER) {
                throw new Error('Payload header is truncated');
            }
            var v2 = new DataView(decryptedArrayBuffer);
            var nameLen = v2.getUint32(4, true);
            var dataLo = v2.getUint32(8, true);
            var dataHi = v2.getUint32(12, true);
            if (nameLen > MAX_FILENAME_BYTES) {
                throw new Error('Payload filename length is invalid');
            }
            if (dataHi >= 0x200000) { // >= 2^53 bytes
                throw new Error('Payload length exceeds the decrypted size');
            }
            var dataLen = dataHi * 4294967296 + dataLo;
            var dataStart = V2_FIXED_HEADER + nameLen;
            if (dataStart + dataLen > bytes.byteLength) {
                throw new Error('Payload length exceeds the decrypted size');
            }
            for (var i = dataStart + dataLen; i < bytes.byteLength; i++) {
                if (bytes[i] !== 0) {
                    throw new Error('Payload padding is invalid');
                }
            }
            var name = nameLen > 0
                ? new TextDecoder().decode(bytes.subarray(V2_FIXED_HEADER, dataStart))
                : null;
            return {
                filename: name,
                data: decryptedArrayBuffer.slice(dataStart, dataStart + dataLen),
                version: 2
            };
        }

        // Check for SF01 magic
        if (bytes.byteLength < 8 || !startsWith(bytes, PAYLOAD_MAGIC)) {
            // v1 format — no header, return original data
            return { filename: null, data: decryptedArrayBuffer, version: 1 };
        }
        var view = new DataView(decryptedArrayBuffer);
        var nameLength = view.getUint32(4, true);
        if (nameLength === 0 || nameLength > MAX_FILENAME_BYTES || nameLength + 8 > bytes.byteLength) {
            // Corrupt header — treat as v1
            return { filename: null, data: decryptedArrayBuffer, version: 1 };
        }
        var decoder = new TextDecoder();
        var filename = decoder.decode(bytes.slice(8, 8 + nameLength));
        var data = decryptedArrayBuffer.slice(8 + nameLength);
        return { filename: filename, data: data, version: 1 };
    }

    /**
     * True if decrypted data starts with the SF02 magic. The download page uses
     * this to unwrap padded uploads whose filename was left visible (stored under
     * the real name rather than encrypted.bin).
     * @param {ArrayBuffer} decryptedArrayBuffer
     * @returns {boolean}
     */
    function hasPaddedPayloadMagic(decryptedArrayBuffer) {
        return startsWith(new Uint8Array(decryptedArrayBuffer, 0, Math.min(4, decryptedArrayBuffer.byteLength)), PAYLOAD_MAGIC_V2);
    }

    // === Base64url helpers ===

    function arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    function base64urlToArrayBuffer(base64url) {
        // Convert base64url to base64
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }
        let binary;
        try {
            binary = atob(base64);
        } catch (e) {
            throw new Error('Invalid decryption key');
        }
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Expose public API
    window.SafeShareCrypto = {
        isClientEncryptionSupported,
        generateEncryptionKey,
        exportKey,
        importKey,
        encryptFile,
        decryptFile,
        isFileTooLargeForClientEncryption,
        parseFragment,
        buildEncryptedUrl,
        wrapPayload,
        wrapPayloadPadded,
        unwrapPayload,
        hasPaddedPayloadMagic,
        padmeLength,
        paddedPayloadLength,
        PAD_MIN_BYTES,
        CIPHERTEXT_OVERHEAD,
        LARGE_FILE_WARNING_BYTES
    };
})();

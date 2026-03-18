// SafeShare Client-Side Encryption Module
// Uses Web Crypto API for AES-256-GCM encryption/decryption
// Encryption format: [12-byte random IV][AES-256-GCM ciphertext + 16-byte auth tag]

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

    // === Payload wrapping (v2 format: filename anonymization) ===

    // Magic marker for v2 payload format
    var PAYLOAD_MAGIC = new Uint8Array([0x53, 0x46, 0x30, 0x31]); // "SF01"
    var MAX_FILENAME_BYTES = 1024;

    /**
     * Wrap file data with filename header for encryption.
     * Format: [SF01][4-byte name length, little-endian uint32][name UTF-8][file data]
     * @param {string} filename
     * @param {ArrayBuffer} fileArrayBuffer
     * @returns {ArrayBuffer}
     */
    function wrapPayload(filename, fileArrayBuffer) {
        var encoder = new TextEncoder();
        var nameBytes = encoder.encode(filename);
        if (nameBytes.byteLength > MAX_FILENAME_BYTES) {
            nameBytes = nameBytes.slice(0, MAX_FILENAME_BYTES);
        }
        var headerSize = PAYLOAD_MAGIC.byteLength + 4 + nameBytes.byteLength;
        var result = new Uint8Array(headerSize + fileArrayBuffer.byteLength);
        // Magic
        result.set(PAYLOAD_MAGIC, 0);
        // Filename length (little-endian uint32)
        var view = new DataView(result.buffer);
        view.setUint32(PAYLOAD_MAGIC.byteLength, nameBytes.byteLength, true);
        // Filename
        result.set(nameBytes, PAYLOAD_MAGIC.byteLength + 4);
        // File data
        result.set(new Uint8Array(fileArrayBuffer), headerSize);
        return result.buffer;
    }

    /**
     * Unwrap decrypted data to extract filename and file content.
     * @param {ArrayBuffer} decryptedArrayBuffer
     * @returns {{ filename: string|null, data: ArrayBuffer }}
     */
    function unwrapPayload(decryptedArrayBuffer) {
        var bytes = new Uint8Array(decryptedArrayBuffer);
        // Check for SF01 magic
        if (bytes.byteLength < 8 ||
            bytes[0] !== 0x53 || bytes[1] !== 0x46 ||
            bytes[2] !== 0x30 || bytes[3] !== 0x31) {
            // v1 format — no header, return original data
            return { filename: null, data: decryptedArrayBuffer };
        }
        var view = new DataView(decryptedArrayBuffer);
        var nameLength = view.getUint32(4, true);
        if (nameLength > MAX_FILENAME_BYTES || nameLength + 8 > bytes.byteLength) {
            // Corrupt header — treat as v1
            return { filename: null, data: decryptedArrayBuffer };
        }
        var decoder = new TextDecoder();
        var filename = decoder.decode(bytes.slice(8, 8 + nameLength));
        var data = decryptedArrayBuffer.slice(8 + nameLength);
        return { filename: filename, data: data };
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
        unwrapPayload,
        LARGE_FILE_WARNING_BYTES
    };
})();

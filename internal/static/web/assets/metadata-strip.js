/**
 * SafeShare client-side metadata stripping (dependency-free).
 *
 * Used before end-to-end encryption: the server only ever sees ciphertext, so
 * it cannot remove EXIF/XMP/text metadata itself. Supports JPEG and PNG; other
 * types pass through unchanged (callers should warn the user).
 *
 * Pure functions on ArrayBuffer/Uint8Array, exported on
 * window.SafeShareMetadata (and module.exports under Node for tests).
 */
(function (root) {
    'use strict';

    // PNG allowlist: everything not listed here is dropped (text, EXIF, time,
    // private/unknown ancillary chunks, ...).
    var PNG_KEEP = { IHDR: 1, PLTE: 1, IDAT: 1, IEND: 1, tRNS: 1, cHRM: 1, gAMA: 1, iCCP: 1,
        sBIT: 1, sRGB: 1, bKGD: 1, pHYs: 1, acTL: 1, fcTL: 1, fdAT: 1 };
    var PNG_SIG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    function toU8(input) {
        if (input instanceof Uint8Array) return input;
        if (input instanceof ArrayBuffer) return new Uint8Array(input);
        if (input && input.buffer instanceof ArrayBuffer) {
            return new Uint8Array(input.buffer, input.byteOffset || 0, input.byteLength);
        }
        throw new TypeError('Expected ArrayBuffer or Uint8Array');
    }

    /** Detect by magic bytes (never by extension). Returns 'jpeg', 'png' or null. */
    function detectType(input) {
        var b = toU8(input);
        if (b.length >= 4 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'jpeg';
        if (b.length >= 8) {
            for (var i = 0; i < 8; i++) if (b[i] !== PNG_SIG[i]) return null;
            return 'png';
        }
        return null;
    }

    function concat(parts, total) {
        var out = new Uint8Array(total);
        var pos = 0;
        for (var i = 0; i < parts.length; i++) {
            out.set(parts[i], pos);
            pos += parts[i].length;
        }
        return out;
    }

    // "Adobe" APP14 holds only the colour-transform flag; without it CMYK/YCCK
    // JPEGs decode with wrong colours. It carries no personal data, so keep it.
    function isAdobeApp14(b, start, end) {
        // start points at the 2 length bytes; "Adobe" follows at start+2
        return end - start >= 7 && b[start + 2] === 0x41 && b[start + 3] === 0x64 &&
            b[start + 4] === 0x6F && b[start + 5] === 0x62 && b[start + 6] === 0x65;
    }

    function isJfifApp0(b, start, end) {
        return end - start >= 16 && b[start + 2] === 0x4A && b[start + 3] === 0x46 &&
            b[start + 4] === 0x49 && b[start + 5] === 0x46 && b[start + 6] === 0x00;
    }

    /**
     * Strip a JPEG down to image data. Walks every segment and every scan:
     * APP1-APP15 and COM are dropped (APP14 "Adobe" colour flag kept), APP0 is
     * reduced to a bare 16-byte JFIF header with no thumbnail (JFXX dropped),
     * entropy-coded data is copied verbatim, and everything after the final EOI
     * (MPF images, vendor trailers, appended XMP) is discarded. Throws on
     * malformed input, including a missing EOI.
     */
    function stripJpeg(input) {
        var b = toU8(input);
        if (b.length < 4 || b[0] !== 0xFF || b[1] !== 0xD8) throw new Error('Not a JPEG (missing SOI)');

        var parts = [b.subarray(0, 2)];
        var total = 2;
        var pos = 2;

        function push(arr) { parts.push(arr); total += arr.length; }

        while (pos < b.length) {
            if (b[pos] !== 0xFF) throw new Error('Malformed JPEG: expected marker at offset ' + pos);
            var markerPos = pos;
            while (pos < b.length && b[pos] === 0xFF) pos++; // fill bytes
            if (pos >= b.length) throw new Error('Malformed JPEG: truncated marker');
            var marker = b[pos++];
            if (marker === 0x00) throw new Error('Malformed JPEG: invalid marker 0xFF00');

            if (marker === 0xD9) { // EOI: done; drop whatever follows
                push(new Uint8Array([0xFF, 0xD9]));
                return concat(parts, total);
            }
            // Standalone markers (no length): TEM, RSTn, SOI
            if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD8)) {
                push(new Uint8Array([0xFF, marker]));
                continue;
            }

            if (pos + 2 > b.length) throw new Error('Malformed JPEG: truncated segment length');
            var len = (b[pos] << 8) | b[pos + 1];
            if (len < 2 || pos + len > b.length) throw new Error('Malformed JPEG: bad segment length at offset ' + pos);
            var segEnd = pos + len;

            if (marker === 0xE0) {
                if (isJfifApp0(b, pos, segEnd)) {
                    var hdr = new Uint8Array(18);
                    hdr[0] = 0xFF; hdr[1] = 0xE0; hdr[2] = 0x00; hdr[3] = 0x10;
                    hdr.set(b.subarray(pos + 2, pos + 14), 4); // "JFIF\0", version, units, densities
                    hdr[16] = 0; hdr[17] = 0;                   // no thumbnail
                    push(hdr);
                } // JFXX and other APP0 variants are dropped
            } else {
                var drop = (marker >= 0xE1 && marker <= 0xEF) || marker === 0xFE;
                if (marker === 0xEE && isAdobeApp14(b, pos, segEnd)) drop = false;
                if (!drop) push(b.subarray(markerPos, segEnd));
            }
            pos = segEnd;

            if (marker === 0xDA) {
                // Entropy-coded data: copy until the next real marker
                // (FF followed by something other than 00, D0-D7 or FF fill).
                var scanStart = pos;
                while (pos < b.length) {
                    if (b[pos] !== 0xFF) { pos++; continue; }
                    var n = pos + 1 < b.length ? b[pos + 1] : -1;
                    if (n === -1) throw new Error('Malformed JPEG: truncated scan data');
                    if (n === 0x00 || (n >= 0xD0 && n <= 0xD7)) { pos += 2; continue; }
                    if (n === 0xFF) { pos++; continue; }
                    break;
                }
                if (pos >= b.length) throw new Error('Malformed JPEG: missing EOI');
                push(b.subarray(scanStart, pos));
            }
        }
        throw new Error('Malformed JPEG: missing EOI');
    }

    /**
     * Rebuild a PNG from an allowlist of chunk types. Kept chunks are copied
     * verbatim (CRCs untouched); data after IEND is dropped. Throws on
     * malformed input, including a missing IEND.
     */
    function stripPng(input) {
        var b = toU8(input);
        if (detectType(b) !== 'png') throw new Error('Not a PNG (bad signature)');

        var parts = [b.subarray(0, 8)];
        var total = 8;
        var pos = 8;

        while (pos < b.length) {
            if (pos + 12 > b.length) throw new Error('Malformed PNG: truncated chunk header');
            var len = ((b[pos] << 24) | (b[pos + 1] << 16) | (b[pos + 2] << 8) | b[pos + 3]) >>> 0;
            var type = String.fromCharCode(b[pos + 4], b[pos + 5], b[pos + 6], b[pos + 7]);
            if (!/^[A-Za-z]{4}$/.test(type)) throw new Error('Malformed PNG: bad chunk type at offset ' + pos);
            var end = pos + 12 + len; // length + type + data + CRC
            if (end > b.length) throw new Error('Malformed PNG: chunk "' + type + '" overruns file');

            if (PNG_KEEP[type]) {
                parts.push(b.subarray(pos, end));
                total += end - pos;
            }
            pos = end;
            if (type === 'IEND') return concat(parts, total);
        }
        throw new Error('Malformed PNG: missing IEND');
    }

    // Read an EXIF Orientation (1-8) from a TIFF block; null if absent/invalid. Never throws.
    function orientationFromTiff(b, t, end) {
        if (end - t < 8) return null;
        var le = b[t] === 0x49 && b[t + 1] === 0x49;
        if (!le && !(b[t] === 0x4D && b[t + 1] === 0x4D)) return null;
        function u16(o) { return o + 2 > end ? null : (le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1]); }
        function u32(o) { return o + 4 > end ? null : (le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0
            : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0); }
        var ifd = u32(t + 4);
        if (ifd === null || ifd < 8) return null;
        var p = t + ifd;
        var count = u16(p);
        if (count === null) return null;
        for (var i = 0; i < count; i++) {
            var e = p + 2 + i * 12;
            if (e + 12 > end) return null;
            if (u16(e) === 0x0112) {
                var v = u16(e + 8);
                return v >= 1 && v <= 8 ? v : null;
            }
        }
        return null;
    }

    /** EXIF orientation (1-8) of a JPEG/PNG, or null. Never throws. */
    function readOrientation(input) {
        try {
            var b = toU8(input);
            var type = detectType(b);
            if (type === 'jpeg') {
                var pos = 2;
                while (pos + 4 <= b.length && b[pos] === 0xFF) {
                    var m = b[pos + 1];
                    if (m === 0xFF) { pos++; continue; }
                    if (m === 0xDA || m === 0xD9) return null;
                    var len = (b[pos + 2] << 8) | b[pos + 3];
                    if (len < 2 || pos + 2 + len > b.length) return null;
                    if (m === 0xE1 && len >= 16 && b[pos + 4] === 0x45 && b[pos + 5] === 0x78 &&
                        b[pos + 6] === 0x69 && b[pos + 7] === 0x66 && b[pos + 8] === 0 && b[pos + 9] === 0) {
                        return orientationFromTiff(b, pos + 10, pos + 2 + len);
                    }
                    pos += 2 + len;
                }
            } else if (type === 'png') {
                var q = 8;
                while (q + 12 <= b.length) {
                    var l = ((b[q] << 24) | (b[q + 1] << 16) | (b[q + 2] << 8) | b[q + 3]) >>> 0;
                    var t = String.fromCharCode(b[q + 4], b[q + 5], b[q + 6], b[q + 7]);
                    if (t === 'eXIf') return orientationFromTiff(b, q + 8, Math.min(q + 8 + l, b.length));
                    if (t === 'IDAT' || t === 'IEND') return null;
                    q += 12 + l;
                }
            }
        } catch (e) { /* fall through */ }
        return null;
    }

    /**
     * Strip metadata from file bytes, detecting the type by magic bytes.
     * Returns { data: ArrayBuffer, type: 'jpeg'|'png'|null, supported: bool,
     * removedBytes: number, orientation: 1-8|null } (orientation is the value
     * that was present BEFORE stripping). Unsupported types are returned
     * unchanged with supported:false. Throws if a JPEG/PNG is malformed.
     */
    function stripMetadata(input) {
        var b = toU8(input);
        var type = detectType(b);
        if (!type) {
            var copy = (input instanceof ArrayBuffer) ? input : b.slice().buffer;
            return { data: copy, type: null, supported: false, removedBytes: 0, orientation: null };
        }
        var orientation = readOrientation(b);
        var out = type === 'jpeg' ? stripJpeg(b) : stripPng(b);
        var buf = out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
        return { data: buf, type: type, supported: true, removedBytes: b.length - out.length, orientation: orientation };
    }

    var api = {
        detectType: detectType,
        stripJpeg: stripJpeg,
        stripPng: stripPng,
        readOrientation: readOrientation,
        stripMetadata: stripMetadata
    };

    root.SafeShareMetadata = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);

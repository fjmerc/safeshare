/**
 * SafeShare client-side metadata stripping (dependency-free).
 *
 * Used before end-to-end encryption: the server only ever sees ciphertext, so
 * it cannot remove metadata itself. Supports JPEG, PNG and Office Open XML
 * (docx/xlsx/pptx and their macro-enabled variants); other types pass through
 * unchanged (callers should warn the user). Office files need the browser's
 * built-in DecompressionStream/CompressionStream ("deflate-raw").
 *
 * Exported on window.SafeShareMetadata (and module.exports under Node for
 * tests). stripMetadata is async; the JPEG/PNG helpers are synchronous.
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

    // ---- Office Open XML (zip) -------------------------------------------

    // Same limits as the server-side stripper (internal/privacy): files above
    // MAX_CONTAINER_BYTES are not stripped, and inflating more than
    // MAX_INFLATED_BYTES in total is treated as a decompression bomb.
    var MAX_CONTAINER_BYTES = 100 * 1024 * 1024;
    var MAX_INFLATED_BYTES = 500 * 1024 * 1024;

    /**
     * Errors from the Office stripper carry a code so callers can explain them:
     * UNSUPPORTED_BROWSER (no deflate-raw streams), TOO_LARGE, ENCRYPTED,
     * MALFORMED.
     */
    function stripError(code, message) {
        var err = new Error(message);
        err.code = code;
        return err;
    }

    var CRC_TABLE = (function () {
        var t = new Uint32Array(256);
        for (var n = 0; n < 256; n++) {
            var c = n;
            for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
            t[n] = c >>> 0;
        }
        return t;
    })();

    function crc32(b) {
        var c = 0xFFFFFFFF;
        for (var i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xFF] ^ (c >>> 8);
        return (c ^ 0xFFFFFFFF) >>> 0;
    }

    function u16le(b, o) { return b[o] | (b[o + 1] << 8); }
    function u32le(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

    /** True if this browser can inflate and deflate raw streams (needed for Office files). */
    function compressionSupported() {
        try {
            if (typeof DecompressionStream !== 'function' || typeof CompressionStream !== 'function') return false;
            new DecompressionStream('deflate-raw');
            new CompressionStream('deflate-raw');
            return true;
        } catch (e) {
            return false;
        }
    }

    // Run bytes through a (De)CompressionStream, failing once the output
    // passes limit bytes.
    async function pipeBytes(transform, input, limit) {
        var reader = new Blob([input]).stream().pipeThrough(transform).getReader();
        var parts = [];
        var total = 0;
        for (;;) {
            var r = await reader.read();
            if (r.done) break;
            total += r.value.length;
            if (total > limit) {
                reader.cancel().catch(function () {});
                throw stripError('TOO_LARGE', 'Office file expands to more than the stripping limit');
            }
            parts.push(r.value);
        }
        return concat(parts, total);
    }

    var ZIP_SIG = [0x50, 0x4B, 0x03, 0x04];

    function isZip(b) {
        for (var i = 0; i < 4; i++) if (b[i] !== ZIP_SIG[i]) return false;
        return true;
    }

    /**
     * Read a zip's central directory. Only plain single-disk zips are
     * accepted: zip64, encrypted entries and spanned archives throw.
     */
    function readZip(b) {
        var min = Math.max(0, b.length - 65557); // EOCD is 22 bytes plus at most a 64 KB comment
        var eocd = -1;
        for (var p = b.length - 22; p >= min; p--) {
            // The real record's comment runs exactly to the end of the file,
            // which skips a fake signature inside the comment itself.
            if (b[p] === 0x50 && b[p + 1] === 0x4B && b[p + 2] === 0x05 && b[p + 3] === 0x06 &&
                p + 22 + u16le(b, p + 20) === b.length) { eocd = p; break; }
        }
        if (eocd < 0) throw stripError('MALFORMED', 'Not a zip file (no end of central directory)');
        if (eocd >= 20 && u32le(b, eocd - 20) === 0x07064B50) throw stripError('MALFORMED', 'Zip64 files are not supported');
        var disk = u16le(b, eocd + 4), cdDisk = u16le(b, eocd + 6);
        var countDisk = u16le(b, eocd + 8), count = u16le(b, eocd + 10);
        var cdSize = u32le(b, eocd + 12), cdOffset = u32le(b, eocd + 16);
        if (disk !== 0 || cdDisk !== 0 || countDisk !== count) throw stripError('MALFORMED', 'Multi-disk zip files are not supported');
        if (count === 0xFFFF || cdOffset === 0xFFFFFFFF || cdSize === 0xFFFFFFFF) throw stripError('MALFORMED', 'Zip64 files are not supported');
        if (cdOffset + cdSize > eocd) throw stripError('MALFORMED', 'Zip central directory out of range');

        var names = new TextDecoder('utf-8');
        var entries = [];
        var pos = cdOffset;
        for (var i = 0; i < count; i++) {
            if (pos + 46 > eocd || u32le(b, pos) !== 0x02014B50) throw stripError('MALFORMED', 'Bad zip central directory entry');
            var flags = u16le(b, pos + 8);
            var method = u16le(b, pos + 10);
            var crc = u32le(b, pos + 16);
            var compSize = u32le(b, pos + 20), size = u32le(b, pos + 24);
            var nameLen = u16le(b, pos + 28), extraLen = u16le(b, pos + 30), commentLen = u16le(b, pos + 32);
            var localOffset = u32le(b, pos + 42);
            if (flags & 0x41) throw stripError('ENCRYPTED', 'Encrypted zip entries are not supported');
            if (compSize === 0xFFFFFFFF || size === 0xFFFFFFFF || localOffset === 0xFFFFFFFF) throw stripError('MALFORMED', 'Zip64 files are not supported');
            if (pos + 46 + nameLen > eocd) throw stripError('MALFORMED', 'Bad zip entry name');
            var nameBytes = b.subarray(pos + 46, pos + 46 + nameLen);

            if (localOffset + 30 > b.length || u32le(b, localOffset) !== 0x04034B50) throw stripError('MALFORMED', 'Bad zip local header');
            var dataStart = localOffset + 30 + u16le(b, localOffset + 26) + u16le(b, localOffset + 28);
            if (dataStart + compSize > b.length) throw stripError('MALFORMED', 'Zip entry data out of range');

            entries.push({
                name: names.decode(nameBytes),
                nameBytes: nameBytes,
                flags: flags,
                method: method,
                crc: crc,
                size: size,
                data: b.subarray(dataStart, dataStart + compSize)
            });
            pos += 46 + nameLen + extraLen + commentLen;
        }
        return entries;
    }

    var CONTENT_TYPES = [];
    for (var ci = 0; ci < '[content_types].xml'.length; ci++) CONTENT_TYPES.push('[content_types].xml'.charCodeAt(ci));

    function lowerByte(c) { return c >= 0x41 && c <= 0x5A ? c + 32 : c; }

    // True if the bytes contain the name [Content_Types].xml (any case)
    // anywhere: it is in every Office file's directory, whatever the entry
    // order or zip variant.
    function mentionsContentTypes(b) {
        var n = CONTENT_TYPES.length;
        for (var i = b.indexOf(0x5B); i !== -1 && i + n <= b.length; i = b.indexOf(0x5B, i + 1)) {
            var j = 1;
            while (j < n && lowerByte(b[i + j]) === CONTENT_TYPES[j]) j++;
            if (j === n) return true;
        }
        return false;
    }

    // Part names are compared lower-cased with forward slashes and no leading
    // slash: OPC part names are case-insensitive.
    function partName(name) {
        return name.replace(/\\/g, '/').replace(/^\/+/, '').toLowerCase();
    }

    // A Word, Excel or PowerPoint package. Other OPC packages (Visio, XPS,
    // 3MF, ...) aren't handled and are reported as unsupported.
    function isOoxml(entries) {
        var types = false, main = false;
        for (var i = 0; i < entries.length; i++) {
            var n = partName(entries[i].name);
            if (n === '[content_types].xml') types = true;
            if (/^(?:word|xl|ppt)\//.test(n)) main = true;
        }
        return types && main;
    }

    var XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n';
    var VT_NS = ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"';
    // Empty but valid replacements for parts that are all metadata.
    var TEMPLATES = {
        core: XML_DECL + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"' +
            ' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"' +
            ' xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></cp:coreProperties>',
        app: XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"' + VT_NS + '></Properties>',
        custom: XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"' + VT_NS + '></Properties>',
        // customXml data stores (SharePoint columns, cover-page fields, ...)
        customItem: XML_DECL + '<root/>',
        // Microsoft 365 sensitivity labels name the organisation (siteId)
        labels: XML_DECL + '<clbl:labelList xmlns:clbl="http://schemas.microsoft.com/office/2020/mipLabelMetadata"></clbl:labelList>'
    };
    var DEFAULT_PROPERTY_PARTS = { 'docprops/core.xml': 'core', 'docprops/app.xml': 'app', 'docprops/custom.xml': 'custom' };
    var PROPERTY_REL_TYPES = [[/\/metadata\/core-properties$/, 'core'], [/\/extended-?properties$/i, 'app'], [/\/custom-?properties$/i, 'custom']];

    var CUSTOM_XML_ITEM = /^customxml\/item\d+\.xml$/;
    var XML_PART = /\.(?:xml|rels|vml)$/;
    var EMBEDDED_PART = /^(?:word|ppt|xl)\/embeddings\//;
    var PRINTER_SETTINGS = /^(?:word|ppt|xl)\/printersettings\/.+\.bin$/;
    // Binary parts that carry no metadata and are copied unchanged. Everything
    // else that isn't XML or a JPEG/PNG (video, audio, SVG, GIF, TIFF, VBA,
    // ActiveX, OLE objects, data models, ...) is reported as not cleaned.
    var SAFE_BINARY = /\.(?:emf|wmf|bmp|odttf|fntdata|ttf|otf)$/;
    // How deep embedded Office files (e.g. a chart's workbook) are cleaned.
    var MAX_EMBED_DEPTH = 2;
    var DROP = {};

    var EPOCH = '1970-01-01T00:00:00Z';
    var P = '(?:[A-Za-z_][\\w.-]*:)?'; // optional namespace prefix (an NCName)
    var VAL = '\\s*=\\s*(?:"[^"]*"|\'[^\']*\')';
    var FULL = '\\s*=\\s*(?:"[^"]+"|\'[^\']+\')'; // a non-empty value
    var WHO = '(?:author|initials|userId|providerId|userName|refreshedBy)';
    var DATE_ATTR = '(?:date|dateUtc|dateTime|dt|dT|created|refreshedDateIso|timeString)';
    // Elements whose name attribute is a person
    var NAME_ATTR_TAGS = { cmAuthor: 1, author: 1, userInfo: 1, chgData: 1 };

    var RE_WHO = new RegExp('(\\s' + P + WHO + ')' + VAL, 'g');
    var RE_NAME = new RegExp('(\\s' + P + 'name)' + VAL, 'g');
    var RE_ED = new RegExp('(\\s' + P + 'ed)' + VAL, 'g'); // editing-permission editor
    var RE_DISPLAY_NAME = new RegExp('(\\s' + P + 'displayName)' + VAL, 'g'); // Excel persons (tables use it too)
    var RE_ID = new RegExp('(\\sid)' + VAL, 'g');
    var RE_DATE = new RegExp('(\\s' + P + DATE_ATTR + ')\\s*=\\s*(?:"\\d{4}-[^"]*"|\'\\d{4}-[^\']*\')', 'g');
    var RE_REFRESHED = new RegExp('(\\srefreshedDate)' + VAL, 'g');
    var RE_RSID = new RegExp('\\s[A-Za-z_][\\w.-]*:rsid[A-Za-z]*' + VAL, 'g');
    var RE_SECURITY = new RegExp('\\s' + P + 'securityDescriptor' + VAL, 'g');
    var RE_URL = new RegExp('(\\surl)' + VAL);
    // Excel data connections: the .odc/source file path, and the connection
    // string (which can hold a user name or password).
    var RE_SOURCE_FILE = new RegExp('(\\s(?:odcFile|sourceFile))' + VAL, 'g');
    var RE_CONNECTION = new RegExp('(\\sconnection)' + VAL, 'g');
    var RE_TARGET = new RegExp('(\\sTarget)' + VAL);
    var RE_EXTERNAL = /\sTargetMode\s*=\s*["']External["']/;
    var RE_HYPERLINK_TYPE = /\sType\s*=\s*["'][^"']*\/hyperlink["']/;
    // Online video and audio (e.g. a YouTube video on a slide). Linked
    // pictures aren't included: they usually live in the author's own storage.
    var RE_WEB_MEDIA = /\sType\s*=\s*["'][^"']*\/(?:video|audio|media)["']/;
    var RE_WEB_TARGET = /\sTarget\s*=\s*["']\s*https?:/i;
    // Personal cloud storage names its owner (…-my.sharepoint.com/personal/<user>)
    var RE_PERSONAL_TARGET = /\sTarget\s*=\s*["'][^"']*(?:-my\.sharepoint\.com|onedrive\.live\.com|1drv\.ms|\/personal\/)/i;
    var RE_TEMPLATE_TYPE = /\sType\s*=\s*["'][^"']*\/attachedTemplate["']/;
    // Local and relative paths (file:, C:\, \\server, /Users/..., ../..)
    var RE_LOCAL_TARGET = /\sTarget\s*=\s*["']\s*(?:file:|[A-Za-z]:[\\/]|[\\/]|\.\.?[\\/])/i;
    // Paths that are never package parts, whatever the target mode
    var RE_ABSOLUTE_TARGET = /\sTarget\s*=\s*["']\s*(?:file:|[A-Za-z]:[\\/]|\\\\)/i;

    function tagName(tag) {
        var m = /^<\/?(?:([A-Za-z_][\w.-]*):)?([A-Za-z_][\w.-]*)/.exec(tag);
        return m ? { prefix: m[1] || '', local: m[2] } : null;
    }

    // Elements removed whole (with their content).
    function isRemovedElement(n) {
        return n.local === 'rsids' || n.local === 'docVars' || n.local === 'mailMerge' ||
            (n.local === 'docId' && /^w\d*$/.test(n.prefix)) ||
            (n.local === 'revisionPtr' && /^xr\d*$/.test(n.prefix));
    }

    function scrubTag(tag, n) {
        tag = tag
            .replace(RE_WHO, '$1=""')
            .replace(RE_DATE, '$1="' + EPOCH + '"')
            .replace(RE_REFRESHED, '$1="0"')
            .replace(RE_RSID, '')
            .replace(RE_SECURITY, '')
            .replace(RE_SOURCE_FILE, '$1=""');
        if (NAME_ATTR_TAGS[n.local]) tag = tag.replace(RE_NAME, '$1=""');
        if (n.local === 'permStart') tag = tag.replace(RE_ED, '$1=""');
        if (n.local === 'person') tag = tag.replace(RE_DISPLAY_NAME, '$1=""');
        if (n.local === 'client') tag = tag.replace(RE_ID, '$1=""'); // PowerPoint revisionInfo
        if (n.local === 'absPath') tag = tag.replace(RE_URL, '$1=""');
        if (n.local === 'dbPr') tag = tag.replace(RE_CONNECTION, '$1=""');
        if (n.local === 'Relationship') {
            // External targets other than web hyperlinks and online media
            // point at the author's files (templates, linked workbooks and
            // objects, mail merge sources); hyperlinks lose only local and
            // relative paths.
            var external = RE_EXTERNAL.test(tag);
            var web = RE_HYPERLINK_TYPE.test(tag) ||
                (RE_WEB_MEDIA.test(tag) && RE_WEB_TARGET.test(tag) && !RE_PERSONAL_TARGET.test(tag));
            if (RE_TEMPLATE_TYPE.test(tag) || (external && !web) || (external && RE_LOCAL_TARGET.test(tag)) ||
                RE_ABSOLUTE_TARGET.test(tag)) {
                tag = tag.replace(RE_TARGET, '$1=""');
            }
        }
        return tag;
    }

    function malformed(msg) { return stripError('MALFORMED', msg); }

    /**
     * Walk XML markup in one linear pass, calling visit(kind, token) with
     * kind 'text', 'tag' (start, end or empty-element tag) or 'other'
     * (comment, CDATA, processing instruction, DOCTYPE). Throws on malformed
     * markup: unterminated constructs, '<' inside a tag, unquoted attribute
     * values, and a DOCTYPE unless allowDoctype (never one with an internal
     * subset, which could declare entities).
     */
    function walkXml(xml, visit, allowDoctype) {
        var n = xml.length;
        var i = 0;
        while (i < n) {
            var lt = xml.indexOf('<', i);
            if (lt === -1) {
                visit('text', xml.slice(i));
                return;
            }
            if (lt > i) visit('text', xml.slice(i, lt));
            var end;
            if (xml.startsWith('<!--', lt)) {
                end = xml.indexOf('-->', lt + 4);
                if (end < 0) throw malformed('Unterminated XML comment');
                end += 3;
                visit('other', xml.slice(lt, end));
            } else if (xml.startsWith('<![CDATA[', lt)) {
                end = xml.indexOf(']]>', lt + 9);
                if (end < 0) throw malformed('Unterminated CDATA section');
                end += 3;
                visit('other', xml.slice(lt, end));
            } else if (xml.startsWith('<?', lt)) {
                end = xml.indexOf('?>', lt + 2);
                if (end < 0) throw malformed('Unterminated processing instruction');
                end += 2;
                visit('other', xml.slice(lt, end));
            } else if (xml[lt + 1] === '!') {
                end = xml.indexOf('>', lt);
                if (!allowDoctype || !xml.startsWith('<!DOCTYPE', lt) || end < 0 || xml.slice(lt, end).indexOf('[') !== -1) {
                    throw malformed('Unexpected markup declaration'); // Office never writes a DOCTYPE
                }
                end += 1;
                visit('other', xml.slice(lt, end));
            } else {
                var j = lt + 1, quote = 0;
                for (; j < n; j++) {
                    var c = xml.charCodeAt(j);
                    if (quote) {
                        if (c === quote) quote = 0;
                    } else if (c === 34 || c === 39) {
                        quote = c;
                    } else if (c === 62) {
                        break;
                    } else if (c === 60) {
                        throw malformed('Unexpected < inside a tag');
                    } else if (c === 61) {
                        // '=' must be followed by a quoted value
                        var k = j + 1;
                        while (k < n && /\s/.test(xml[k])) k++;
                        if (xml[k] !== '"' && xml[k] !== "'") throw malformed('Unquoted attribute value');
                    }
                }
                if (j >= n) throw malformed('Unterminated tag');
                end = j + 1;
                visit('tag', xml.slice(lt, end));
            }
            i = end;
        }
    }

    /**
     * Shared rewrite loop: each tag goes through onTag(token, name), which
     * returns the replacement token, and may drop an element whole
     * (dropElement) or keep it but drop its content (emptyElement).
     * Comments are dropped when dropComments is set.
     */
    function rewriteXml(xml, rules) {
        var out = [];
        var mode = null; // { remove: bool, name: qualified name, depth }
        walkXml(xml, function (kind, token) {
            if (kind !== 'tag') {
                if (!mode && !(rules.dropComments && token.startsWith('<!--'))) out.push(token);
                return;
            }
            var name = tagName(token);
            if (!name) throw malformed('Bad tag');
            var qname = (name.prefix ? name.prefix + ':' : '') + name.local;
            var closing = token[1] === '/';
            var selfClosing = !closing && token[token.length - 2] === '/';
            if (mode) {
                if (qname === mode.name && !selfClosing) mode.depth += closing ? -1 : 1;
                if (mode.depth === 0) {
                    if (!mode.remove) out.push(token); // keep the emptied element's end tag
                    mode = null;
                }
            } else if (closing) {
                out.push(token);
            } else if (rules.dropElement(name)) {
                if (!selfClosing) mode = { remove: true, name: qname, depth: 1 };
            } else {
                out.push(rules.onTag(token, name));
                if (rules.emptyElement(name) && !selfClosing) mode = { remove: false, name: qname, depth: 1 };
            }
        }, rules.allowDoctype);
        if (mode) throw malformed('Unclosed <' + mode.name + '> element');
        return out.join('');
    }

    var OFFICE_RULES = {
        onTag: scrubTag,
        dropElement: isRemovedElement,
        emptyElement: function (n) { return n.local === 'author'; }
    };

    /**
     * Remove people, dates, edit-session identifiers and local file paths
     * from an Office XML part: attributes are edited only inside tags (so
     * document text is never touched), some elements are removed whole, and
     * the content of author elements is dropped. Malformed markup throws.
     */
    function scrubOfficeXml(xml) {
        return rewriteXml(xml, OFFICE_RULES);
    }

    var RE_SVG_EDITOR_ATTR = new RegExp('\\s(?:sodipodi|inkscape):[\\w.-]+' + VAL, 'g');
    // Links that aren't fragments or web addresses (file:///home/<name>/...)
    var RE_SVG_LOCAL_HREF = /(\s(?:xlink:)?href)\s*=\s*(?:"(?!\s*(?:#|https?:))[^"]*"|'(?!\s*(?:#|https?:))[^']*')/g;
    var SVG_RULES = {
        onTag: function (tag) { return tag.replace(RE_SVG_EDITOR_ATTR, '').replace(RE_SVG_LOCAL_HREF, '$1=""'); },
        // <metadata> and RDF/XMP blocks (author, licence, ...), Illustrator's
        // private editing data and Inkscape/Sodipodi elements
        dropElement: function (n) {
            return n.local === 'metadata' || n.local === 'RDF' || n.local === 'xmpmeta' || n.local === 'pgf' ||
                n.prefix === 'sodipodi' || n.prefix === 'inkscape';
        },
        emptyElement: function () { return false; },
        dropComments: true,
        allowDoctype: true
    };

    /**
     * Clean an SVG image: drop <metadata>, RDF/XMP, comments, Illustrator and
     * Inkscape/Sodipodi data, and links to local files. Returns null when
     * something can't be cleaned here: embedded data (data: URIs, such as a
     * raster image with its own EXIF), file: URLs or CSS imports.
     */
    function scrubSvg(svg) {
        if (/data(?::|&#)|@import/i.test(svg)) return null;
        var out = rewriteXml(svg, SVG_RULES);
        if (/file:/i.test(out)) return null;
        if (/<(?:[\w.-]+:)?metadata\b|\s(?:sodipodi|inkscape):[\w.-]+\s*=|<!--/.test(out)) throw malformed('Could not clean SVG image');
        return out;
    }

    // Word fields that link to files keep the path in the (hidden) field
    // code, also inside tracked deletions: LINK, INCLUDE(PICTURE|TEXT), DDE,
    // RD, DATABASE and IMPORT fields, and any field quoting a local, network
    // or relative path.
    var FIELD_KEYWORD = '\\s*(?:LINK|INCLUDEPICTURE|INCLUDETEXT|INCLUDE|DDE|DDEAUTO|RD|DATABASE|IMPORT)\\b';
    var FIELD_PATH = '(?:[A-Za-z]:\\\\|\\\\\\\\|file:|(?:"|&quot;)\\s*(?:/|\\.\\.?[\\\\/]))';
    var INSTR_TEXT = '<' + P + '(?:del)?instrText\\b[^>]*>';
    var RE_LINKED_FIELD = new RegExp(INSTR_TEXT + FIELD_KEYWORD + '|' + INSTR_TEXT + '[^<]*' + FIELD_PATH +
        '|\\s' + P + 'instr\\s*=\\s*(?:"' + FIELD_KEYWORD + '|\'' + FIELD_KEYWORD + '|"[^"]*' + FIELD_PATH + '|\'[^\']*' + FIELD_PATH + ')', 'i');

    // Checks run over the whole scrubbed part, text included, so anything the
    // scrubber missed fails closed. (A name typed into body text that looks
    // like one of these attributes also fails closed.)
    var LEFTOVERS = [
        new RegExp('\\s' + P + WHO + FULL),
        new RegExp('<' + P + '(?:cmAuthor|author|userInfo|chgData)\\b[^>]*\\s' + P + 'name' + FULL),
        new RegExp('<' + P + 'permStart\\b[^>]*\\s' + P + 'ed' + FULL),
        new RegExp('\\s[A-Za-z_][\\w.-]*:rsid[A-Za-z]*\\s*='),
        new RegExp('\\s' + P + 'securityDescriptor\\s*='),
        // a non-empty author element (an empty-element tag doesn't count)
        new RegExp('<' + P + 'author(?:\\s[^>]*[^/>]|\\s)?>\\s*(?:[^<\\s]|<!\\[CDATA)'),
        new RegExp('<' + P + 'person\\b[^>]*\\s' + P + 'displayName' + FULL),
        new RegExp('<' + P + '(?:rsids|docVars|mailMerge)\\b'),
        /<w\d*:docId\b|<xr\d*:revisionPtr\b/,
        new RegExp('<' + P + 'absPath\\b[^>]*\\surl' + FULL),
        new RegExp('\\s(?:odcFile|sourceFile)' + FULL),
        new RegExp('<' + P + 'dbPr\\b[^>]*\\sconnection' + FULL)
    ];
    var RE_DATE_VALUE = new RegExp('\\s' + P + DATE_ATTR + '\\s*=\\s*["\'](\\d{4}-[^"\']*)', 'g');

    function officeLeftover(xml) {
        for (var i = 0; i < LEFTOVERS.length; i++) if (LEFTOVERS[i].test(xml)) return true;
        var m;
        RE_DATE_VALUE.lastIndex = 0;
        while ((m = RE_DATE_VALUE.exec(xml)) !== null) if (m[1] !== EPOCH) return true;
        return false;
    }

    function sameBytes(a, b) {
        if (a.length !== b.length) return false;
        for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        return true;
    }

    async function readEntry(entry, budget) {
        var out;
        if (entry.method === 0) {
            out = entry.data;
        } else if (entry.method === 8) {
            if (entry.size > budget.left) throw stripError('TOO_LARGE', 'Office file expands to more than the stripping limit');
            out = await pipeBytes(new DecompressionStream('deflate-raw'), entry.data, budget.left);
            budget.left -= out.length;
        } else {
            throw stripError('MALFORMED', 'Unsupported zip compression method ' + entry.method);
        }
        if (out.length !== entry.size || crc32(out) !== entry.crc) throw stripError('MALFORMED', 'Zip entry ' + entry.name + ' is corrupt');
        return out;
    }

    function decodeUtf8(bytes, name) {
        try {
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (e) {
            throw stripError('MALFORMED', 'Office part ' + name + ' is not UTF-8');
        }
    }

    // Names of the core, extended and custom property parts: the usual
    // docProps/ paths plus wherever _rels/.rels points.
    async function propertyParts(entries, budget) {
        var parts = Object.assign({}, DEFAULT_PROPERTY_PARTS);
        for (var i = 0; i < entries.length; i++) {
            if (partName(entries[i].name) !== '_rels/.rels') continue;
            var rels = decodeUtf8(await readEntry(entries[i], budget), entries[i].name);
            var tags = [];
            walkXml(rels, function (kind, token) {
                if (kind === 'tag' && /^<Relationship\b/.test(token)) tags.push(token);
            });
            for (var t = 0; t < tags.length; t++) {
                var type = /\sType\s*=\s*["']([^"']*)/.exec(tags[t]);
                var target = /\sTarget\s*=\s*["']([^"']*)/.exec(tags[t]);
                if (!type || !target) continue;
                for (var k = 0; k < PROPERTY_REL_TYPES.length; k++) {
                    if (PROPERTY_REL_TYPES[k][0].test(type[1])) parts[partName(target[1])] = PROPERTY_REL_TYPES[k][1];
                }
            }
        }
        return parts;
    }

    function cleanImage(data, type) {
        var clean = type === 'jpeg' ? stripJpeg(data) : stripPng(data);
        return sameBytes(clean, data) ? null : clean;
    }

    // New bytes for an entry, null to copy it unchanged, or DROP to leave it
    // out. Parts that may hold metadata but can't be cleaned are copied and
    // listed in ctx.incomplete.
    async function processEntry(entry, ctx, props) {
        var name = entry.name;
        var lname = partName(name);
        if (lname === '' || lname[lname.length - 1] === '/' || entry.size === 0) return null; // directories, empty parts
        if (/^\[trash\]\//.test(lname)) return DROP; // stale data from earlier saves, unreferenced
        if (props[lname]) return new TextEncoder().encode(TEMPLATES[props[lname]]);
        if (CUSTOM_XML_ITEM.test(lname)) return new TextEncoder().encode(TEMPLATES.customItem);
        if (lname === 'docmetadata/labelinfo.xml') return new TextEncoder().encode(TEMPLATES.labels);
        if (/^_xmlsignatures\//.test(lname) || /^docprops\/.+\.xml$/.test(lname) || /(?:^|\/)webextensions\//.test(lname)) {
            // Digital signatures embed the signer's certificate; unknown
            // property parts are all metadata; add-in (web extension) state
            // can hold anything, including e-mail addresses and tokens.
            ctx.incomplete.push(name);
            return null;
        }

        if (XML_PART.test(lname)) {
            var xml = decodeUtf8(await readEntry(entry, ctx.budget), name);
            var scrubbed = scrubOfficeXml(xml);
            if (officeLeftover(scrubbed)) throw stripError('MALFORMED', 'Could not clean Office part ' + name);
            if (RE_LINKED_FIELD.test(scrubbed)) ctx.incomplete.push(name + ' (a field linking to a file)');
            return scrubbed === xml ? null : new TextEncoder().encode(scrubbed);
        }
        if (/\.svg$/.test(lname) && !EMBEDDED_PART.test(lname)) {
            var svg = decodeUtf8(await readEntry(entry, ctx.budget), name);
            var cleanSvg = scrubSvg(svg);
            if (cleanSvg === null) {
                ctx.incomplete.push(name);
                return null;
            }
            return cleanSvg === svg ? null : new TextEncoder().encode(cleanSvg);
        }
        if (PRINTER_SETTINGS.test(lname)) {
            // A Windows DEVMODE starts with the printer name (32 UTF-16
            // chars); the driver's private data (which can name users or
            // accounts) follows the dmSize-byte public part.
            var dev = await readEntry(entry, ctx.budget);
            if (dev.length < 64) return null;
            var copy = dev.slice();
            copy.fill(0, 0, 64);
            if (copy.length >= 72) {
                var pub = u16le(copy, 68);
                if (pub >= 72 && pub < copy.length) copy.fill(0, pub);
            }
            return copy;
        }
        if (SAFE_BINARY.test(lname) && !EMBEDDED_PART.test(lname)) return null;

        var data = await readEntry(entry, ctx.budget);
        var type = detectType(data);
        if (type) return cleanImage(data, type);
        if (EMBEDDED_PART.test(lname) && isZip(data) && ctx.depth < MAX_EMBED_DEPTH) {
            // An embedded Office file (a chart's workbook, a pasted document)
            // has its own metadata: clean it the same way.
            var inner = null;
            try { inner = readZip(data); } catch (e) { inner = null; }
            if (inner && isOoxml(inner)) {
                var child = { budget: ctx.budget, depth: ctx.depth + 1, incomplete: [] };
                var cleaned = await stripOoxml(inner, child);
                for (var i = 0; i < child.incomplete.length; i++) ctx.incomplete.push(name + '/' + child.incomplete[i]);
                return cleaned;
            }
        }
        ctx.incomplete.push(name);
        return null;
    }

    function writeU16(out, o, v) { out[o] = v & 0xFF; out[o + 1] = (v >>> 8) & 0xFF; }
    function writeU32(out, o, v) { writeU16(out, o, v & 0xFFFF); writeU16(out, o + 2, v >>> 16); }

    /**
     * Rebuild an Office zip: metadata parts replaced or scrubbed, every entry's
     * timestamp, extra fields, comment and file attributes cleared. Entries
     * that don't change are copied without recompressing.
     */
    async function stripOoxml(entries, ctx) {
        if (!compressionSupported()) throw stripError('UNSUPPORTED_BROWSER', 'This browser cannot remove metadata from Office files');
        var props = await propertyParts(entries, ctx.budget);
        var out = [];
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var plain = await processEntry(e, ctx, props);
            if (plain === DROP) continue;
            if (plain === null) {
                out.push({ e: e, method: e.method, crc: e.crc, size: e.size, data: e.data });
            } else {
                var packed = await pipeBytes(new CompressionStream('deflate-raw'), plain, MAX_INFLATED_BYTES);
                out.push({ e: e, method: 8, crc: crc32(plain), size: plain.length, data: packed });
            }
        }

        var total = 22;
        for (i = 0; i < out.length; i++) total += 30 + 46 + 2 * out[i].e.nameBytes.length + out[i].data.length;
        if (total > 0xFFFFFFFF || out.length >= 0xFFFF) throw stripError('TOO_LARGE', 'Office file too large to rebuild');

        var z = new Uint8Array(total);
        var pos = 0;
        var offsets = [];
        // DOS date 1980-01-01, time 00:00: no entry keeps its save time.
        var DOS_DATE = 0x21;
        for (i = 0; i < out.length; i++) {
            var o = out[i];
            var flags = o.e.flags & 0x0800; // keep only the UTF-8 name flag
            offsets.push(pos);
            writeU32(z, pos, 0x04034B50);
            writeU16(z, pos + 4, 20);
            writeU16(z, pos + 6, flags);
            writeU16(z, pos + 8, o.method);
            writeU16(z, pos + 10, 0);
            writeU16(z, pos + 12, DOS_DATE);
            writeU32(z, pos + 14, o.crc);
            writeU32(z, pos + 18, o.data.length);
            writeU32(z, pos + 22, o.size);
            writeU16(z, pos + 26, o.e.nameBytes.length);
            writeU16(z, pos + 28, 0);
            z.set(o.e.nameBytes, pos + 30);
            pos += 30 + o.e.nameBytes.length;
            z.set(o.data, pos);
            pos += o.data.length;
        }
        var cdStart = pos;
        for (i = 0; i < out.length; i++) {
            o = out[i];
            writeU32(z, pos, 0x02014B50);
            writeU16(z, pos + 4, 20); // made by: MS-DOS, spec 2.0 (hides the creating OS)
            writeU16(z, pos + 6, 20);
            writeU16(z, pos + 8, o.e.flags & 0x0800);
            writeU16(z, pos + 10, o.method);
            writeU16(z, pos + 12, 0);
            writeU16(z, pos + 14, DOS_DATE);
            writeU32(z, pos + 16, o.crc);
            writeU32(z, pos + 20, o.data.length);
            writeU32(z, pos + 24, o.size);
            writeU16(z, pos + 28, o.e.nameBytes.length);
            // extra, comment, disk, internal and external attributes all zero
            writeU32(z, pos + 42, offsets[i]);
            z.set(o.e.nameBytes, pos + 46);
            pos += 46 + o.e.nameBytes.length;
        }
        writeU32(z, pos, 0x06054B50);
        writeU16(z, pos + 8, out.length);
        writeU16(z, pos + 10, out.length);
        writeU32(z, pos + 12, pos - cdStart);
        writeU32(z, pos + 16, cdStart);
        pos += 22;
        return z.subarray(0, pos);
    }

    // ---- PDF ---------------------------------------------------------------

    // Metadata is overwritten in place with values of the same length, so no
    // object moves and the cross-reference data stays valid. A compressed
    // stream that has to change (an object stream holding the Info
    // dictionary, compressed XMP, a JPEG with EXIF) is rewritten in its own
    // space: the new data must fit, /Length is rewritten in the same width,
    // and the space left over becomes whitespace between objects.

    // A PDF header anywhere in the first megabyte (readers tolerate junk
    // before it), or a PDF trailer at the end.
    function isPdf(b) {
        var head = pdfLatin1(b.subarray(0, Math.min(b.length, 1024 * 1024)));
        var tail = pdfLatin1(b.subarray(Math.max(0, b.length - 2048)));
        return head.indexOf('%PDF-') !== -1 || (tail.indexOf('startxref') !== -1 && tail.indexOf('%%EOF') !== -1);
    }

    var PDF_WS = { 0: 1, 9: 1, 10: 1, 12: 1, 13: 1, 32: 1 };
    var PDF_DELIM = '()<>[]{}/%';
    var MAX_PDF_DEPTH = 64;
    // Comment annotations whose /T is the author (a form field's /T is its name)
    var MARKUP_ANNOTS = { Text: 1, FreeText: 1, Line: 1, Square: 1, Circle: 1, Polygon: 1, PolyLine: 1, Highlight: 1,
        Underline: 1, Squiggly: 1, StrikeOut: 1, Stamp: 1, Caret: 1, Ink: 1, FileAttachment: 1, Sound: 1, Redact: 1 };

    function pdfError(msg) { return stripError('MALFORMED', msg); }

    function skipPdfWs(S, i) {
        var n = S.length;
        while (i < n) {
            var c = S.charCodeAt(i);
            if (PDF_WS[c]) { i++; continue; }
            if (c === 37) { // % comment to end of line
                while (i < n && S[i] !== '\n' && S[i] !== '\r') i++;
                continue;
            }
            break;
        }
        return i;
    }

    function isRegular(c) { return c !== undefined && !PDF_WS[c.charCodeAt(0)] && PDF_DELIM.indexOf(c) === -1; }

    /**
     * Parse one PDF value at S[i]. Returns { t, s, e, ... } with e exclusive:
     * dict (map of key -> value), arr (items), name (v), num (v), ref (n, g),
     * str (literal) and hex strings, bool, null.
     */
    function parsePdfValue(S, i, depth) {
        if (depth > MAX_PDF_DEPTH) throw pdfError('PDF nesting too deep');
        i = skipPdfWs(S, i);
        var start = i, c = S[i];
        if (c === undefined) throw pdfError('Unexpected end of PDF');
        if (c === '<' && S[i + 1] === '<') {
            var map = {};
            i += 2;
            for (;;) {
                i = skipPdfWs(S, i);
                if (S[i] === '>' && S[i + 1] === '>') return { t: 'dict', map: map, s: start, e: i + 2 };
                if (S[i] !== '/') throw pdfError('Bad PDF dictionary key');
                var key = parsePdfValue(S, i, depth + 1);
                var val = parsePdfValue(S, key.e, depth + 1);
                map[key.v] = val;
                i = val.e;
            }
        }
        if (c === '<') {
            var close = S.indexOf('>', i);
            if (close < 0) throw pdfError('Unterminated hex string');
            return { t: 'hex', s: start, e: close + 1 };
        }
        if (c === '(') {
            var level = 0;
            for (; i < S.length; i++) {
                var ch = S[i];
                if (ch === '\\') { i++; continue; }
                if (ch === '(') level++;
                else if (ch === ')' && --level === 0) return { t: 'str', s: start, e: i + 1 };
            }
            throw pdfError('Unterminated string');
        }
        if (c === '[') {
            var items = [];
            i++;
            for (;;) {
                i = skipPdfWs(S, i);
                if (S[i] === ']') return { t: 'arr', items: items, s: start, e: i + 1 };
                var item = parsePdfValue(S, i, depth + 1);
                items.push(item);
                i = item.e;
            }
        }
        if (c === '/') {
            i++;
            while (isRegular(S[i])) i++;
            var raw = S.slice(start + 1, i);
            var decoded = raw.indexOf('#') === -1 ? raw : raw.replace(/#([0-9A-Fa-f]{2})/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); });
            return { t: 'name', v: decoded, s: start, e: i };
        }
        var num = /^[+-]?(?:\d+\.?\d*|\.\d+)/.exec(S.slice(i, i + 32));
        if (num) {
            var after = i + num[0].length;
            // An indirect reference: "12 0 R"
            var ref = /^(\s+)(\d+)(\s+)R(?![^\s()<>\[\]{}\/%])/.exec(S.slice(after, after + 32));
            if (/^\d+$/.test(num[0]) && ref) {
                return { t: 'ref', n: +num[0], g: +ref[2], s: start, e: after + ref[0].length };
            }
            return { t: 'num', v: +num[0], s: start, e: after };
        }
        var word = /^(true|false|null)(?![^\s()<>\[\]{}\/%])/.exec(S.slice(i, i + 6));
        if (word) return { t: word[1] === 'null' ? 'null' : 'bool', s: start, e: i + word[1].length };
        throw pdfError('Unexpected PDF token at offset ' + i);
    }

    function nameOf(v) { return v && v.t === 'name' ? v.v : null; }

    function filtersOf(dict) {
        var f = dict.map.Filter;
        if (!f) return [];
        if (f.t === 'name') return [f.v];
        if (f.t === 'arr') return f.items.map(nameOf);
        return [null];
    }

    // An unsigned integer token of at most maxDigits digits at S[i], or null.
    // Bounded, so a long run of digits costs nothing extra.
    function readUint(S, i, maxDigits) {
        var j = i;
        while (j < S.length && j - i <= maxDigits) {
            var c = S.charCodeAt(j);
            if (c < 48 || c > 57) break;
            j++;
        }
        if (j === i || j - i > maxDigits || isRegular(S[j])) return null;
        return { v: +S.slice(i, j), e: j };
    }

    // An object header "N G obj" at S[i] (any PDF whitespace or comments
    // between the parts): { n, g, body } or null.
    function parseHeader(S, i) {
        var n = readUint(S, i, 10);
        if (!n) return null;
        var j = skipPdfWs(S, n.e);
        if (j === n.e) return null;
        var g = readUint(S, j, 5);
        if (!g) return null;
        var k = skipPdfWs(S, g.e);
        if (k === g.e || !S.startsWith('obj', k) || isRegular(S[k + 3])) return null;
        return { n: n.v, g: g.v, body: k + 3 };
    }

    // Every "N G obj <int> endobj" (stream lengths stored as separate
    // objects), indexed by "n g": [{ v, s, e }]. The quantifiers are bounded,
    // so the scan stays linear even over long runs of digits.
    function indexIntObjects(S) {
        var re = /(\d{1,10})[\0\t\n\f\r ]+(\d{1,5})[\0\t\n\f\r ]+obj[\0\t\n\f\r ]*(\d{1,12})[\0\t\n\f\r ]*endobj/g;
        var index = {}, m;
        while ((m = re.exec(S)) !== null) {
            var prev = S.charCodeAt(m.index - 1);
            if (prev >= 48 && prev <= 57) continue; // the middle of a longer number
            var numStart = m.index + m[0].lastIndexOf(m[3], m[0].length - 6);
            var key = (+m[1]) + ' ' + (+m[2]);
            (index[key] = index[key] || []).push({ v: +m[3], s: numStart, e: numStart + m[3].length });
        }
        return index;
    }

    /**
     * Read the object whose header starts at off (body is where its value
     * starts). For a stream, finds its data from /Length, checked against
     * the endstream keyword.
     */
    function readPdfObject(S, off, num, gen, bodyStart, ints) {
        var value = parsePdfValue(S, bodyStart, 0);
        var p = skipPdfWs(S, value.e);
        var obj = { n: num, g: gen, off: off, value: value, stream: null, end: 0 };
        if (value.t === 'dict' && S.startsWith('stream', p)) {
            var ds = p + 6;
            if (S[ds] === '\r' && S[ds + 1] === '\n') ds += 2;
            else if (S[ds] === '\n' || S[ds] === '\r') ds += 1;
            var lenVal = value.map.Length;
            var candidates = [];
            if (lenVal && lenVal.t === 'num') candidates.push({ v: lenVal.v, direct: lenVal });
            if (lenVal && lenVal.t === 'ref') {
                // Each distinct value once, and only a few: duplicates of the
                // length object can't make every stream try them all.
                var tried = {};
                (ints[lenVal.n + ' ' + lenVal.g] || []).forEach(function (c) {
                    if (tried[c.v] || Object.keys(tried).length >= 8) return;
                    tried[c.v] = true;
                    candidates.push({ v: c.v, indirect: c, ref: lenVal.n + ' ' + lenVal.g });
                });
            }
            var de = -1, lengthAt = null;
            for (var k = 0; k < candidates.length && de < 0; k++) {
                var q = ds + candidates[k].v;
                if (S.startsWith('endstream', skipPdfWs(S, q))) { de = q; lengthAt = candidates[k]; }
            }
            if (de < 0) {
                // /Length is missing or wrong: use the endstream keyword.
                var es = S.indexOf('endstream', ds);
                if (es < 0) throw pdfError('Unterminated stream');
                de = es;
                if (S[de - 1] === '\n') de--;
                if (S[de - 1] === '\r') de--;
            }
            var endstream = S.indexOf('endstream', de);
            obj.stream = { ds: ds, de: de, length: lengthAt, endstream: endstream };
            p = endstream + 9;
        }
        // The object ends at its endobj, which must come next; without one it
        // ends right after its value, so it can't swallow what follows.
        p = skipPdfWs(S, p);
        if (S.startsWith('endobj', p)) {
            obj.end = p + 6;
        } else {
            obj.end = p;
            obj.noEndobj = true;
        }
        return obj;
    }

    /**
     * Walk the file token by token at the top level, as a reader rebuilding
     * a damaged file would: objects (including ones left over from older
     * revisions) and trailer dictionaries. Comments and NULs count as
     * whitespace, junk is stepped over, and each object's contents (its
     * stream data included) are skipped as a whole.
     */
    function scanTopLevel(S, ints) {
        var objects = [], trailers = [], trailerFailed = false;
        var n = S.length, i = 0;
        while (i < n) {
            i = skipPdfWs(S, i);
            if (i >= n) break;
            var c = S.charCodeAt(i);
            if (c >= 48 && c <= 57) {
                var h = parseHeader(S, i);
                if (h) {
                    var obj = readPdfObject(S, i, h.n, h.g, h.body, ints);
                    objects.push(obj);
                    i = Math.max(obj.end, h.body);
                    continue;
                }
            } else if (!trailerFailed && S.startsWith('trailer', i) && !isRegular(S[i + 7])) {
                // A trailer that doesn't parse can cost a scan to the end of
                // the file, so later ones aren't retried.
                var t = null;
                try { t = parsePdfValue(S, i + 7, 0); } catch (e) { t = null; }
                if (t && t.t === 'dict') { trailers.push(t); i = t.e; continue; }
                trailerFailed = true;
            }
            // Anything else: step over one token.
            if (isRegular(S[i])) { while (i < n && isRegular(S[i])) i++; } else i++;
        }
        return { objects: objects, trailers: trailers };
    }

    // True if S[from, to) contains something that looks like an object header.
    var RE_HEADER_ANYWHERE = /(?:^|[^0-9])\d{1,10}[\0\t\n\f\r ]+\d{1,5}[\0\t\n\f\r ]+obj(?![^\0\t\n\f\r ()<>\[\]{}\/%])/;
    function hasHiddenHeader(S, from, to) {
        return to > from && RE_HEADER_ANYWHERE.test(S.slice(from, to));
    }

    // Undo PNG predictors (as used by cross-reference streams): rows of
    // `columns` bytes, each preceded by its filter type.
    function unpredictPng(data, columns) {
        var row = columns + 1, rows = Math.floor(data.length / row);
        var out = new Uint8Array(rows * columns), prevRow = new Uint8Array(columns);
        for (var r = 0; r < rows; r++) {
            var type = data[r * row], base = r * row + 1, cur = new Uint8Array(columns);
            for (var x = 0; x < columns; x++) {
                var raw = data[base + x], left = x > 0 ? cur[x - 1] : 0, up = prevRow[x], ul = x > 0 ? prevRow[x - 1] : 0;
                var v;
                if (type === 0) v = raw;
                else if (type === 1) v = raw + left;
                else if (type === 2) v = raw + up;
                else if (type === 3) v = raw + ((left + up) >> 1);
                else if (type === 4) {
                    var pa = Math.abs(up - ul), pb = Math.abs(left - ul), pc = Math.abs(left + up - 2 * ul);
                    v = raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : ul);
                } else throw pdfError('Bad cross-reference predictor');
                cur[x] = v & 255;
            }
            out.set(cur, r * columns);
            prevRow = cur;
        }
        return out;
    }

    function readXrefTable(S, p, entries) {
        for (;;) {
            p = skipPdfWs(S, p);
            if (S.startsWith('trailer', p)) {
                var t = parsePdfValue(S, p + 7, 0);
                if (t.t !== 'dict') throw pdfError('Bad trailer');
                return t;
            }
            var start = readUint(S, p, 10);
            if (!start) throw pdfError('Bad cross-reference table');
            var count = readUint(S, skipPdfWs(S, start.e), 10);
            if (!count || count.v > 10000000) throw pdfError('Bad cross-reference table');
            p = count.e;
            for (var k = 0; k < count.v; k++) {
                var off = readUint(S, skipPdfWs(S, p), 10);
                if (!off) throw pdfError('Bad cross-reference entry');
                var gen = readUint(S, skipPdfWs(S, off.e), 5);
                if (!gen) throw pdfError('Bad cross-reference entry');
                p = skipPdfWs(S, gen.e);
                if (S[p] === 'n') entries.push({ n: start.v + k, g: gen.v, type: 1, off: off.v });
                else if (S[p] !== 'f') throw pdfError('Bad cross-reference entry');
                p++;
            }
        }
    }

    async function readXrefStream(S, b, p, ints, entries, ctx) {
        var h = parseHeader(S, p);
        if (!h) return null;
        var obj = readPdfObject(S, p, h.n, h.g, h.body, ints);
        var d = obj.value;
        if (!obj.stream || nameOf(d.map.Type) !== 'XRef') return null;
        var filters = filtersOf(d);
        var data = b.subarray(obj.stream.ds, obj.stream.de);
        if (filters.length === 1 && filters[0] === 'FlateDecode') {
            data = await inflatePdf(data, ctx.budget.left);
            ctx.budget.left -= data.length;
        } else if (filters.length) {
            return null;
        }
        var w = d.map.W && d.map.W.t === 'arr' ? d.map.W.items.map(function (x) { return x.v; }) : null;
        if (!w || w.length !== 3 || w.some(function (x) { return !(x >= 0 && x <= 8); })) return null;
        var parms = d.map.DecodeParms && d.map.DecodeParms.t === 'dict' ? d.map.DecodeParms.map : {};
        var predictor = parms.Predictor ? parms.Predictor.v : 1;
        if (predictor >= 10) data = unpredictPng(data, parms.Columns ? parms.Columns.v : 1);
        else if (predictor !== 1) return null;
        var size = d.map.Size ? d.map.Size.v : 0;
        var index = d.map.Index && d.map.Index.t === 'arr' ? d.map.Index.items.map(function (x) { return x.v; }) : [0, size];
        var rowLen = w[0] + w[1] + w[2], pos = 0;
        if (rowLen === 0) return null;
        function field(width, dflt) {
            if (!width) return dflt;
            var v = 0;
            for (var i = 0; i < width; i++) v = v * 256 + data[pos++];
            return v;
        }
        for (var s = 0; s + 1 < index.length; s += 2) {
            var count = Math.min(index[s + 1], Math.floor((data.length - pos) / rowLen));
            if (!(count >= 0) || entries.length + count > 10000000) return null;
            for (var k = 0; k < count; k++) {
                var type = field(w[0], 1), f2 = field(w[1], 0), f3 = field(w[2], 0);
                if (type === 1) entries.push({ n: index[s] + k, g: f3, type: 1, off: f2 });
                else if (type === 2) entries.push({ n: index[s] + k, g: 0, type: 2, stm: f2, idx: f3 });
            }
        }
        return d;
    }

    /**
     * Follow the cross-reference chain from startxref (tables and streams,
     * /Prev and /XRefStm) as a reader does. Returns { entries, trailers,
     * shift } (shift: offsets are relative to a %PDF- header that isn't at
     * the start), or broken: true when the chain can't be followed.
     */
    async function readXrefChain(S, b, ints, ctx) {
        var res = { entries: [], trailers: [], shift: 0, broken: false };
        var sx = S.lastIndexOf('startxref');
        var first = sx >= 0 ? readUint(S, skipPdfWs(S, sx + 9), 12) : null;
        if (!first) { res.broken = true; return res; }
        var header = S.indexOf('%PDF-');
        var queue = [first.v], seen = {};
        while (queue.length && res.trailers.length < 10000) {
            var off = queue.shift();
            if (seen[off]) continue;
            seen[off] = true;
            var trailer = null;
            for (var attempt = 0; attempt < 2 && !trailer; attempt++) {
                var shift = attempt ? header : res.shift;
                if (attempt && header <= 0) break;
                var p = skipPdfWs(S, off + shift);
                if (!(off + shift >= 0 && off + shift < S.length)) continue;
                try {
                    trailer = S.startsWith('xref', p) ? readXrefTable(S, p + 4, res.entries) : await readXrefStream(S, b, p, ints, res.entries, ctx);
                } catch (e) {
                    if (e.code === 'TOO_LARGE') throw e;
                    trailer = null;
                }
                if (trailer) res.shift = shift;
            }
            if (!trailer) { res.broken = true; continue; }
            res.trailers.push(trailer);
            ['Prev', 'XRefStm'].forEach(function (k) {
                var v = trailer.map[k];
                if (v && v.t === 'num') queue.push(v.v);
            });
        }
        return res;
    }

    // Bytes as a string with exactly one char per byte (TextDecoder's
    // "latin1" is really windows-1252 and not reliable across engines).
    function pdfLatin1(b) {
        var parts = [];
        for (var i = 0; i < b.length; i += 8192) parts.push(String.fromCharCode.apply(null, b.subarray(i, i + 8192)));
        return parts.join('');
    }

    async function inflatePdf(data, limit) {
        return pipeBytes(new DecompressionStream('deflate'), data, limit);
    }

    /**
     * Strip a PDF: the Info dictionary in every revision (including inside
     * object streams) and the strings it references, all XMP metadata
     * streams, the trailer /ID, comment authors and dates on annotations, and
     * EXIF in embedded JPEG images. Attached files, other image formats and
     * anything that can't be rewritten in place are listed in ctx.incomplete.
     */
    async function stripPdf(b, ctx) {
        var S = pdfLatin1(b);
        var out = b.slice();
        var ints = indexIntObjects(S);
        var scan = scanTopLevel(S, ints);
        var objects = scan.objects;
        if (!objects.length) throw pdfError('No objects found in PDF');

        // Cross-check against the cross-reference data readers use: every
        // object it lists must be one we process (anything it points at that
        // the scan missed is read from there), and its trailers count too.
        var chain = await readXrefChain(S, b, ints, ctx);
        var trailers = scan.trailers.slice();
        var trailerAt = {};
        trailers.forEach(function (t) { trailerAt[t.s] = true; });
        chain.trailers.forEach(function (t) { if (!trailerAt[t.s]) { trailers.push(t); trailerAt[t.s] = true; } });
        objects.forEach(function (o) {
            if (o.value.t === 'dict' && nameOf(o.value.map.Type) === 'XRef' && !trailerAt[o.value.s]) trailers.push(o.value);
        });
        if (!trailers.length) throw pdfError('No PDF trailer found');
        var byNum = {};
        objects.forEach(function (o) { (byNum[o.n + ' ' + o.g] = byNum[o.n + ' ' + o.g] || []).push(o); });
        // Scanned objects in file order, for finding the one an offset is in.
        var spans = objects.slice().sort(function (x, y) { return x.off - y.off; });
        function containing(at) {
            var lo = 0, hi = spans.length - 1, found = null;
            while (lo <= hi) {
                var mid = (lo + hi) >> 1;
                if (spans[mid].off < at) { found = spans[mid]; lo = mid + 1; } else hi = mid - 1;
            }
            return found && at < found.end ? found : null;
        }
        chain.entries.forEach(function (e) {
            if (e.type !== 1) return;
            var at = skipPdfWs(S, e.off + chain.shift);
            var same = byNum[e.n + ' ' + e.g] || [];
            if (same.some(function (o) { return o.off === at; })) return;
            var h = parseHeader(S, at);
            if (!(h && h.n === e.n && h.g === e.g)) {
                // Slightly-off offsets are common: accept a scanned object
                // with this number nearby, unless the offset lands inside
                // some other object.
                var near = same.some(function (o) { return Math.abs(o.off - at) <= 64; });
                if (near) {
                    var host = containing(at);
                    if (!host || (host.n === e.n && host.g === e.g)) return;
                }
            }
            if (h && h.n === e.n && h.g === e.g) {
                try {
                    var x = readPdfObject(S, at, h.n, h.g, h.body, ints);
                    objects.push(x);
                    (byNum[x.n + ' ' + x.g] = byNum[x.n + ' ' + x.g] || []).push(x);
                    return;
                } catch (err) { /* reported below */ }
            }
            ctx.incomplete.push('object listed in the cross-reference data but not found (object ' + e.n + ')');
        });

        // Without usable cross-reference data a reader rebuilds it by looking
        // for object headers anywhere, including inside other objects' stream
        // data, where the scan above doesn't look. Report such a file.
        if (chain.broken && objects.some(function (o) { return o.stream && hasHiddenHeader(S, o.stream.ds, o.stream.de); })) {
            ctx.incomplete.push('objects hidden inside other objects (damaged cross-reference data)');
        }

        // Length objects shared by several streams can't be rewritten for one.
        var lengthUses = {};
        objects.forEach(function (o) {
            var l = o.stream && o.stream.length;
            if (l && l.ref) lengthUses[l.ref] = (lengthUses[l.ref] || 0) + 1;
        });
        ctx.lengthUses = lengthUses;

        var infoRefs = {};
        trailers.forEach(function (t) {
            if (t.map.Encrypt) throw stripError('ENCRYPTED', 'Encrypted PDF');
            var info = t.map.Info;
            if (info && info.t === 'ref') infoRefs[info.n + ' ' + info.g] = true;
            if (info && info.t === 'dict') blankRange(out, info.s + 2, info.e - 2);
            var id = t.map.ID;
            if (id && id.t === 'arr') id.items.forEach(function (it) { zeroString(out, S, it); });
        });

        // Object streams, inflated once: { obj, text, objects: [{ n, value }] }
        var objStms = [];
        for (var i = 0; i < objects.length; i++) {
            var o = objects[i];
            if (!o.stream || nameOf(o.value.map.Type) !== 'ObjStm') continue;
            var f = filtersOf(o.value);
            if (f.length > 1 || (f.length === 1 && f[0] !== 'FlateDecode') || o.value.map.DecodeParms) {
                ctx.incomplete.push('compressed objects (object ' + o.n + ')');
                continue;
            }
            var raw = out.subarray(o.stream.ds, o.stream.de);
            var plain = f.length ? await inflatePdf(raw, ctx.budget.left) : raw;
            ctx.budget.left -= plain.length;
            var text = pdfLatin1(plain);
            var count = o.value.map.N && o.value.map.N.v, first = o.value.map.First && o.value.map.First.v;
            if (!(count >= 0) || !(first >= 0)) throw pdfError('Bad object stream header');
            var head = text.slice(0, first).trim().split(/\s+/).map(Number);
            var members = [];
            for (var k = 0; k < count; k++) {
                var at = first + head[2 * k + 1];
                if (!(at >= first && at < text.length)) throw pdfError('Bad object stream offset');
                members.push({ n: head[2 * k], value: parsePdfValue(text, at, 0) });
            }
            objStms.push({ obj: o, text: text, bytes: plain.slice(), members: members, changed: false });
        }

        // Compressed objects the cross-reference data lists must be members
        // of an object stream we read.
        var members = {};
        objStms.forEach(function (st) { st.members.forEach(function (m) { members[st.obj.n + ':' + m.n] = true; }); });
        chain.entries.forEach(function (e) {
            if (e.type === 2 && !members[e.stm + ':' + e.n]) {
                ctx.incomplete.push('compressed object not found (object ' + e.n + ')');
            }
        });

        // Pass 1: what to clear. Strings referenced from an Info dictionary
        // or a comment annotation (e.g. /Producer 11 0 R), and streams
        // named by a /Metadata entry even when they lack /Type /Metadata.
        var stringRefs = {}, blobRefs = {}, metadataRefs = {}, pieceRefs = {}, embeddedRefs = {}, matched = {};
        function noteRef(v, into) { if (v && v.t === 'ref') into[v.n + ' ' + v.g] = true; }
        function collect(key, value) {
            if (infoRefs[key] && value.t === 'dict') collectRefs(value, stringRefs);
            walkDicts(value, function (d) {
                noteRef(d.map.Metadata, metadataRefs);
                if (d.map.PieceInfo) collectRefs(d.map.PieceInfo, pieceRefs);
                // Attached files, whatever their /Type: through a file
                // specification's /EF or /RF
                if (d.map.EF) collectRefs(d.map.EF, embeddedRefs);
                if (d.map.RF) collectRefs(d.map.RF, embeddedRefs);
                if (MARKUP_ANNOTS[nameOf(d.map.Subtype)]) ANNOT_KEYS.forEach(function (k) { noteRef(d.map[k], stringRefs); });
                if (isSignature(d)) {
                    SIG_STRINGS.forEach(function (k) { noteRef(d.map[k], stringRefs); });
                    SIG_BLOBS.forEach(function (k) { noteRef(d.map[k], blobRefs); });
                }
            });
        }
        objects.forEach(function (o) { collect(o.n + ' ' + o.g, o.value); });
        objStms.forEach(function (st) { st.members.forEach(function (m) { collect(m.n + ' 0', m.value); }); });
        // Everything application-private data reaches (Illustrator's
        // private data streams and the like) that the document itself
        // doesn't use: anything reachable from the trailer without going
        // through /PieceInfo is kept.
        var values = {};
        function addValue(k, v) { (values[k] = values[k] || []).push(v); }
        objects.forEach(function (o) { addValue(o.n + ' ' + o.g, o.value); });
        objStms.forEach(function (st) { st.members.forEach(function (m) { addValue(m.n + ' 0', m.value); }); });
        function reach(startRefs, skipPieceInfo) {
            var seen = {}, queue = Object.keys(startRefs);
            while (queue.length) {
                var k = queue.pop();
                if (seen[k]) continue;
                seen[k] = true;
                (values[k] || []).forEach(function (v) {
                    var next = {};
                    collectRefs(v, next, skipPieceInfo);
                    Object.keys(next).forEach(function (r) { if (!seen[r]) queue.push(r); });
                });
            }
            return seen;
        }
        var docRefs = {};
        trailers.forEach(function (t) { collectRefs(t, docRefs, true); });
        var used = reach(docRefs, true);
        var privateReach = reach(pieceRefs, false);
        pieceRefs = {};
        Object.keys(privateReach).forEach(function (k) { if (!used[k]) pieceRefs[k] = true; });

        // Pass 2: top-level objects
        for (i = 0; i < objects.length; i++) {
            o = objects[i];
            var key = o.n + ' ' + o.g;
            var v = o.value;
            // An Info dictionary never has /Type: a reused object number
            // that now holds something else is left alone.
            if (infoRefs[key] && v.t === 'dict' && !v.map.Type) { blankRange(out, v.s + 2, v.e - 2); matched[key] = true; }
            if (blobRefs[key] && (v.t === 'str' || v.t === 'hex')) { zeroString(out, S, v); matched[key] = true; }
            if (pieceRefs[key]) await clearPrivate(out, S, o, ctx);
            if (stringRefs[key] && (v.t === 'str' || v.t === 'hex')) { blankString(out, v); matched[key] = true; }
            walkDicts(v, function (d) { cleanDict(out, S, d); });
            if (!o.stream) continue;
            var type = nameOf(v.map.Type), subtype = nameOf(v.map.Subtype);
            var filters = filtersOf(v);
            if (type === 'Metadata' || subtype === 'XML' || metadataRefs[key]) {
                await replaceXmp(out, S, o, filters, ctx);
                matched[key] = true;
            } else if (type === 'EmbeddedFile' || embeddedRefs[key]) {
                ctx.incomplete.push('attached file (object ' + o.n + ')');
            } else if (subtype === 'Image' && filters.indexOf('DCTDecode') !== -1) {
                if (filters.length !== 1) {
                    ctx.incomplete.push('image (object ' + o.n + ')');
                } else {
                    var jpg = out.subarray(o.stream.ds, o.stream.de);
                    var clean = null;
                    try { clean = stripJpeg(jpg); } catch (e) { clean = null; }
                    if (!clean) ctx.incomplete.push('image (object ' + o.n + ')');
                    else if (clean.length !== jpg.length && !tryRewrite(out, S, o, clean.slice(), ctx)) ctx.incomplete.push('image (object ' + o.n + ')');
                }
            } else if (subtype === 'Image' && filters.indexOf('JPXDecode') !== -1) {
                ctx.incomplete.push('JPEG 2000 image (object ' + o.n + ')');
            } else if (filters.length && type !== 'ObjStm' && type !== 'XRef' && subtype !== 'Image' && !isFontFile(v) && !pieceRefs[key]) {
                // Any other encoded stream might hide an XMP packet.
                var found = await encodedXmp(out.subarray(o.stream.ds, o.stream.de), v, ctx);
                if (found) ctx.incomplete.push(found + ' (object ' + o.n + ')');
            } else if (!filters.length && type !== 'XRef' && subtype !== 'Image' && !isFontFile(v) && !pieceRefs[key]) {
                var reason = inspectDecoded(S.slice(o.stream.ds, o.stream.de));
                if (reason) ctx.incomplete.push(reason + ' (object ' + o.n + ')');
            }
        }

        // Objects inside object streams
        for (i = 0; i < objStms.length; i++) {
            var st = objStms[i];
            for (k = 0; k < st.members.length; k++) {
                var mem = st.members[k];
                var mk = mem.n + ' 0';
                if (infoRefs[mk] && mem.value.t === 'dict' && !mem.value.map.Type) { blankRange(st.bytes, mem.value.s + 2, mem.value.e - 2); st.changed = matched[mk] = true; }
                if (blobRefs[mk] && (mem.value.t === 'str' || mem.value.t === 'hex')) { zeroString(st.bytes, st.text, mem.value); st.changed = matched[mk] = true; }
                if (pieceRefs[mk] && mem.value.t === 'dict') { blankRange(st.bytes, mem.value.s + 2, mem.value.e - 2); st.changed = true; }
                if (pieceRefs[mk] && (mem.value.t === 'str' || mem.value.t === 'hex')) { blankString(st.bytes, mem.value); st.changed = true; }
                if (stringRefs[mk] && (mem.value.t === 'str' || mem.value.t === 'hex')) { blankString(st.bytes, mem.value); st.changed = matched[mk] = true; }
                walkDicts(mem.value, function (d) { if (cleanDict(st.bytes, st.text, d)) st.changed = true; });
            }
            if (XMP_MARKER.test(st.text)) ctx.incomplete.push('XMP metadata (object ' + st.obj.n + ')');
            if (st.changed) {
                var packed = await pipeBytes(new CompressionStream('deflate'), st.bytes, MAX_INFLATED_BYTES);
                // Recompressed at the browser's level it may not fit where
                // the original was; then the file is reported, not changed.
                if (!tryRewrite(out, S, st.obj, packed, ctx)) {
                    ctx.incomplete.push('compressed objects that could not be rewritten (object ' + st.obj.n + ')');
                }
            }
        }

        // Fail closed if any document information or string it names wasn't
        // found and cleared.
        Object.keys(infoRefs).concat(Object.keys(stringRefs), Object.keys(blobRefs)).forEach(function (r) {
            if (!matched[r]) ctx.incomplete.push('document information not found (object ' + r.split(' ')[0] + ')');
        });
        Object.keys(metadataRefs).forEach(function (r) {
            if (!matched[r]) ctx.incomplete.push('metadata not found (object ' + r.split(' ')[0] + ')');
        });

        // Uncompressed XMP that wasn't in a metadata stream we could clear
        if (XMP_MARKER.test(S)) {
            var left = pdfLatin1(out).split(EMPTY_XMP).join('');
            if (XMP_MARKER.test(left)) ctx.incomplete.push('XMP metadata outside a metadata stream');
        }
        return out;
    }

    var XMP_MARKER = /<\?xpacket\s+begin|<x:xmpmeta/;
    var MAX_CHECKED_STREAM = 64 * 1024 * 1024;
    var ANNOT_KEYS = ['T', 'M', 'CreationDate'];

    // Call fn on every dictionary in a parsed value, nested ones included.
    function walkDicts(v, fn) {
        if (v.t === 'dict') {
            fn(v);
            Object.keys(v.map).forEach(function (k) { walkDicts(v.map[k], fn); });
        } else if (v.t === 'arr') {
            v.items.forEach(function (it) { walkDicts(it, fn); });
        }
    }

    function isSignature(d) { return nameOf(d.map.Type) === 'Sig' || !!d.map.ByteRange; }

    // Every indirect reference inside a value (optionally not following
    // /PieceInfo entries).
    function collectRefs(v, into, skipPieceInfo) {
        if (v.t === 'ref') into[v.n + ' ' + v.g] = true;
        else if (v.t === 'dict') Object.keys(v.map).forEach(function (k) { if (!(skipPieceInfo && k === 'PieceInfo')) collectRefs(v.map[k], into, skipPieceInfo); });
        else if (v.t === 'arr') v.items.forEach(function (it) { collectRefs(it, into, skipPieceInfo); });
    }

    function isFontFile(v) {
        var sub = nameOf(v.map.Subtype);
        return !!(v.map.Length1 || v.map.Length2 || v.map.Length3) || sub === 'Type1C' || sub === 'CIDFontType0C' || sub === 'OpenType';
    }

    // Clear an object that application-private data points at: a dict is
    // emptied, a string blanked, a stream's data replaced with nothing.
    async function clearPrivate(out, S, o, ctx) {
        var v = o.value;
        if (!o.stream) {
            if (v.t === 'dict') blankRange(out, v.s + 2, v.e - 2);
            else if (v.t === 'str' || v.t === 'hex') blankString(out, v);
            return;
        }
        var filters = filtersOf(v);
        if (!filters.length) {
            blankRange(out, o.stream.ds, o.stream.de);
        } else if (filters.length === 1 && filters[0] === 'FlateDecode') {
            var empty = await pipeBytes(new CompressionStream('deflate'), new Uint8Array(0), 1024);
            if (!tryRewrite(out, S, o, empty, ctx)) ctx.incomplete.push('application data (object ' + o.n + ')');
        } else {
            ctx.incomplete.push('application data (object ' + o.n + ')');
        }
    }

    function uncheckable() { var e = new Error('uncheckable'); e.code = 'UNCHECKABLE'; return e; }

    // A growable byte buffer that stops at the inflate budget.
    function ByteSink(limit) { this.buf = new Uint8Array(4096); this.len = 0; this.limit = limit; }
    ByteSink.prototype.push = function (byte) {
        if (this.len >= this.buf.length) {
            if (this.len >= this.limit) throw stripError('TOO_LARGE', 'Decoded data too large');
            var bigger = new Uint8Array(Math.min(this.buf.length * 2, this.limit + 1));
            bigger.set(this.buf);
            this.buf = bigger;
        }
        this.buf[this.len++] = byte;
    };
    ByteSink.prototype.bytes = function () { return this.buf.subarray(0, this.len); };

    function decodeHex(b, limit) {
        var out = new ByteSink(limit), hi = -1;
        for (var i = 0; i < b.length && b[i] !== 0x3E; i++) {
            var c = b[i];
            if (PDF_WS[c]) continue;
            var d = parseInt(String.fromCharCode(c), 16);
            if (isNaN(d)) throw uncheckable();
            if (hi < 0) hi = d; else { out.push(hi * 16 + d); hi = -1; }
        }
        if (hi >= 0) out.push(hi * 16);
        return out.bytes();
    }

    function decode85(b, limit) {
        var out = new ByteSink(limit), group = [], i = 0;
        if (b[0] === 0x3C && b[1] === 0x7E) i = 2; // optional <~
        function emit(g, count) {
            var n = (((g[0] * 85 + g[1]) * 85 + g[2]) * 85 + g[3]) * 85 + g[4];
            var bytes = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
            for (var k = 0; k < count; k++) out.push(bytes[k]);
        }
        for (; i < b.length; i++) {
            var c = b[i];
            if (PDF_WS[c]) continue;
            if (c === 0x7E) break; // ~> ends the data
            if (c === 0x7A && group.length === 0) { emit([0, 0, 0, 0, 0], 4); continue; } // z
            if (c < 0x21 || c > 0x75) throw uncheckable();
            group.push(c - 33);
            if (group.length === 5) { emit(group, 4); group = []; }
        }
        if (group.length) {
            var len = group.length;
            while (group.length < 5) group.push(84);
            emit(group, len - 1);
        }
        return out.bytes();
    }

    // LZW with the 4096-entry table PDF uses (entries stored as prefix code
    // plus one byte, so nothing is copied).
    function decodeLzw(b, earlyChange, limit) {
        var out = new ByteSink(limit);
        var prefix = new Int32Array(4096), suffix = new Uint8Array(4096), first = new Uint8Array(4096), stack = new Uint8Array(4096);
        for (var c0 = 0; c0 < 256; c0++) { suffix[c0] = c0; first[c0] = c0; prefix[c0] = -1; }
        var next = 258, width = 9, prev = -1, acc = 0, bits = 0;
        function emit(code) {
            var sp = 0;
            for (var c = code; c >= 0; c = prefix[c]) stack[sp++] = suffix[c];
            while (sp) out.push(stack[--sp]);
        }
        for (var i = 0; i < b.length; i++) {
            acc = ((acc << 8) | b[i]) & 0xFFFFFF;
            bits += 8;
            while (bits >= width) {
                bits -= width;
                var code = (acc >>> bits) & ((1 << width) - 1);
                if (code === 256) { next = 258; width = 9; prev = -1; continue; }
                if (code === 257) return out.bytes();
                if (prev < 0) {
                    if (code > 255) throw uncheckable();
                    emit(code);
                    prev = code;
                    continue;
                }
                var head;
                if (code < next) head = first[code];
                else if (code === next) head = first[prev];
                else throw uncheckable();
                if (next < 4096) {
                    prefix[next] = prev; suffix[next] = head; first[next] = first[prev];
                    next++;
                }
                emit(code);
                prev = code;
                if (next + earlyChange >= (1 << width) && width < 12) width++;
            }
        }
        return out.bytes();
    }

    function decodeRunLength(b, limit) {
        var out = new ByteSink(limit);
        for (var i = 0; i < b.length;) {
            var n = b[i++];
            if (n === 128) break;
            if (n < 128) { for (var j = 0; j <= n && i < b.length; j++) out.push(b[i++]); }
            else { var c = b[i++]; for (var k = 0; k < 257 - n; k++) out.push(c); }
        }
        return out.bytes();
    }

    // Inline JPEG images (BI ... /F /DCT ... ID) carry their own EXIF.
    var RE_INLINE_DCT = /\/(?:F|Filter)\s*(?:\/DCT|\[[^\]]{0,200}\/DCT)/;

    // A reason string if decoded stream data holds XMP or an inline JPEG.
    function inspectDecoded(text) {
        if (XMP_MARKER.test(text)) return 'XMP metadata';
        if (/(?:^|[\s\]>])BI(?=[\s\/])/.test(text) && RE_INLINE_DCT.test(text)) return 'inline JPEG image';
        return null;
    }

    /**
     * A reason string if an encoded stream holds XMP or can't be checked:
     * Flate, LZW, ASCIIHex, ASCII85 and RunLength chains are decoded (no
     * predictors); anything else is reported as uncheckable.
     */
    async function encodedXmp(data, dict, ctx) {
        var filters = filtersOf(dict);
        var parms = dict.map.DecodeParms;
        var parmList = parms ? (parms.t === 'arr' ? parms.items : [parms]) : [];
        var plain = data;
        // One stream is checked up to 64 MB decoded; bigger is reported.
        var limit = Math.min(ctx.budget.left, MAX_CHECKED_STREAM);
        try {
            for (var i = 0; i < filters.length; i++) {
                var dp = parmList[i] && parmList[i].t === 'dict' ? parmList[i].map : {};
                if (dp.Predictor && dp.Predictor.v > 1) throw uncheckable();
                var f = filters[i];
                if (f === 'FlateDecode' || f === 'Fl') plain = await inflatePdf(plain, limit);
                else if (f === 'LZWDecode' || f === 'LZW') plain = decodeLzw(plain, dp.EarlyChange ? dp.EarlyChange.v : 1, limit);
                else if (f === 'ASCIIHexDecode' || f === 'AHx') plain = decodeHex(plain, limit);
                else if (f === 'ASCII85Decode' || f === 'A85') plain = decode85(plain, limit);
                else if (f === 'RunLengthDecode' || f === 'RL') plain = decodeRunLength(plain, limit);
                else throw uncheckable();
            }
        } catch (e) {
            if (e.code === 'TOO_LARGE') return 'encoded data too large to check';
            return 'encoded data that could not be checked';
        }
        ctx.budget.left -= plain.length;
        return inspectDecoded(pdfLatin1(plain));
    }

    function blankRange(out, s, e) { if (e > s) out.fill(0x20, s, e); }

    // A string value becomes () followed by spaces.
    function blankString(out, v) {
        out[v.s] = 0x28; out[v.s + 1] = 0x29;
        blankRange(out, v.s + 2, v.e);
    }

    // Keep the /ID strings' length but zero their contents.
    function zeroString(out, S, v) {
        if (v.t === 'hex') {
            for (var i = v.s + 1; i < v.e - 1; i++) if (/[0-9A-Fa-f]/.test(S[i])) out[i] = 0x30;
        } else if (v.t === 'str') {
            out[v.s] = 0x3C; out[v.e - 1] = 0x3E; // rewrite as a hex string of zeros
            for (var j = v.s + 1; j < v.e - 1; j++) out[j] = 0x30;
        }
    }

    var SIG_STRINGS = ['Name', 'Location', 'Reason', 'ContactInfo', 'M'];
    var SIG_BLOBS = ['Contents', 'Cert'];

    /**
     * Clean one dictionary wherever it appears: comment annotations lose
     * their author and dates, signature dictionaries their signer details and
     * certificate (the signature is invalid after any edit anyway), and
     * /PieceInfo (application-private data) is emptied. True if changed.
     */
    function cleanDict(out, src, d) {
        var changed = blankAnnotation(out, d);
        if (isSignature(d)) {
            SIG_STRINGS.forEach(function (k) {
                var v = d.map[k];
                if (v && (v.t === 'str' || v.t === 'hex')) { blankString(out, v); changed = true; }
            });
            SIG_BLOBS.forEach(function (k) {
                var v = d.map[k];
                var items = v ? (v.t === 'arr' ? v.items : [v]) : [];
                items.forEach(function (it) { if (it.t === 'str' || it.t === 'hex') { zeroString(out, src, it); changed = true; } });
            });
        }
        var piece = d.map.PieceInfo;
        if (piece && piece.t === 'dict') { blankRange(out, piece.s + 2, piece.e - 2); changed = true; }
        return changed;
    }

    // Clear the author and dates of a comment annotation; true if changed.
    function blankAnnotation(out, dict) {
        if (!MARKUP_ANNOTS[nameOf(dict.map.Subtype)]) return false;
        var changed = false;
        ANNOT_KEYS.forEach(function (k) {
            var v = dict.map[k];
            if (v && (v.t === 'str' || v.t === 'hex')) { blankString(out, v); changed = true; }
        });
        return changed;
    }

    // An XMP packet with no properties, so validators still find valid XMP.
    var EMPTY_XMP = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>' +
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>' +
        '<?xpacket end="w"?>';

    function asciiBytes(str) {
        var b = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) b[i] = str.charCodeAt(i);
        return b;
    }

    async function replaceXmp(out, S, o, filters, ctx) {
        var empty = asciiBytes(EMPTY_XMP);
        if (!filters.length) {
            // Same length: the empty packet padded with spaces (or just
            // spaces if the original was shorter).
            blankRange(out, o.stream.ds, o.stream.de);
            if (empty.length <= o.stream.de - o.stream.ds) out.set(empty, o.stream.ds);
        } else if (filters.length === 1 && filters[0] === 'FlateDecode' && !o.value.map.DecodeParms) {
            var packed = await pipeBytes(new CompressionStream('deflate'), empty, 1024);
            // A tiny original may not have room for the packet: leave it empty.
            if (o.stream.ds + packed.length + 17 > o.end) packed = await pipeBytes(new CompressionStream('deflate'), new Uint8Array(0), 1024);
            if (!tryRewrite(out, S, o, packed, ctx)) ctx.incomplete.push('metadata (object ' + o.n + ')');
        } else {
            ctx.incomplete.push('metadata (object ' + o.n + ')');
        }
    }

    /**
     * Replace a stream's data with shorter data in its own space: the data,
     * then endstream/endobj, then spaces up to where the object ended, with
     * /Length rewritten in the same width.
     */
    // rewriteStream, returning false instead of throwing when it can't fit.
    function tryRewrite(out, S, o, data, ctx) {
        try {
            rewriteStream(out, S, o, data, ctx);
            return true;
        } catch (e) {
            if (e.noFit) return false;
            throw e;
        }
    }

    function noFit(msg) { var e = pdfError(msg); e.noFit = true; return e; }

    function rewriteStream(out, S, o, data, ctx) {
        var st = o.stream;
        var tail = '\nendstream\nendobj';
        if (o.noEndobj || st.ds + data.length + tail.length > o.end) throw noFit('Cleaned data does not fit in object ' + o.n);
        var len = o.value.map.Length;
        var site = st.length && (st.length.direct || st.length.indirect);
        if (!len || !site || !(len.t === 'num' || len.t === 'ref')) throw noFit('Cannot update the length of object ' + o.n);
        if (st.length.ref && ctx.lengthUses[st.length.ref] > 1) throw noFit('Length of object ' + o.n + ' is shared');
        var digits = String(data.length);
        if (digits.length > site.e - site.s) throw noFit('Cannot update the length of object ' + o.n);
        for (var i = 0; i < site.e - site.s; i++) out[site.s + i] = i < digits.length ? digits.charCodeAt(i) : 0x20;
        out.set(data, st.ds);
        var p = st.ds + data.length;
        for (i = 0; i < tail.length; i++) out[p + i] = tail.charCodeAt(i);
        blankRange(out, p + tail.length, o.end);
    }

    /**
     * Strip metadata from file bytes, detecting the type from the content
     * (never the extension). Resolves to { data: ArrayBuffer, type:
     * 'jpeg'|'png'|'office'|'pdf'|null, supported: bool, removedBytes: number,
     * orientation: 1-8|null, incomplete: string[] } (orientation is the value
     * that was present BEFORE stripping; incomplete lists the parts of an
     * Office file or PDF that may still hold metadata, such as embedded OLE
     * objects, TIFF images or PDF attachments). Unsupported types are returned unchanged with
     * supported:false. Rejects when a supported type can't be stripped; the
     * error's code says why (see stripError).
     */
    async function stripMetadata(input) {
        var b = toU8(input);
        var type = detectType(b);
        var entries = null;
        if (!type && isZip(b)) {
            try {
                entries = readZip(b);
            } catch (err) {
                // An unreadable zip only matters if it may be an Office
                // file; other archives, zip64 ones included, pass through as
                // unsupported.
                if (mentionsContentTypes(b)) throw err;
                entries = [];
            }
            if (isOoxml(entries)) {
                if (b.length > MAX_CONTAINER_BYTES) throw stripError('TOO_LARGE', 'Office file too large to remove metadata in the browser');
                type = 'office';
            }
        }
        if (!type && isPdf(b)) {
            if (b.length > MAX_CONTAINER_BYTES) throw stripError('TOO_LARGE', 'PDF too large to remove metadata in the browser');
            type = 'pdf';
        }
        if (!type) {
            var copy = (input instanceof ArrayBuffer) ? input : b.slice().buffer;
            return { data: copy, type: null, supported: false, removedBytes: 0, orientation: null, incomplete: [] };
        }
        var orientation = null;
        var incomplete = [];
        var out;
        if (type === 'office' || type === 'pdf') {
            if (!compressionSupported()) throw stripError('UNSUPPORTED_BROWSER', 'This browser cannot remove metadata from this file');
            var ctx = { budget: { left: MAX_INFLATED_BYTES }, depth: 0, incomplete: incomplete };
            out = type === 'office' ? await stripOoxml(entries, ctx) : await stripPdf(b, ctx);
        } else {
            orientation = readOrientation(b);
            out = type === 'jpeg' ? stripJpeg(b) : stripPng(b);
        }
        var buf = out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
        return { data: buf, type: type, supported: true, removedBytes: b.length - out.length, orientation: orientation,
            incomplete: incomplete };
    }

    var api = {
        detectType: detectType,
        stripJpeg: stripJpeg,
        stripPng: stripPng,
        readOrientation: readOrientation,
        compressionSupported: compressionSupported,
        scrubOfficeXml: scrubOfficeXml,
        stripMetadata: stripMetadata
    };

    root.SafeShareMetadata = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);

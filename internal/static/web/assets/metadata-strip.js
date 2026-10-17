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
    for (var ci = 0; ci < '[Content_Types].xml'.length; ci++) CONTENT_TYPES.push('[Content_Types].xml'.charCodeAt(ci));

    // True if the bytes contain the name [Content_Types].xml anywhere (it is
    // in every Office file's directory, whatever order or zip variant).
    function mentionsContentTypes(b) {
        var first = CONTENT_TYPES[0], n = CONTENT_TYPES.length;
        for (var i = b.indexOf(first); i !== -1 && i + n <= b.length; i = b.indexOf(first, i + 1)) {
            var j = 1;
            while (j < n && b[i + j] === CONTENT_TYPES[j]) j++;
            if (j === n) return true;
        }
        return false;
    }

    function isOoxml(entries) {
        for (var i = 0; i < entries.length; i++) if (entries[i].name === '[Content_Types].xml') return true;
        return false;
    }

    var XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n';
    var VT_NS = ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"';
    // Empty but valid replacements for the document property parts.
    var PROPERTY_TEMPLATES = {
        core: XML_DECL + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"' +
            ' xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"' +
            ' xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></cp:coreProperties>',
        app: XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"' + VT_NS + '></Properties>',
        custom: XML_DECL + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"' + VT_NS + '></Properties>'
    };
    var DEFAULT_PROPERTY_PARTS = { 'docprops/core.xml': 'core', 'docprops/app.xml': 'app', 'docprops/custom.xml': 'custom' };
    var PROPERTY_REL_TYPES = [[/\/metadata\/core-properties$/, 'core'], [/\/extended-properties$/, 'app'], [/\/custom-properties$/, 'custom']];

    // Part names below are matched lower-cased: OPC part names are case-insensitive.
    // customXml data stores (SharePoint columns, cover-page fields, ...) are emptied.
    var CUSTOM_XML_ITEM = /^customxml\/item\d+\.xml$/;
    var EMPTY_CUSTOM_XML = XML_DECL + '<root/>';
    // XML parts that can name people, carry edit history or point at the
    // author's files. Worksheets are left alone: they hold no author data and
    // can be very large.
    var SCRUB_PART = new RegExp('^(?:word|ppt)/.+\\.(?:xml|rels)$|^xl/(?:workbook\\.xml|connections\\.xml|comments\\d*\\.xml|' +
        'comments/.+\\.xml|(?:.+/)?_rels/.+\\.rels|persons/.+\\.xml|threadedcomments/.+\\.xml|revisions/.+\\.xml|' +
        'pivotcache/.+\\.xml|externallinks/.+\\.xml|querytables/.+\\.xml)$');
    // VBA projects carry the project name and code; they can't be cleaned here.
    var VBA_PART = /(?:^|\/)vbaproject\.bin$/;
    var MEDIA_PART = /^(?:word|ppt|xl)\/media\/|^docprops\/thumbnail\./;
    var EMBEDDED_PART = /^(?:word|ppt|xl)\/embeddings\//;
    var PRINTER_SETTINGS = /^(?:word|ppt|xl)\/printersettings\/.+\.bin$/;
    // Embedded image formats that can carry EXIF but can't be cleaned here.
    var UNCLEANABLE_IMAGE = /\.(?:tiff?|heic|heif|avif|webp|jxr|wdp|hdp)$/;
    // How deep embedded Office files (e.g. a chart's workbook) are cleaned.
    var MAX_EMBED_DEPTH = 2;

    var EPOCH = '1970-01-01T00:00:00Z';
    var WHO = '(?:author|initials|userId|providerId|userName|displayName|refreshedBy)';
    var VAL = '\\s*=\\s*(?:"[^"]*"|\'[^\']*\')';
    var DATE_ATTR = '(?:date|dateUtc|dateTime|dt|dT|created)';
    var NAME_ATTR_TAGS = { cmAuthor: 1, author: 1, userInfo: 1 };
    // One tag, with quoted attribute values that may contain '>'. The
    // alternatives start with different characters, so matching is linear.
    var TAG = /<(?:[^>"']|"[^"]*"|'[^']*')*>/g;

    var RE_WHO = new RegExp('(\\s(?:[A-Za-z0-9]+:)?' + WHO + ')' + VAL, 'g');
    var RE_NAME = new RegExp('(\\sname)' + VAL, 'g');
    var RE_DATE = new RegExp('(\\s(?:[A-Za-z0-9]+:)?' + DATE_ATTR + ')\\s*=\\s*(?:"\\d{4}-[^"]*"|\'\\d{4}-[^\']*\')', 'g');
    var RE_REFRESHED = new RegExp('(\\srefreshedDate)' + VAL, 'g');
    var RE_RSID = new RegExp('\\s[A-Za-z0-9]+:rsid[A-Za-z]*' + VAL, 'g');
    var RE_URL = new RegExp('(\\surl)' + VAL);
    // Excel data connections: the .odc/source file path, and the connection
    // string (which can hold a user name or password).
    var RE_SOURCE_FILE = new RegExp('(\\s(?:odcFile|sourceFile))' + VAL, 'g');
    var RE_CONNECTION = new RegExp('(\\sconnection)' + VAL, 'g');
    var RE_TARGET = new RegExp('(\\sTarget)' + VAL);
    // file: URLs, drive paths and network paths (\\server\share)
    var RE_FILE_TARGET = /\sTarget\s*=\s*["']\s*(?:file:|[A-Za-z]:[\\/]|\\\\)/i;

    function tagName(tag) {
        var m = /^<\/?(?:([A-Za-z0-9]+):)?([A-Za-z0-9_.-]+)/.exec(tag);
        return m ? { prefix: m[1] || '', local: m[2] } : null;
    }

    function scrubTag(tag) {
        if (tag[1] === '!' || tag[1] === '?' || tag[1] === '/') return tag;
        var n = tagName(tag);
        if (!n) return tag;
        // Word document IDs and Excel's revision pointer go entirely.
        if ((n.local === 'docId' && /^w\d*$/.test(n.prefix)) || (n.local === 'revisionPtr' && n.prefix === 'xr')) return '';
        tag = tag
            .replace(RE_WHO, '$1=""')
            .replace(RE_DATE, '$1="' + EPOCH + '"')
            .replace(RE_REFRESHED, '$1="0"')
            .replace(RE_RSID, '');
        if (NAME_ATTR_TAGS[n.local]) tag = tag.replace(RE_NAME, '$1=""');
        if (n.local === 'absPath') tag = tag.replace(RE_URL, '$1=""');
        tag = tag.replace(RE_SOURCE_FILE, '$1=""');
        if (n.local === 'dbPr') tag = tag.replace(RE_CONNECTION, '$1=""');
        // Template paths and links to the author's own files
        // (file:///C:/Users/<name>/...).
        if (n.local === 'Relationship' && (/attachedTemplate["']/.test(tag) || RE_FILE_TARGET.test(tag))) {
            tag = tag.replace(RE_TARGET, '$1=""');
        }
        return tag;
    }

    /**
     * Remove people, dates, edit-session identifiers and local file paths
     * from an Office XML part. Attributes are edited only inside tags, so
     * document text is never touched.
     */
    function scrubOfficeXml(xml) {
        return xml
            .replace(/<w:rsids\b[^>]*\/>|<w:rsids\b[^>]*>[\s\S]*?<\/w:rsids>/g, '')
            // Word document variables (any add-in data) and mail-merge
            // sources (paths and connection strings).
            .replace(/<w:docVars\b[^>]*\/>|<w:docVars\b[^>]*>[\s\S]*?<\/w:docVars>/g, '')
            .replace(/<w:mailMerge\b[^>]*\/>|<w:mailMerge\b[^>]*>[\s\S]*?<\/w:mailMerge>/g, '')
            .replace(/<author>(?:[^<]|<!\[CDATA\[[\s\S]*?\]\]>)*<\/author>/g, '<author></author>')
            .replace(TAG, scrubTag);
    }

    // Checks run over the whole scrubbed part, text included, so anything the
    // tag scrubber missed (odd quoting, a CDATA section) fails closed.
    var LEFTOVERS = [
        new RegExp('\\s(?:[A-Za-z0-9]+:)?' + WHO + '\\s*=\\s*(?:"[^"]+"|\'[^\']+\')'),
        new RegExp('<(?:[A-Za-z0-9]+:)?(?:cmAuthor|author|userInfo)\\b[^>]*\\sname\\s*=\\s*(?:"[^"]+"|\'[^\']+\')'),
        /\s[A-Za-z0-9]+:rsid[A-Za-z]*\s*=/,
        /<w:rsids\b|<w:docVars\b|<w:mailMerge\b|<w\d*:docId\b|<xr:revisionPtr\b/,
        /<author>(?!<\/author>)/,
        /<x15ac:absPath\b[^>]*\surl\s*=\s*(?:"[^"]+"|'[^']+')/,
        /\s(?:odcFile|sourceFile)\s*=\s*(?:"[^"]+"|'[^']+')/,
        /<dbPr\b[^>]*\sconnection\s*=\s*(?:"[^"]+"|'[^']+')/
    ];
    var RE_DATE_VALUE = new RegExp('\\s(?:[A-Za-z0-9]+:)?' + DATE_ATTR + '\\s*=\\s*["\'](\\d{4}-[^"\']*)', 'g');

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

    // Lower-cased names of the core, extended and custom property parts:
    // the usual docProps/ paths plus wherever _rels/.rels points.
    async function propertyParts(entries, budget) {
        var parts = Object.assign({}, DEFAULT_PROPERTY_PARTS);
        for (var i = 0; i < entries.length; i++) {
            if (entries[i].name.toLowerCase() !== '_rels/.rels') continue;
            var rels = decodeUtf8(await readEntry(entries[i], budget), entries[i].name);
            var tags = rels.match(/<Relationship\b(?:[^>"']|"[^"]*"|'[^']*')*>/g) || [];
            for (var t = 0; t < tags.length; t++) {
                var type = /\sType\s*=\s*["']([^"']*)/.exec(tags[t]);
                var target = /\sTarget\s*=\s*["']([^"']*)/.exec(tags[t]);
                if (!type || !target) continue;
                for (var k = 0; k < PROPERTY_REL_TYPES.length; k++) {
                    if (PROPERTY_REL_TYPES[k][0].test(type[1])) parts[target[1].replace(/^\//, '').toLowerCase()] = PROPERTY_REL_TYPES[k][1];
                }
            }
        }
        return parts;
    }

    // New bytes for an entry, or null to copy it unchanged. Parts that may
    // hold metadata but can't be cleaned are listed in ctx.incomplete.
    async function processEntry(entry, ctx, props) {
        var name = entry.name;
        var lname = name.toLowerCase();
        if (props[lname]) return new TextEncoder().encode(PROPERTY_TEMPLATES[props[lname]]);
        if (CUSTOM_XML_ITEM.test(lname)) return new TextEncoder().encode(EMPTY_CUSTOM_XML);

        if (SCRUB_PART.test(lname)) {
            var xml = decodeUtf8(await readEntry(entry, ctx.budget), name);
            var scrubbed = scrubOfficeXml(xml);
            if (officeLeftover(scrubbed)) throw stripError('MALFORMED', 'Could not clean Office part ' + name);
            return scrubbed === xml ? null : new TextEncoder().encode(scrubbed);
        }
        if (MEDIA_PART.test(lname) || EMBEDDED_PART.test(lname)) {
            var data = await readEntry(entry, ctx.budget);
            var type = detectType(data);
            if (type) {
                var clean = type === 'jpeg' ? stripJpeg(data) : stripPng(data);
                return sameBytes(clean, data) ? null : clean;
            }
            if (EMBEDDED_PART.test(lname)) {
                // An embedded Office file (a chart's workbook, a pasted
                // document) has its own metadata: clean it the same way.
                var inner = null;
                if (isZip(data) && ctx.depth < MAX_EMBED_DEPTH) {
                    try { inner = readZip(data); } catch (e) { inner = null; }
                }
                if (inner && isOoxml(inner)) {
                    var child = { budget: ctx.budget, depth: ctx.depth + 1, incomplete: [] };
                    var cleaned = await stripOoxml(inner, child);
                    for (var i = 0; i < child.incomplete.length; i++) ctx.incomplete.push(name + '/' + child.incomplete[i]);
                    return cleaned;
                }
                ctx.incomplete.push(name); // OLE objects and other embedded files
            } else if (UNCLEANABLE_IMAGE.test(lname)) {
                ctx.incomplete.push(name);
            }
            return null;
        }
        if (VBA_PART.test(lname)) {
            ctx.incomplete.push(name);
            return null;
        }
        if (/^docprops\//.test(lname)) {
            ctx.incomplete.push(name); // an unknown property part
            return null;
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

    /**
     * Strip metadata from file bytes, detecting the type from the content
     * (never the extension). Resolves to { data: ArrayBuffer, type:
     * 'jpeg'|'png'|'office'|null, supported: bool, removedBytes: number,
     * orientation: 1-8|null, incomplete: string[] } (orientation is the value
     * that was present BEFORE stripping; incomplete lists the parts of an
     * Office file that may still hold metadata, such as embedded OLE objects
     * or TIFF images). Unsupported types are returned unchanged with
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
        if (!type) {
            var copy = (input instanceof ArrayBuffer) ? input : b.slice().buffer;
            return { data: copy, type: null, supported: false, removedBytes: 0, orientation: null, incomplete: [] };
        }
        var orientation = null;
        var incomplete = [];
        var out;
        if (type === 'office') {
            var ctx = { budget: { left: MAX_INFLATED_BYTES }, depth: 0, incomplete: incomplete };
            out = await stripOoxml(entries, ctx);
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

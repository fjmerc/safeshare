/**
 * End-to-end encryption compatible with the SafeShare web app
 * (internal/static/web/assets/crypto.js). A file encrypted here opens from its
 * share link in a browser, and a browser upload decrypts here.
 *
 * Stored blob: [12-byte random IV][AES-256-GCM ciphertext + 16-byte tag]. The
 * key never reaches the server: it travels in the share link's fragment,
 * `{base}/#/claim/{code}/key/{base64url key}`.
 *
 * The plaintext is SF02 (padded): [SF02][u32 LE name length][u64 LE data
 * length][name][data][zero padding], SF01: [SF01][u32 LE name length][name]
 * [data], or raw file bytes (legacy browser uploads). This SDK always writes
 * SF02 padded to a PADME bucket, whatever the server says about its mode.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { SafeShareError, ValidationError } from "./errors.js";

export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const KEY_LENGTH = 32;
export const CIPHERTEXT_OVERHEAD = IV_LENGTH + TAG_LENGTH;
export const ENCRYPTED_FILENAME = "encrypted.bin";
export const PAD_MIN_BYTES = 4096;
const UPLOAD_ENVELOPE_SLACK = 4096;
const MAX_FILENAME_BYTES = 1024;
const V2_FIXED_HEADER = 16;
/** What an encrypted upload or download may hold in memory (Node's Buffer limit is lower on some builds). */
export const MAX_ENCRYPTED_PAYLOAD = 2 ** 32;

const MAGIC_V1 = Buffer.from("SF01");
const MAGIC_V2 = Buffer.from("SF02");
const CLAIM_CODE = /^[A-Za-z0-9_-]{8,32}$/;
const FRAGMENT = /^#\/claim\/([^/]+)\/key\/(.+)$/;

/** The key is wrong or the file was changed. */
export class DecryptionError extends SafeShareError {
  constructor(message = "File data is corrupted or the key is wrong") {
    super(message);
    this.name = "DecryptionError";
  }
}

/** A decrypted payload has a malformed header. */
export class InvalidPayloadError extends SafeShareError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPayloadError";
  }
}

/** The file doesn't fit under the server's limit once encrypted. */
export class PayloadTooLargeError extends SafeShareError {
  constructor(message: string) {
    super(message);
    this.name = "PayloadTooLargeError";
  }
}

/** An encrypted upload to a Ghost server was refused: the file may contain metadata neither the SDK nor the server can remove. */
export class MetadataNotRemovedError extends SafeShareError {
  constructor(message: string) {
    super(message);
    this.name = "MetadataNotRemovedError";
  }
}

/** The server only accepts files encrypted before upload. */
export class ClientEncryptionRequiredError extends SafeShareError {
  constructor(message = "This server only accepts files encrypted before upload") {
    super(message);
    this.name = "ClientEncryptionRequiredError";
  }
}

/** PADME padded length (Nikitin et al., PETS 2019): at most ~12% overhead. */
export function padmeLength(n: number): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("Length must be a non-negative integer");
  if (n < 2) return n;
  const big = BigInt(n);
  const e = big.toString(2).length - 1;
  const s = e.toString(2).length;
  const lastBits = e - s;
  if (lastBits <= 0) return n;
  const mask = (1n << BigInt(lastBits)) - 1n;
  return Number((big + mask) & ~mask);
}

/** Padded payload size for n unpadded bytes, capped so payload + overhead stays under maxStored (0 = no limit). */
export function paddedPayloadLength(n: number, maxStored = 0): number {
  let target = Math.max(padmeLength(n), PAD_MIN_BYTES);
  if (maxStored > 0) {
    const hardCap = maxStored - CIPHERTEXT_OVERHEAD;
    if (n > hardCap) {
      throw new PayloadTooLargeError(
        `File is too large to upload encrypted: the server limit is ${maxStored} bytes including ${CIPHERTEXT_OVERHEAD} bytes of encryption overhead`
      );
    }
    target = Math.min(target, Math.max(hardCap - UPLOAD_ENVELOPE_SLACK, n));
  }
  return target;
}

function nameBytes(name: string): Buffer {
  const b = Buffer.from(name, "utf8");
  return b.length > MAX_FILENAME_BYTES ? b.subarray(0, MAX_FILENAME_BYTES) : b;
}

/** Frame data as SF02 (pad) or, without padding, SF01 (with a name) / raw (no name). */
export function wrapPayload(name: string, data: Uint8Array, pad = true, maxStored = 0): Buffer {
  const nb = nameBytes(name);
  if (pad) {
    const used = V2_FIXED_HEADER + nb.length + data.length;
    const out = Buffer.alloc(paddedPayloadLength(used, maxStored)); // zero-filled: the padding
    MAGIC_V2.copy(out, 0);
    out.writeUInt32LE(nb.length, 4);
    out.writeBigUInt64LE(BigInt(data.length), 8);
    nb.copy(out, V2_FIXED_HEADER);
    out.set(data, V2_FIXED_HEADER + nb.length);
    return out;
  }
  let out: Buffer;
  if (nb.length > 0) {
    out = Buffer.alloc(8 + nb.length + data.length);
    MAGIC_V1.copy(out, 0);
    out.writeUInt32LE(nb.length, 4);
    nb.copy(out, 8);
    out.set(data, 8 + nb.length);
  } else {
    out = Buffer.from(data);
  }
  if (maxStored > 0 && out.length > maxStored - CIPHERTEXT_OVERHEAD) {
    throw new PayloadTooLargeError(`File is too large to upload encrypted: the server limit is ${maxStored} bytes`);
  }
  return out;
}

export interface UnwrappedPayload {
  filename: string | null;
  data: Buffer;
  version: number;
}

const decoder = new TextDecoder();

/** Remove SF02/SF01 framing. Malformed SF02 throws; data without a magic, or with a corrupt SF01 header, is returned as is. */
export function unwrapPayload(b: Buffer): UnwrappedPayload {
  if (b.length >= 4 && b.subarray(0, 4).equals(MAGIC_V2)) {
    if (b.length < V2_FIXED_HEADER) throw new InvalidPayloadError("Payload header is truncated");
    const nameLen = b.readUInt32LE(4);
    const dataLen = b.readBigUInt64LE(8);
    if (nameLen > MAX_FILENAME_BYTES) throw new InvalidPayloadError("Payload filename length is invalid");
    const start = V2_FIXED_HEADER + nameLen;
    if (dataLen > BigInt(b.length - start)) throw new InvalidPayloadError("Payload length exceeds the decrypted size");
    const end = start + Number(dataLen);
    for (let i = end; i < b.length; i++) {
      if (b[i] !== 0) throw new InvalidPayloadError("Payload padding is invalid");
    }
    return {
      filename: nameLen > 0 ? decoder.decode(b.subarray(V2_FIXED_HEADER, start)) : null,
      data: b.subarray(start, end),
      version: 2,
    };
  }
  if (b.length < 8 || !b.subarray(0, 4).equals(MAGIC_V1)) return { filename: null, data: b, version: 1 };
  const nameLen = b.readUInt32LE(4);
  if (nameLen === 0 || nameLen > MAX_FILENAME_BYTES || nameLen + 8 > b.length) {
    return { filename: null, data: b, version: 1 };
  }
  return { filename: decoder.decode(b.subarray(8, 8 + nameLen)), data: b.subarray(8 + nameLen), version: 1 };
}

/** A downloaded end-to-end encrypted file after decryption. `filename` comes from the uploader: pass it through safeFilename() before saving. */
export interface DecryptedFile {
  filename: string;
  data: Buffer;
}

/** Unframe a download the way the web app does (stored name "encrypted.bin" means framed). */
export function unwrapDownload(plaintext: Buffer, storedName: string): DecryptedFile {
  if (storedName === ENCRYPTED_FILENAME) {
    const p = unwrapPayload(plaintext);
    return { filename: p.filename || storedName, data: p.data };
  }
  if (plaintext.length >= 4 && plaintext.subarray(0, 4).equals(MAGIC_V2)) {
    try {
      return { filename: storedName, data: unwrapPayload(plaintext).data };
    } catch {
      // not a valid padded payload: a raw file that happens to start with SF02
    }
  }
  return { filename: storedName, data: plaintext };
}

/** A new random 256-bit key, base64url without padding. */
export function generateKey(): string {
  return randomBytes(KEY_LENGTH).toString("base64url");
}

export function decodeKey(key: string): Buffer {
  const s = key.trim().replace(/=+$/, "");
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new ValidationError("Invalid encryption key");
  const raw = Buffer.from(s, "base64url");
  if (raw.length !== KEY_LENGTH) throw new ValidationError("Invalid encryption key");
  return raw;
}

/** [IV][AES-256-GCM(payload)][tag]; a fresh random IV unless given (tests). */
export function encryptBlob(key: Buffer, payload: Uint8Array, iv: Buffer = randomBytes(IV_LENGTH)): Buffer {
  if (iv.length !== IV_LENGTH) throw new RangeError("IV must be 12 bytes");
  const c = createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, c.update(payload), c.final(), c.getAuthTag()]);
}

export function decryptBlob(key: Buffer, blob: Buffer): Buffer {
  if (blob.length < IV_LENGTH + TAG_LENGTH) throw new DecryptionError();
  try {
    const d = createDecipheriv("aes-256-gcm", key, blob.subarray(0, IV_LENGTH));
    d.setAuthTag(blob.subarray(blob.length - TAG_LENGTH));
    return Buffer.concat([d.update(blob.subarray(IV_LENGTH, blob.length - TAG_LENGTH)), d.final()]);
  } catch {
    throw new DecryptionError();
  }
}

/** The link the web app opens to download and decrypt a file. */
export function buildShareUrl(baseUrl: string, claimCode: string, key: string): string {
  return `${baseUrl.replace(/\/$/, "")}/#/claim/${claimCode}/key/${key}`;
}

export interface ShareLink {
  baseUrl: string;
  claimCode: string;
  key: string;
}

/** Parse an encrypted share link (keeps any path prefix of the server; drops credentials and query). */
export function parseShareUrl(link: string): ShareLink {
  let u: URL;
  try {
    u = new URL(link.trim());
  } catch {
    throw new ValidationError("The link must be an http(s) share link");
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname) {
    throw new ValidationError("The link must be an http(s) share link");
  }
  const m = FRAGMENT.exec(u.hash);
  if (!m) throw new ValidationError("The link has no #/claim/<code>/key/<key> part; it is not an encrypted share link");
  if (!CLAIM_CODE.test(m[1])) throw new ValidationError("The link's claim code is invalid");
  decodeKey(m[2]);
  return { baseUrl: `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, "")}`, claimCode: m[1], key: m[2] };
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** Name of the file type when it is one the web app cleans of metadata before encrypting, else null. */
export function metadataFileType(b: Buffer): string | null {
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "JPEG image";
  if (b.length >= 8 && b.subarray(0, 8).equals(PNG)) return "PNG image";
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4 &&
      b.toString("latin1").toLowerCase().includes("[content_types].xml")) {
    return "Office document";
  }
  const head = b.subarray(0, 1024 * 1024).toString("latin1");
  const tail = b.subarray(Math.max(0, b.length - 2048)).toString("latin1");
  if (head.includes("%PDF-") || (tail.includes("startxref") && tail.includes("%%EOF"))) return "PDF";
  return null;
}

const WINDOWS_RESERVED = new Set(["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]);
for (const p of ["COM", "LPT"]) for (let d = 0; d <= 9; d++) WINDOWS_RESERVED.add(`${p}${d}`);

/**
 * Turn an uploader-supplied filename into a plain name that is safe to create
 * in the current directory: no directories, control or invisible formatting
 * characters, leading dots (hidden files), Windows-reserved characters or
 * device names; at most 255 bytes.
 */
export function safeFilename(name: string, fallback = "download.bin"): string {
  name = name.replace(/\\/g, "/");
  name = name.slice(name.lastIndexOf("/") + 1);
  name = name.replace(/[\p{Cc}\p{Cf}�]/gu, "").replace(/[<>:"|?*]/g, "_");
  name = name.replace(/^[ .]+|[ .]+$/g, "");
  if (Buffer.byteLength(name) > 255) {
    const dot = name.lastIndexOf(".");
    let ext = dot > 0 ? name.slice(dot) : "";
    if (Buffer.byteLength(ext) > 16) ext = "";
    let stem = Array.from(ext ? name.slice(0, dot) : name);
    while (Buffer.byteLength(stem.join("") + ext) > 255) stem.pop();
    name = stem.join("").replace(/[ .]+$/, "") + ext;
  }
  if (!name || name === "." || name === "..") return fallback;
  if (WINDOWS_RESERVED.has(name.split(".")[0].replace(/ +$/, "").toUpperCase())) name = "_" + name;
  return name;
}

/**
 * End-to-end encryption tests: interop vectors generated from the web app's
 * crypto.js (sdk/testdata/e2e-vectors.json, see tests/js/e2e-vectors.test.js),
 * plus upload/download round trips against a fake server.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, mkdtempSync, writeFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { SafeShareClient } from "../src/client.js";
import * as e2e from "../src/e2e.js";
import { DownloadError } from "../src/errors.js";

const VECTORS = JSON.parse(readFileSync(resolve(__dirname, "../../testdata/e2e-vectors.json"), "utf8"));
const KEY = e2e.decodeKey(VECTORS.key);
const IV = Buffer.from(VECTORS.iv, "hex");
const BASE = "https://share.example.com";
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("vectors from the web app's crypto.js", () => {
  it("constants", () => {
    expect(VECTORS.constants).toEqual({ pad_min_bytes: e2e.PAD_MIN_BYTES, ciphertext_overhead: e2e.CIPHERTEXT_OVERHEAD });
  });

  it("padme", () => {
    for (const c of VECTORS.padme) expect(e2e.padmeLength(c.n)).toBe(c.padded);
  });

  it("padded length", () => {
    for (const c of VECTORS.padded_length) {
      if (c.error) expect(() => e2e.paddedPayloadLength(c.n, c.max_stored)).toThrow(e2e.PayloadTooLargeError);
      else expect(e2e.paddedPayloadLength(c.n, c.max_stored)).toBe(c.padded);
    }
  });

  it("wrap", () => {
    for (const c of VECTORS.wrap) {
      const data = Buffer.from(c.data, "hex");
      const pad = c.format === "SF02";
      if (c.error) {
        expect(() => e2e.wrapPayload(c.name, data, pad, c.max_stored ?? 0), c.id).toThrow(e2e.PayloadTooLargeError);
      } else {
        expect(hex(e2e.wrapPayload(c.name, data, pad, c.max_stored ?? 0)), c.id).toBe(c.payload);
      }
    }
  });

  it("unwrap", () => {
    for (const c of VECTORS.unwrap) {
      const payload = Buffer.from(c.payload, "hex");
      if (c.error) {
        expect(() => e2e.unwrapPayload(payload), c.id).toThrow(e2e.InvalidPayloadError);
        continue;
      }
      const got = e2e.unwrapPayload(payload);
      expect([got.filename, hex(got.data), got.version], c.id).toEqual([c.filename, c.data, c.version]);
    }
  });

  it("encrypt and decrypt", () => {
    for (const c of VECTORS.encrypt) {
      const payload = Buffer.from(c.payload, "hex");
      expect(hex(e2e.encryptBlob(KEY, payload, IV)), c.id).toBe(c.blob);
      expect(hex(e2e.decryptBlob(KEY, Buffer.from(c.blob, "hex"))), c.id).toBe(c.payload);
    }
    for (const c of VECTORS.decrypt_fails) {
      expect(() => e2e.decryptBlob(KEY, Buffer.from(c.blob, "hex")), c.id).toThrow(e2e.DecryptionError);
    }
  });

  it("share url", () => {
    for (const c of VECTORS.share_url) {
      expect(e2e.buildShareUrl(c.base, c.claim_code, c.key)).toBe(c.url);
      const link = e2e.parseShareUrl(c.url);
      expect([link.claimCode, link.key]).toEqual([c.claim_code, c.key]);
      expect(e2e.buildShareUrl(link.baseUrl, link.claimCode, link.key)).toBe(c.url);
    }
  });
});

describe("e2e helpers", () => {
  it("padme matches a dense reference", () => {
    const ref = (n: number) => {
      if (n < 2) return n;
      const e = Math.floor(Math.log2(n));
      const z = e - e.toString(2).length;
      if (z <= 0) return n;
      const u = 2 ** z;
      return Math.ceil(n / u) * u;
    };
    for (let n = 0; n < 70000; n++) expect(e2e.padmeLength(n)).toBe(ref(n));
  });

  it("rejects bad share links and drops credentials", () => {
    for (const link of [
      "",
      `ftp://h.example/#/claim/abcdefgh/key/${VECTORS.key}`,
      "https://h.example/#/claim/abcdefgh",
      `https://h.example/#/claim/abc/key/${VECTORS.key}`,
      "https://h.example/#/claim/abcdefgh/key/short",
      `https://h.example/#/claim/abcdefgh/key/${VECTORS.key}AA`,
    ]) {
      expect(() => e2e.parseShareUrl(link), link).toThrow();
    }
    const l = e2e.parseShareUrl(`https://share.example.com@evil.example:8443/p/?x=1#/claim/abcdefgh/key/${VECTORS.key}`);
    expect(l.baseUrl).toBe("https://evil.example:8443/p");
  });

  it("safeFilename", () => {
    const cases: Array<[string, string]> = [
      ["report.pdf", "report.pdf"],
      ["../../etc/passwd", "passwd"],
      ["..\\..\\boot.ini", "boot.ini"],
      ["..", "fallback"],
      ["", "fallback"],
      [".bash_profile", "bash_profile"],
      ["CON", "_CON"],
      ["nul.txt", "_nul.txt"],
      ["a.txt:evil", "a.txt_evil"],
      ["trail. ", "trail"],
      ["invoice‮txt.exe", "invoicetxt.exe"],
      ["bell\x07\nname.txt", "bellname.txt"],
      ["naïve 日本語.txt", "naïve 日本語.txt"],
      ["é".repeat(200) + ".txt", "é".repeat(125) + ".txt"],
    ];
    for (const [name, want] of cases) expect(e2e.safeFilename(name, "fallback"), name).toBe(want);
  });

  it("metadataFileType scans big zips in place", () => {
    const big = Buffer.alloc(64 * 1024 * 1024);
    big.write("PK\x03\x04", 0, "latin1");
    big.write("[Content_Types].XML", big.length - 100, "latin1");
    expect(e2e.metadataFileType(big)).toBe("Office document");
  });

  it("metadataFileType", () => {
    expect(e2e.metadataFileType(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0]))).toBe("JPEG image");
    expect(e2e.metadataFileType(Buffer.from("PK\x03\x04...[Content_Types].XML", "latin1"))).toBe("Office document");
    expect(e2e.metadataFileType(Buffer.from("PK\x03\x04 plain zip", "latin1"))).toBeNull();
    expect(e2e.metadataFileType(Buffer.concat([Buffer.alloc(5000, 32), Buffer.from("%PDF-1.7")]))).toBe("PDF");
    expect(e2e.metadataFileType(Buffer.from("hello"))).toBeNull();
  });

  it("unwrapDownload matches the web app", () => {
    const sf02 = e2e.wrapPayload("inner.txt", Buffer.from("body"));
    const sf01 = e2e.wrapPayload("inner.txt", Buffer.from("body"), false);
    const bad = Buffer.concat([sf02.subarray(0, -1), Buffer.from([1])]);
    expect(e2e.unwrapDownload(sf02, "encrypted.bin")).toEqual({ filename: "inner.txt", data: Buffer.from("body") });
    expect(e2e.unwrapDownload(sf01, "encrypted.bin")).toEqual({ filename: "inner.txt", data: Buffer.from("body") });
    expect(() => e2e.unwrapDownload(bad, "encrypted.bin")).toThrow(e2e.InvalidPayloadError);
    expect(e2e.unwrapDownload(sf02, "v.txt")).toEqual({ filename: "v.txt", data: Buffer.from("body") });
    expect(e2e.unwrapDownload(bad, "v.txt").data.equals(bad)).toBe(true);
    expect(e2e.unwrapDownload(sf01, "v.txt").data.equals(sf01)).toBe(true);
  });
});

// ---- client round trips against a fake server ----

const GHOST = {
  max_file_size: 1 << 20, chunked_upload_threshold: 1 << 20, chunk_size: 1000, max_expiration_hours: 168,
  registration_enabled: false, anonymous_mode: true, client_encryption_required: true, strip_metadata: true,
};
const PLAIN = { ...GHOST, anonymous_mode: false, client_encryption_required: false, strip_metadata: false };

function fakeServer(config: Record<string, unknown>) {
  const state = {
    stored: Buffer.alloc(0), name: "", requests: [] as Array<{ url: string; init: RequestInit }>,
    chunks: [] as Buffer[], init: {} as Record<string, unknown>, infoSize: undefined as number | undefined,
  };
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl = (async (input: string | URL, init: RequestInit = {}) => {
    const url = new URL(String(input));
    state.requests.push({ url: url.pathname, init });
    const p = url.pathname;
    if (p === "/api/config") return json(config);
    if (p === "/api/upload") {
      const form = init.body as FormData;
      const file = form.get("file") as File;
      state.stored = Buffer.from(await file.arrayBuffer());
      state.name = file.name;
      return json({ claim_code: "Claim1234", original_filename: file.name, file_size: state.stored.length });
    }
    if (p === "/api/upload/init") {
      state.init = JSON.parse(String(init.body));
      state.chunks = [];
      const size = state.init.total_size as number;
      return json({ upload_id: "0123abcd-0000-4000-8000-000000000000", chunk_size: 1000, total_chunks: Math.ceil(size / 1000) });
    }
    if (p.startsWith("/api/upload/chunk/")) {
      const f = (init.body as FormData).get("chunk") as Blob;
      state.chunks.push(Buffer.from(await f.arrayBuffer()));
      return json({});
    }
    if (p.startsWith("/api/upload/complete/")) {
      state.stored = Buffer.concat(state.chunks);
      state.name = state.init.filename as string;
      return json({ claim_code: "Claim1234", original_filename: state.name, file_size: state.stored.length });
    }
    if (p === "/api/claim/Claim1234/info") {
      return json({ claim_code: "Claim1234", original_filename: state.name, file_size: state.infoSize ?? state.stored.length, client_encrypted: true });
    }
    if (p === "/api/claim/Claim1234") return new Response(new Uint8Array(state.stored));
    return json({ error: "not found" }, 404);
  }) as unknown as typeof fetch;
  return { state, client: new SafeShareClient({ baseUrl: BASE, fetch: fetchImpl }) };
}

function tempFile(name: string, data: Buffer | string): string {
  const dir = mkdtempSync(join(tmpdir(), "ss-e2e-"));
  const p = join(dir, name);
  writeFileSync(p, data);
  return p;
}

describe("encrypted uploads and downloads", () => {
  it("ghost upload is encrypted, padded, hides the name and round-trips", async () => {
    const { state, client } = fakeServer(GHOST);
    const res = await client.upload(tempFile("notes.txt", "secret notes"));
    expect(res.encrypted).toBe(true);
    expect(res.filename).toBe("notes.txt");
    expect(res.shareUrl).toBe(e2e.buildShareUrl(BASE, "Claim1234", res.encryptionKey!));
    expect(JSON.stringify(res)).not.toContain(res.encryptionKey!);
    expect(JSON.stringify({ ...res })).not.toContain(res.encryptionKey!);
    expect(state.name).toBe("encrypted.bin");
    expect(state.stored.includes("secret notes")).toBe(false);
    expect(state.stored.length).toBe(e2e.PAD_MIN_BYTES + e2e.CIPHERTEXT_OVERHEAD);
    const up = state.requests.find((r) => r.url === "/api/upload")!;
    expect((up.init.headers as Record<string, string>)["X-SafeShare-Client-Encrypted"]).toBe("true");
    expect((up.init.body as FormData).get("client_encrypted")).toBe("true");
    expect(up.init.redirect).toBe("follow"); // no token: nothing to leak on a redirect

    const f = await client.downloadDecrypted("Claim1234", res.encryptionKey!);
    expect([f.filename, f.data.toString()]).toEqual(["notes.txt", "secret notes"]);

    const dest = join(mkdtempSync(join(tmpdir(), "ss-out-")), "out.txt");
    await client.download("Claim1234", dest, { decryptionKey: res.encryptionKey });
    expect(readFileSync(dest, "utf8")).toBe("secret notes");
    expect(statSync(dest).mode & 0o777).toBe(0o600);
    const before = state.requests.length;
    await expect(client.download("Claim1234", dest, { decryptionKey: res.encryptionKey })).rejects.toThrow(DownloadError);
    expect(state.requests.length).toBe(before);
    await client.download("Claim1234", dest, { decryptionKey: res.encryptionKey, overwrite: true });
    expect(existsSync(dest)).toBe(true);

    await expect(client.downloadDecrypted("Claim1234", e2e.generateKey())).rejects.toThrow(e2e.DecryptionError);
  });

  it("chunked encrypted upload sends the flag at init", async () => {
    const { state, client } = fakeServer({ ...GHOST, chunked_upload_threshold: 2000 });
    const body = Buffer.from("0123456789".repeat(900));
    const res = await client.upload(tempFile("big.log", body), { showFilename: true });
    expect(state.init.client_encrypted).toBe(true);
    expect(state.init.filename).toBe("big.log");
    expect(state.chunks.length).toBeGreaterThan(1);
    expect(state.stored.length).toBe(e2e.padmeLength(16 + 9000) + e2e.CIPHERTEXT_OVERHEAD);
    const f = await client.downloadDecrypted("Claim1234", res.encryptionKey!);
    expect(f.filename).toBe("big.log");
    expect(f.data.equals(body)).toBe(true);
  });

  it("ghost refuses metadata files unless keepMetadata", async () => {
    const { state, client } = fakeServer(GHOST);
    const jpg = tempFile("photo.jpg", Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x45]));
    await expect(client.upload(jpg)).rejects.toThrow(e2e.MetadataNotRemovedError);
    expect(state.stored.length).toBe(0);
    const res = await client.upload(jpg, { keepMetadata: true });
    expect(res.metadataKept).toBe("JPEG image");
  });

  it("never fails on a required server; plain server: auto unencrypted, always encrypts", async () => {
    const g = fakeServer(GHOST);
    await expect(g.client.upload(tempFile("a.txt", "x"), { encrypt: "never" })).rejects.toThrow(e2e.ClientEncryptionRequiredError);
    const { state, client } = fakeServer(PLAIN);
    const p = tempFile("a.txt", "do not reveal");
    const plain = await client.upload(p);
    expect(plain.encrypted).toBeUndefined();
    expect(state.stored.toString()).toBe("do not reveal");
    await client.upload(p, { encrypt: "always" });
    expect(state.stored.includes("do not reveal")).toBe(false);
    expect(state.stored.length).toBe(e2e.PAD_MIN_BYTES + e2e.CIPHERTEXT_OVERHEAD);
  });

  it("refuses a huge reported size before downloading", async () => {
    const { state, client } = fakeServer(GHOST);
    state.name = "encrypted.bin";
    state.infoSize = 2 ** 50;
    await expect(client.downloadDecrypted("Claim1234", e2e.generateKey())).rejects.toThrow(DownloadError);
    expect(state.requests.some((r) => r.url === "/api/claim/Claim1234")).toBe(false);
  });
});

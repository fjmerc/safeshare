/**
 * SafeShare SDK Client
 *
 * Main client class for interacting with the SafeShare API.
 */

import { createReadStream, statSync } from "node:fs";
import { writeFile, mkdir, open as openFile, readFile, rename, unlink, lstat } from "node:fs/promises";
import { dirname, resolve, basename, join } from "node:path";
import { randomBytes } from "node:crypto";

import * as e2e from "./e2e.js";

import type {
  ClientOptions,
  UploadResult,
  UploadOptions,
  ChunkUploadResult,
  UploadStatus,
  FileInfo,
  ScanStatus,
  UserFilesResponse,
  DownloadOptions,
  UpdateExpirationOptions,
  RenameResult,
  ExpirationResult,
  RegenerateResult,
  PublicConfig,
  EncryptMode,
  CreateTokenRequest,
  TokenCreatedResponse,
  TokenInfo,
} from "./types.js";

import {
  SafeShareError,
  ValidationError,
  DownloadError,
  ChunkedUploadError,
  UploadError,
  RateLimitError,
  handleErrorResponse,
} from "./errors.js";

// Validation patterns
// Server uses base64 URL-safe encoding which includes - and _ characters
const CLAIM_CODE_PATTERN = /^[a-zA-Z0-9_-]{8,32}$/;
// Standard UUID v4 pattern (8-4-4-4-12 format)
const UPLOAD_ID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const FILENAME_MAX_LENGTH = 255;

// Derived from the fetch signature so the SDK typechecks against whichever
// fetch globals the consumer's @types/node (or DOM lib) provides —
// HeadersInit/BodyInit themselves are not global in all @types/node versions.
type FetchRequestBody = NonNullable<Parameters<typeof fetch>[1]>["body"];

/**
 * SafeShare API Client
 *
 * @example
 * ```typescript
 * const client = new SafeShareClient({
 *   baseUrl: "https://share.example.com",
 *   apiToken: "safeshare_abc123...",
 * });
 *
 * // Upload a file
 * const result = await client.upload("/path/to/file.txt", {
 *   expiresInHours: 24,
 * });
 * console.log(`Claim code: ${result.claimCode}`);
 * ```
 */
/** Bounds on the wait after a rate-limited status poll (ms). */
export const RATE_LIMIT_POLL_WAIT = { min: 15_000, max: 60_000 };

/**
 * How long to wait after the status endpoint answers 429 (T52): the
 * server's Retry-After, clamped to the same 15-60 s range the web uploader
 * uses.
 */
export function rateLimitPollDelay(error: RateLimitError): number {
  const retryAfterMs = (error.retryAfter ?? 0) * 1000;
  return Math.min(Math.max(retryAfterMs, RATE_LIMIT_POLL_WAIT.min), RATE_LIMIT_POLL_WAIT.max);
}

/**
 * Normalize a server download limit. Chunked-upload responses encode
 * "unlimited" as 0 rather than null.
 */
/** What is sent as the uploaded file: a file on disk or an encrypted blob in memory. */
interface UploadSource {
  name: string;
  size: number;
  path?: string;
  data?: Buffer;
}

/** Iterate a source in chunks (the stream's own chunks for files). */
async function* sourceChunks(src: UploadSource, chunkSize?: number): AsyncGenerator<Buffer> {
  if (src.data) {
    const step = chunkSize ?? (src.data.length || 1);
    for (let i = 0; i < src.data.length; i += step) yield src.data.subarray(i, i + step);
    return;
  }
  for await (const chunk of createReadStream(src.path!, chunkSize ? { highWaterMark: chunkSize } : {})) {
    yield Buffer.from(chunk);
  }
}

/**
 * Write data with mode 0600. Without overwrite the file must not exist
 * ("wx" also refuses a symlink); with it, a temp file is renamed over the
 * destination so a symlink there is replaced, not followed.
 */
async function writePrivate(path: string, data: Buffer, overwrite: boolean): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  if (!overwrite) {
    const fh = await openFile(path, "wx", 0o600);
    try {
      await fh.writeFile(data);
    } finally {
      await fh.close();
    }
    return;
  }
  const tmp = join(dirname(path), `.safeshare-${randomBytes(6).toString("hex")}.tmp`);
  try {
    const fh = await openFile(tmp, "wx", 0o600);
    try {
      await fh.writeFile(data);
    } finally {
      await fh.close();
    }
    await rename(tmp, path);
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}

function positiveOrNull(limit: number | null | undefined): number | null {
  return limit !== null && limit !== undefined && limit > 0 ? limit : null;
}

export class SafeShareClient {
  private readonly baseUrl: string;
  private readonly apiToken?: string;
  private readonly timeout: number;
  private readonly fetchImpl: typeof fetch;
  private configCache?: PublicConfig;

  constructor(options: ClientOptions) {
    // Validate and parse the base URL
    if (!options.baseUrl) {
      throw new ValidationError("baseUrl is required");
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(options.baseUrl);
    } catch {
      throw new ValidationError("baseUrl must be a valid URL");
    }

    // Validate URL scheme - only allow http/https
    if (!parsedUrl.protocol.match(/^https?:$/)) {
      throw new ValidationError("baseUrl must use http or https protocol");
    }

    // Warn about insecure HTTP in production
    if (parsedUrl.protocol === "http:" && typeof process !== "undefined" && process.env?.NODE_ENV === "production") {
      console.warn(
        "[SafeShare SDK] WARNING: Using HTTP in production is insecure. " +
        "API tokens and passwords will be transmitted unencrypted."
      );
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiToken = options.apiToken;
    this.timeout = options.timeout ?? 300_000; // 5 minutes default
    this.fetchImpl = options.fetch ?? fetch;
  }

  /**
   * Custom string representation that redacts the API token
   */
  toString(): string {
    const tokenDisplay = this.apiToken ? "***redacted***" : "none";
    return `SafeShareClient(baseUrl="${this.baseUrl}", apiToken=${tokenDisplay})`;
  }

  // ===========================================================================
  // Validation Methods
  // ===========================================================================

  private validateClaimCode(claimCode: string): void {
    if (!claimCode || !CLAIM_CODE_PATTERN.test(claimCode)) {
      throw new ValidationError(
        "Invalid claim code format. Must be 8-32 alphanumeric characters (including - and _)."
      );
    }
  }

  private validateUploadId(uploadId: string): void {
    if (!uploadId || !UPLOAD_ID_PATTERN.test(uploadId)) {
      throw new ValidationError(
        "Invalid upload ID format. Must be a valid UUID."
      );
    }
  }

  private validateTokenId(tokenId: number): void {
    if (!Number.isInteger(tokenId) || tokenId < 1) {
      throw new ValidationError("tokenId must be a positive integer");
    }
  }

  private validateFilename(filename: string): void {
    if (!filename || filename.length > FILENAME_MAX_LENGTH) {
      throw new ValidationError(
        `Invalid filename. Must be 1-${FILENAME_MAX_LENGTH} characters, got length: ${filename?.length ?? 0}`
      );
    }
    // Check for path traversal
    if (filename.includes("..") || filename.includes("/") || filename.includes("\\")) {
      throw new ValidationError("Filename cannot contain path components");
    }
  }

  // ===========================================================================
  // HTTP Helper Methods
  // ===========================================================================

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.apiToken) {
      headers["Authorization"] = `Bearer ${this.apiToken}`;
    }
    return headers;
  }

  /**
   * Headers for a claim download: auth headers plus the file password, if
   * any, in X-File-Password (the ?password= query parameter is deprecated
   * because URLs end up in proxy logs and history).
   */
  private downloadHeaders(password?: string): Record<string, string> {
    const headers = this.getHeaders();
    if (password) {
      headers["X-File-Password"] = password;
    }
    return headers;
  }

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: FetchRequestBody;
      headers?: Record<string, string>;
      timeout?: number;
    } = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      options.timeout ?? this.timeout
    );

    try {
      const response = await this.fetchImpl(url, {
        method,
        headers: {
          ...this.getHeaders(),
          ...options.headers,
        },
        body: options.body,
        // Following a redirect could send the token to another host.
        redirect: this.apiToken ? "error" : "follow",
        signal: controller.signal,
      });

      if (!response.ok) {
        await handleErrorResponse(response);
      }

      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json")) {
        return (await response.json()) as T;
      }

      return (await response.text()) as unknown as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ===========================================================================
  // Configuration
  // ===========================================================================

  /**
   * Get public server configuration
   *
   * @returns Server configuration including upload limits
   */
  async getConfig(): Promise<PublicConfig> {
    if (this.configCache) {
      return this.configCache;
    }

    const response = await this.request<{
      max_file_size: number;
      chunked_upload_threshold: number;
      chunk_size: number;
      max_expiration_hours: number;
      registration_enabled: boolean;
      anonymous_mode?: boolean;
      client_encryption_required?: boolean;
      strip_metadata?: boolean;
    }>("GET", "/api/config");

    this.configCache = {
      maxFileSize: response.max_file_size,
      chunkUploadThreshold: response.chunked_upload_threshold,
      chunkSize: response.chunk_size,
      maxExpirationHours: response.max_expiration_hours,
      registrationEnabled: response.registration_enabled,
      anonymousMode: !!response.anonymous_mode,
      clientEncryptionRequired: !!response.client_encryption_required,
      stripMetadata: !!response.strip_metadata,
    };

    return this.configCache;
  }

  // ===========================================================================
  // File Upload
  // ===========================================================================

  /**
   * Upload a file to SafeShare
   *
   * Automatically uses chunked upload for large files based on server config.
   *
   * With `encrypt` "auto" (the default) the file is encrypted on this machine
   * when the server is in Ghost mode or requires client-side encryption; the
   * result's `shareUrl` then carries the key. See UploadOptions.encrypt.
   *
   * @param filePath - Path to the file to upload
   * @param options - Upload options (expiration, download limit, password, progress callback)
   * @returns Upload result with claim code
   */
  async upload(filePath: string, options: UploadOptions = {}): Promise<UploadResult> {
    const resolvedPath = resolve(filePath);
    const stats = statSync(resolvedPath);
    const filename = basename(resolvedPath);

    this.validateFilename(filename);

    // Get config to determine if chunked upload is needed
    const config = await this.getConfig();

    if (await this.willEncrypt(options.encrypt)) {
      return this.uploadEncrypted(resolvedPath, filename, stats.size, config, options);
    }

    const src: UploadSource = { name: filename, size: stats.size, path: resolvedPath };
    if (stats.size >= config.chunkUploadThreshold) {
      return this.uploadChunked(src, options, false);
    }

    return this.uploadSimple(src, options, false);
  }

  /**
   * Whether upload() with this encrypt mode encrypts on this server. Throws
   * ClientEncryptionRequiredError for "never" on a server that requires it.
   */
  async willEncrypt(mode: EncryptMode = "auto"): Promise<boolean> {
    if (mode !== "auto" && mode !== "always" && mode !== "never") {
      throw new ValidationError('encrypt must be "auto", "always" or "never"');
    }
    const config = await this.getConfig();
    if (mode === "always") return true;
    if (mode === "never") {
      if (config.clientEncryptionRequired) throw new e2e.ClientEncryptionRequiredError();
      return false;
    }
    return config.anonymousMode || config.clientEncryptionRequired;
  }

  /** Encrypt in memory in the web app's format, then upload the ciphertext. */
  private async uploadEncrypted(
    path: string,
    filename: string,
    size: number,
    config: PublicConfig,
    options: UploadOptions
  ): Promise<UploadResult> {
    if (size > e2e.MAX_ENCRYPTED_PAYLOAD) {
      throw new e2e.PayloadTooLargeError(
        `Encrypting holds the whole file in memory, and the limit is ${e2e.MAX_ENCRYPTED_PAYLOAD} bytes`
      );
    }
    const data = await readFile(path);
    if (data.length !== size) throw new UploadError("The file changed while it was being read");

    const kind = e2e.metadataFileType(data);
    if (kind && config.anonymousMode && config.stripMetadata && !options.keepMetadata) {
      throw new e2e.MetadataNotRemovedError(
        `This ${kind} may contain metadata (author, location, dates) and the server cannot remove it from an ` +
          "encrypted file; scrub it first, for example with mat2, or set keepMetadata"
      );
    }

    // Always padded (SF02), whatever the server says about its mode.
    const payload = e2e.wrapPayload(options.showFilename ? "" : filename, data, true, config.maxFileSize);
    data.fill(0);
    const key = e2e.generateKey();
    const rawKey = e2e.decodeKey(key);
    const blob = e2e.encryptBlob(rawKey, payload);
    payload.fill(0);
    rawKey.fill(0);

    const src: UploadSource = {
      name: options.showFilename ? filename : e2e.ENCRYPTED_FILENAME,
      size: blob.length,
      data: blob,
    };
    const result = blob.length >= config.chunkUploadThreshold
      ? await this.uploadChunked(src, options, true)
      : await this.uploadSimple(src, options, true);
    const out: UploadResult = {
      ...result,
      filename,
      encrypted: true,
      metadataKept: kind && config.stripMetadata ? kind : undefined,
    };
    // Non-enumerable, so JSON.stringify, console.log and spreads leave the key out.
    Object.defineProperties(out, {
      encryptionKey: { value: key, enumerable: false },
      shareUrl: { value: e2e.buildShareUrl(this.baseUrl, result.claimCode, key), enumerable: false },
    });
    return out;
  }

  /**
   * Simple (non-chunked) file upload
   */
  private async uploadSimple(
    src: UploadSource,
    options: UploadOptions,
    encrypted: boolean
  ): Promise<UploadResult> {
    const filename = src.name;
    const stats = { size: src.size };

    // Create form data
    const formData = new FormData();

    // Read file as buffer for FormData
    const chunks: Buffer[] = [];

    for await (const chunk of sourceChunks(src)) {
      chunks.push(chunk);
      if (options.onProgress) {
        const bytesUploaded = chunks.reduce((sum, c) => sum + c.length, 0);
        options.onProgress({
          bytesUploaded,
          totalBytes: stats.size,
          percentage: Math.round((bytesUploaded / stats.size) * 100),
        });
      }
    }

    const fileBuffer = Buffer.concat(chunks);
    const blob = new Blob([fileBuffer]);
    formData.append("file", blob, filename);

    if (options.expiresInHours !== undefined && options.expiresInHours !== null) {
      formData.append("expires_in_hours", String(options.expiresInHours));
    }
    if (options.downloadLimit !== undefined && options.downloadLimit !== null) {
      formData.append("max_downloads", String(options.downloadLimit));
    }
    if (options.password) {
      formData.append("password", options.password);
    }
    if (encrypted) {
      formData.append("client_encrypted", "true");
    }

    const response = await this.request<{
      claim_code: string;
      original_filename: string;
      file_size: number;
      mime_type: string;
      expires_at: string | null;
      max_downloads: number | null;
      user_id?: number;
    }>("POST", "/api/upload", {
      body: formData,
      headers: encrypted ? { "X-SafeShare-Client-Encrypted": "true" } : undefined,
    });

    return {
      claimCode: response.claim_code,
      filename: response.original_filename,
      size: response.file_size,
      mimeType: response.mime_type,
      expiresAt: response.expires_at,
      downloadLimit: positiveOrNull(response.max_downloads),
      passwordProtected: !!options.password, // Server does not echo this; we know it from the request
      userId: response.user_id,
    };
  }

  /**
   * Chunked file upload for large files
   */
  private async uploadChunked(
    src: UploadSource,
    options: UploadOptions,
    encrypted: boolean
  ): Promise<UploadResult> {
    const filename = src.name;
    const stats = { size: src.size };

    // Initialize chunked upload
    const initBody: Record<string, unknown> = {
      filename,
      total_size: stats.size,
    };
    if (options.expiresInHours !== undefined && options.expiresInHours !== null) {
      initBody.expires_in_hours = options.expiresInHours;
    }
    if (options.downloadLimit !== undefined && options.downloadLimit !== null) {
      initBody.max_downloads = options.downloadLimit;
    }
    if (options.password) {
      initBody.password = options.password;
    }
    if (encrypted) {
      initBody.client_encrypted = true;
    }

    const session = await this.request<{
      upload_id: string;
      chunk_size: number;
      total_chunks: number;
      expires_at: string;
    }>("POST", "/api/upload/init", {
      body: JSON.stringify(initBody),
      headers: {
        "Content-Type": "application/json",
        ...(encrypted ? { "X-SafeShare-Client-Encrypted": "true" } : {}),
      },
    });

    const uploadId = session.upload_id;
    const chunkSize = session.chunk_size;
    const totalChunks = session.total_chunks;

    try {
      // Upload chunks
      let bytesUploaded = 0;
      let chunkNumber = 0;

      for await (const chunkBuffer of sourceChunks(src, chunkSize)) {
        const chunkFormData = new FormData();
        chunkFormData.append("chunk", new Blob([new Uint8Array(chunkBuffer)]));

        await this.request<ChunkUploadResult>(
          "POST",
          `/api/upload/chunk/${uploadId}/${chunkNumber}`,
          { body: chunkFormData }
        );

        bytesUploaded += chunkBuffer.length;
        chunkNumber++;

        if (options.onProgress) {
          options.onProgress({
            bytesUploaded,
            totalBytes: stats.size,
            percentage: Math.round((bytesUploaded / stats.size) * 100),
            currentChunk: chunkNumber,
            totalChunks,
          });
        }
      }

      // Complete the upload - may return 200 (sync) or 202 (async assembly)
      const completeResult = await this.completeChunkedUpload(uploadId, filename, stats.size, !!options.password);

      return completeResult;
    } catch (error) {
      // Try to cancel the upload on error
      try {
        await this.request("DELETE", `/api/upload/cancel/${uploadId}`);
      } catch {
        // Ignore cancel errors
      }

      if (error instanceof SafeShareError) {
        throw new ChunkedUploadError(error.message, uploadId, error.statusCode, error.responseBody);
      }
      throw new ChunkedUploadError(
        error instanceof Error ? error.message : "Unknown error",
        uploadId
      );
    }
  }

  /**
   * Complete a chunked upload, handling both sync and async assembly
   */
  private async completeChunkedUpload(
    uploadId: string,
    filename: string,
    fileSize: number,
    passwordProtected: boolean
  ): Promise<UploadResult> {
    const url = `${this.baseUrl}/api/upload/complete/${uploadId}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: this.getHeaders(),
        redirect: "error",
        signal: controller.signal,
      });

      if (!response.ok) {
        await handleErrorResponse(response);
      }

      // Check if async assembly (202 Accepted)
      if (response.status === 202) {
        return this.pollForCompletion(uploadId, filename, fileSize, passwordProtected);
      }

      // Sync completion (200 OK)
      const result = await response.json() as {
        claim_code: string;
        original_filename: string;
        file_size: number;
        mime_type: string;
        expires_at: string | null;
        max_downloads: number | null;
        user_id?: number;
      };

      return {
        claimCode: result.claim_code,
        filename: result.original_filename,
        size: result.file_size,
        mimeType: result.mime_type,
        expiresAt: result.expires_at,
        downloadLimit: positiveOrNull(result.max_downloads),
        passwordProtected,
        userId: result.user_id,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Poll for async assembly completion
   */
  private async pollForCompletion(
    uploadId: string,
    filename: string,
    fileSize: number,
    passwordProtected: boolean
  ): Promise<UploadResult> {
    const INITIAL_DELAY = 500;
    const MAX_DELAY = 5000;
    const MAX_DURATION = 10 * 60 * 1000; // 10 minutes
    const MAX_ITERATIONS = 200;

    const deadline = Date.now() + MAX_DURATION;
    let delay = INITIAL_DELAY;

    // ADR-016: bounds how many times this poll loop will POST /complete
    // again after observing a retryable "failed" status (SCAN_UNAVAILABLE, a
    // transient IO/DB error, etc). The server enforces its own attempt cap
    // independently; this just keeps a permanently broken server from
    // looping the SDK caller forever.
    const MAX_ASSEMBLY_RETRIES = 3;
    let assemblyRetries = 0;

    for (let iteration = 0; iteration < MAX_ITERATIONS && Date.now() < deadline; iteration++) {
      // Get status
      let status;
      try {
        status = await this.getUploadStatusInternal(uploadId);
      } catch (error) {
        if (!(error instanceof RateLimitError)) throw error;
        // T52: a 429 from the status endpoint only means "poll more
        // slowly" - the upload is still assembling, and its claim code is
        // only ever returned here. Wait (honouring Retry-After) and try
        // again; the overall deadline still applies.
        await this.sleep(Math.min(rateLimitPollDelay(error), Math.max(0, deadline - Date.now())));
        iteration--; // rate-limited polls don't count toward MAX_ITERATIONS
        continue;
      }

      switch (status.status) {
        case "completed":
          if (!status.claimCode) {
            throw new ChunkedUploadError(
              "Upload completed but no claim code returned",
              uploadId
            );
          }
          return {
            claimCode: status.claimCode,
            filename: filename,
            size: fileSize,
            mimeType: "", // Not available in status response
            expiresAt: status.expiresAt,
            downloadLimit: positiveOrNull(status.maxDownloads),
            passwordProtected,
          };

        case "failed":
          // ADR-016: a retryable failure still has its chunks on the
          // server — POSTing /complete again reopens the upload and
          // re-runs assembly, up to the server's own attempt cap.
          if (status.retryable && assemblyRetries < MAX_ASSEMBLY_RETRIES) {
            assemblyRetries++;
            await this.sleep(delay);
            try {
              await this.request("POST", `/api/upload/complete/${uploadId}`);
            } catch {
              // Ignore: the next status read is the source of truth,
              // whether the retry POST succeeded, re-failed, or hit a
              // network error.
            }
            delay = Math.min(delay * 2, MAX_DELAY);
            continue;
          }
          throw new ChunkedUploadError(
            status.errorMessage ? `Assembly failed: "${status.errorMessage}"` : "Assembly failed",
            uploadId,
            undefined,
            undefined,
            status.errorCode
          );

        case "uploading":
          // Should not normally happen while polling (polling only starts
          // after /complete already returned 202) — but defensively, if the
          // row ever falls back to "uploading" underneath us, re-POST
          // /complete (bounded by the same budget as a retryable failure)
          // rather than silently poll a row nothing is ever going to finish
          // on its own.
          if (assemblyRetries < MAX_ASSEMBLY_RETRIES) {
            assemblyRetries++;
            await this.sleep(delay);
            try {
              await this.request("POST", `/api/upload/complete/${uploadId}`);
            } catch {
              // Ignore: the next status read is the source of truth.
            }
            delay = Math.min(delay * 2, MAX_DELAY);
            continue;
          }
          throw new ChunkedUploadError("Upload fell back to uploading state and could not be resumed", uploadId);

        case "processing":
          // Wait before retrying
          await this.sleep(delay);
          delay = Math.min(delay * 2, MAX_DELAY);
          break;

        default:
          throw new ChunkedUploadError(`Unexpected status: ${status.status}`, uploadId);
      }
    }

    throw new ChunkedUploadError(
      `Timeout waiting for assembly to complete (max ${MAX_DURATION / 1000 / 60} minutes)`,
      uploadId
    );
  }

  /**
   * Helper to sleep with a promise
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Internal method to get upload status with extended fields
   */
  private async getUploadStatusInternal(uploadId: string): Promise<{
    uploadId: string;
    filename: string;
    totalSize: number;
    uploadedSize: number;
    uploadedChunks: number[];
    totalChunks: number;
    chunkSize: number;
    expiresAt: string;
    complete: boolean;
    status: string;
    claimCode?: string;
    errorMessage?: string;
    errorCode?: string;
    retryable: boolean;
    attempts: number;
    maxDownloads?: number;
  }> {
    const response = await this.request<{
      upload_id: string;
      filename: string;
      total_size: number;
      uploaded_size: number;
      uploaded_chunks: number[];
      total_chunks: number;
      chunk_size: number;
      expires_at: string;
      complete: boolean;
      status?: string;
      claim_code?: string;
      error_message?: string;
      error_code?: string;
      retryable?: boolean;
      attempts?: number;
      max_downloads?: number;
    }>("GET", `/api/upload/status/${uploadId}`);

    return {
      uploadId: response.upload_id,
      filename: response.filename,
      totalSize: response.total_size,
      uploadedSize: response.uploaded_size,
      uploadedChunks: response.uploaded_chunks,
      totalChunks: response.total_chunks,
      chunkSize: response.chunk_size,
      expiresAt: response.expires_at,
      complete: response.complete,
      status: response.status ?? (response.complete ? "completed" : "uploading"),
      claimCode: response.claim_code,
      errorMessage: response.error_message,
      errorCode: response.error_code,
      retryable: response.retryable ?? false,
      attempts: response.attempts ?? 0,
      maxDownloads: response.max_downloads,
    };
  }

  /**
   * Get status of a chunked upload
   *
   * @param uploadId - Upload session ID
   * @returns Upload status
   */
  async getUploadStatus(uploadId: string): Promise<UploadStatus> {
    this.validateUploadId(uploadId);

    const response = await this.request<{
      upload_id: string;
      filename: string;
      total_size: number;
      uploaded_size: number;
      uploaded_chunks: number[];
      total_chunks: number;
      chunk_size: number;
      expires_at: string;
      complete: boolean;
      status?: string;
      claim_code?: string;
      error_message?: string;
      error_code?: string;
      retryable?: boolean;
      attempts?: number;
    }>("GET", `/api/upload/status/${uploadId}`);

    return {
      uploadId: response.upload_id,
      filename: response.filename,
      totalSize: response.total_size,
      uploadedSize: response.uploaded_size,
      uploadedChunks: response.uploaded_chunks,
      totalChunks: response.total_chunks,
      chunkSize: response.chunk_size,
      expiresAt: response.expires_at,
      complete: response.complete,
      status: response.status,
      claimCode: response.claim_code,
      errorMessage: response.error_message,
      errorCode: response.error_code,
      retryable: response.retryable,
      attempts: response.attempts,
    };
  }

  // ===========================================================================
  // File Download
  // ===========================================================================

  /**
   * Download a file by claim code
   *
   * @param claimCode - File claim code
   * @param destination - Path to save the file
   * @param options - Download options (password, progress callback)
   * @returns Path to the downloaded file
   */
  async download(
    claimCode: string,
    destination: string,
    options: DownloadOptions = {}
  ): Promise<string> {
    this.validateClaimCode(claimCode);

    // Resolve and sanitize destination path
    const resolvedDest = resolve(destination);

    if (options.decryptionKey !== undefined) {
      // Check the destination first, so a limited download isn't used up.
      const existing = await lstat(resolvedDest).catch(() => null);
      if (existing?.isSymbolicLink()) {
        throw new DownloadError(`Destination is a symbolic link, refusing to write to it: ${resolvedDest}`);
      }
      if (existing && !options.overwrite) {
        throw new DownloadError(`Destination already exists: ${resolvedDest}`);
      }
      const file = await this.downloadDecrypted(claimCode, options.decryptionKey, options);
      try {
        await writePrivate(resolvedDest, file.data, !!options.overwrite);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        throw new DownloadError(
          code === "EEXIST" ? `Destination already exists: ${resolvedDest}` : `Writing the file failed: ${String(err)}`
        );
      }
      return resolvedDest;
    }

    const url = `/api/claim/${claimCode}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${url}`, {
        method: "GET",
        headers: this.downloadHeaders(options.password),
        // A file password or token travels in a header, which fetch may
        // forward on a redirect; refuse redirects rather than risk that.
        redirect: options.password || this.apiToken ? "error" : "follow",
        signal: controller.signal,
      });

      if (!response.ok) {
        await handleErrorResponse(response);
      }

      if (!response.body) {
        throw new DownloadError("Response body is empty");
      }

      // Get content length for progress
      const contentLength = parseInt(response.headers.get("content-length") || "0", 10);

      // Ensure parent directory exists
      await mkdir(dirname(resolvedDest), { recursive: true });

      // Stream to file with progress
      const chunks: Uint8Array[] = [];
      let bytesDownloaded = 0;
      const reader = response.body.getReader();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        chunks.push(value);
        bytesDownloaded += value.length;

        if (options.onProgress) {
          options.onProgress({
            bytesDownloaded,
            totalBytes: contentLength,
            percentage: contentLength > 0
              ? Math.round((bytesDownloaded / contentLength) * 100)
              : -1,
          });
        }
      }

      // Write to file
      const buffer = Buffer.concat(chunks.map(chunk => Buffer.from(chunk)));
      await writeFile(resolvedDest, buffer);

      return resolvedDest;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Download an end-to-end encrypted file into memory and decrypt it.
   *
   * `key` is the base64url key from the share link (see e2e.parseShareUrl).
   * Handles every format the web app writes. The returned filename comes from
   * the uploader; pass it through e2e.safeFilename() before saving under it.
   */
  async downloadDecrypted(
    claimCode: string,
    key: string,
    options: Pick<DownloadOptions, "password" | "onProgress"> = {}
  ): Promise<e2e.DecryptedFile> {
    this.validateClaimCode(claimCode);
    const rawKey = e2e.decodeKey(key);
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    try {
      const info = await this.getFileInfo(claimCode);
      const limit = info.size;
      if (!Number.isSafeInteger(limit) || limit < 0 || limit > e2e.MAX_ENCRYPTED_PAYLOAD + e2e.CIPHERTEXT_OVERHEAD) {
        throw new DownloadError(`The server reports ${limit} bytes; decrypting holds the whole file in memory`);
      }
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), this.timeout);
      const response = await this.fetchImpl(`${this.baseUrl}/api/claim/${claimCode}`, {
        method: "GET",
        headers: this.downloadHeaders(options.password),
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) {
        await handleErrorResponse(response);
      }
      const declared = parseInt(response.headers.get("content-length") || "0", 10);
      if (declared > limit) {
        throw new DownloadError(`The server sent ${declared} bytes but reported ${limit}`);
      }
      const chunks: Buffer[] = [];
      let received = 0;
      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.length;
          if (received > limit) {
            await reader.cancel();
            throw new DownloadError(`The server sent more than the ${limit} bytes it reported`);
          }
          chunks.push(Buffer.from(value));
          options.onProgress?.({
            bytesDownloaded: received,
            totalBytes: limit,
            percentage: limit > 0 ? Math.round((received / limit) * 100) : -1,
          });
        }
      } else {
        const ab = Buffer.from(await response.arrayBuffer());
        if (ab.length > limit) throw new DownloadError(`The server sent more than the ${limit} bytes it reported`);
        chunks.push(ab);
      }
      const plaintext = e2e.decryptBlob(rawKey, Buffer.concat(chunks));
      return e2e.unwrapDownload(plaintext, info.filename);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      rawKey.fill(0);
    }
  }

  /**
   * Download a file and return as Buffer
   *
   * @param claimCode - File claim code
   * @param options - Download options (password, progress callback)
   * @returns File contents as Buffer
   */
  async downloadToBuffer(
    claimCode: string,
    options: DownloadOptions = {}
  ): Promise<Buffer> {
    this.validateClaimCode(claimCode);

    if (options.decryptionKey !== undefined) {
      return (await this.downloadDecrypted(claimCode, options.decryptionKey, options)).data;
    }

    const url = `/api/claim/${claimCode}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${url}`, {
        method: "GET",
        headers: this.downloadHeaders(options.password),
        // A file password or token travels in a header, which fetch may
        // forward on a redirect; refuse redirects rather than risk that.
        redirect: options.password || this.apiToken ? "error" : "follow",
        signal: controller.signal,
      });

      if (!response.ok) {
        await handleErrorResponse(response);
      }

      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ===========================================================================
  // File Information
  // ===========================================================================

  /**
   * Get file information by claim code
   *
   * @param claimCode - File claim code
   * @returns File information
   */
  async getFileInfo(claimCode: string): Promise<FileInfo> {
    this.validateClaimCode(claimCode);

    // Server returns fields from internal/handlers/claim.go:ClaimInfoHandler
    const response = await this.request<{
      claim_code: string;
      original_filename: string;
      file_size: number;
      mime_type: string;
      created_at: string;
      expires_at: string | null;
      max_downloads: number | null;
      download_count: number;
      completed_downloads: number;
      download_limit_reached: boolean;
      password_required: boolean;
      download_url: string;
      sha256_hash: string;
      scan_status?: ScanStatus;
      client_encrypted?: boolean;
      download_available?: boolean;
    }>("GET", `/api/claim/${claimCode}/info`);

    // Calculate downloads remaining from max_downloads and download_count
    let downloadsRemaining: number | null = null;
    if (response.max_downloads !== null) {
      const remaining = response.max_downloads - response.download_count;
      downloadsRemaining = remaining < 0 ? 0 : remaining;
    }

    return {
      filename: response.original_filename,
      size: response.file_size,
      mimeType: response.mime_type,
      expiresAt: response.expires_at,
      passwordProtected: response.password_required,
      downloadsRemaining: downloadsRemaining,
      scanStatus: response.scan_status,
      clientEncrypted: !!response.client_encrypted,
      downloadAvailable: response.download_available,
    };
  }

  // ===========================================================================
  // User File Management (requires authentication)
  // ===========================================================================

  /**
   * List files uploaded by the authenticated user
   *
   * @param limit - Number of files to return (default: 50, max: 100)
   * @param offset - Number of files to skip (default: 0)
   * @returns Paginated list of user's files
   */
  async listFiles(limit = 50, offset = 0): Promise<UserFilesResponse> {
    // Validate and clamp values
    if (limit <= 0) limit = 50;
    if (limit > 100) limit = 100;
    if (offset < 0) offset = 0;

    const response = await this.request<{
      files: Array<{
        id: number;
        claim_code: string;
        original_filename: string;
        file_size: number;
        mime_type: string;
        created_at: string;
        expires_at: string;
        download_count: number;
        completed_downloads: number;
        max_downloads: number | null;
        is_password_protected: boolean;
        download_url: string;
        is_expired: boolean;
      }>;
      total: number;
      limit: number;
      offset: number;
    }>("GET", `/api/user/files?limit=${limit}&offset=${offset}`);

    // Calculate page info for backward compatibility
    const page = limit > 0 ? Math.floor(offset / limit) : 0;

    return {
      files: response.files.map((f) => ({
        id: f.id,
        claimCode: f.claim_code,
        filename: f.original_filename,
        size: f.file_size,
        mimeType: f.mime_type,
        uploadedAt: f.created_at,
        expiresAt: f.expires_at || null,
        completedDownloads: f.completed_downloads,
        downloadCount: f.download_count,
        downloadLimit: f.max_downloads,
        passwordProtected: f.is_password_protected,
      })),
      total: response.total,
      page: page,
      perPage: limit,
    };
  }

  /**
   * Delete a file by claim code
   *
   * @param claimCode - File claim code
   */
  async deleteFile(claimCode: string): Promise<void> {
    this.validateClaimCode(claimCode);
    await this.request("DELETE", `/api/user/files/${claimCode}`);
  }

  /**
   * Rename a file
   * Note: The API returns a simple message response, not the full file object.
   *
   * @param claimCode - File claim code
   * @param newFilename - New filename
   * @returns Rename result with new filename
   */
  async renameFile(claimCode: string, newFilename: string): Promise<RenameResult> {
    this.validateClaimCode(claimCode);
    this.validateFilename(newFilename);

    const response = await this.request<{
      message: string;
      new_filename: string;
    }>("PUT", `/api/user/files/${claimCode}/rename`, {
      body: JSON.stringify({ filename: newFilename }),
      headers: { "Content-Type": "application/json" },
    });

    return {
      message: response.message,
      newFilename: response.new_filename,
    };
  }

  /**
   * Update file expiration
   * Note: The API returns a simple message response, not the full file object.
   *
   * @param claimCode - File claim code
   * @param options - Expiration options
   * @returns Expiration update result
   */
  async updateExpiration(
    claimCode: string,
    options: UpdateExpirationOptions
  ): Promise<ExpirationResult> {
    this.validateClaimCode(claimCode);

    const response = await this.request<{
      message: string;
      new_expiration: string;
    }>("PUT", `/api/user/files/${claimCode}/expiration`, {
      body: JSON.stringify({ expires_in_hours: options.expiresInHours }),
      headers: { "Content-Type": "application/json" },
    });

    return {
      message: response.message,
      newExpiration: response.new_expiration,
    };
  }

  /**
   * Regenerate claim code for a file
   * Note: The API returns the new claim code and download URL.
   *
   * @param claimCode - Current claim code
   * @returns Regeneration result with new claim code
   */
  async regenerateClaimCode(claimCode: string): Promise<RegenerateResult> {
    this.validateClaimCode(claimCode);

    const response = await this.request<{
      message: string;
      claim_code: string;
      download_url: string;
    }>("POST", `/api/user/files/${claimCode}/regenerate`);

    return {
      message: response.message,
      claimCode: response.claim_code,
      downloadUrl: response.download_url,
    };
  }

  // ===========================================================================
  // API Token Management (requires authentication)
  // ===========================================================================

  /**
   * Create a new API token
   *
   * @param request - Token creation parameters
   * @returns Created token (including the token value - only shown once!)
   */
  async createToken(request: CreateTokenRequest): Promise<TokenCreatedResponse> {
    const response = await this.request<{
      token: string;
      name: string;
      scopes: string[];
      expires_at: string | null;
      created_at: string;
    }>("POST", "/api/tokens", {
      body: JSON.stringify({
        name: request.name,
        scopes: request.scopes,
        expires_in_days: request.expiresInDays,
      }),
      headers: { "Content-Type": "application/json" },
    });

    return {
      token: response.token,
      name: response.name,
      scopes: response.scopes,
      expiresAt: response.expires_at,
      createdAt: response.created_at,
    };
  }

  /**
   * List all API tokens for the authenticated user
   *
   * @returns Array of token information
   */
  async listTokens(): Promise<TokenInfo[]> {
    const response = await this.request<{
      tokens: Array<{
        id: number;
        name: string;
        scopes: string[];
        expires_at: string | null;
        created_at: string;
        last_used_at: string | null;
      }>;
    }>("GET", "/api/tokens");

    return response.tokens.map((t) => ({
      id: t.id,
      name: t.name,
      scopes: t.scopes,
      expiresAt: t.expires_at,
      createdAt: t.created_at,
      lastUsedAt: t.last_used_at,
    }));
  }

  /**
   * Revoke an API token
   *
   * Note: This operation requires session authentication, not API token auth.
   *
   * @param tokenId - Token ID to revoke (must be a positive integer)
   */
  async revokeToken(tokenId: number): Promise<void> {
    this.validateTokenId(tokenId);
    await this.request("DELETE", `/api/tokens/${tokenId}`);
  }
}

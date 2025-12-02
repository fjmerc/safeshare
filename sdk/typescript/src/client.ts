/**
 * SafeShare SDK Client
 *
 * Main client class for interacting with the SafeShare API.
 */

import { createReadStream, statSync } from "node:fs";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve, basename } from "node:path";

import type {
  ClientOptions,
  UploadResult,
  UploadOptions,
  ChunkUploadResult,
  UploadStatus,
  FileInfo,
  UserFilesResponse,
  DownloadOptions,
  UpdateExpirationOptions,
  RenameResult,
  ExpirationResult,
  RegenerateResult,
  PublicConfig,
  CreateTokenRequest,
  TokenCreatedResponse,
  TokenInfo,
} from "./types.js";

import {
  SafeShareError,
  ValidationError,
  DownloadError,
  ChunkedUploadError,
  handleErrorResponse,
} from "./errors.js";

// Validation patterns
// Server uses base64 URL-safe encoding which includes - and _ characters
const CLAIM_CODE_PATTERN = /^[a-zA-Z0-9_-]{8,32}$/;
// Standard UUID v4 pattern (8-4-4-4-12 format)
const UPLOAD_ID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const FILENAME_MAX_LENGTH = 255;

// Pagination limits
const MAX_PER_PAGE = 100;
const MIN_PAGE = 1;
const MIN_PER_PAGE = 1;

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

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private validatePagination(page: number, perPage: number): void {
    if (!Number.isInteger(page) || page < MIN_PAGE) {
      throw new ValidationError("page must be a positive integer");
    }
    if (!Number.isInteger(perPage) || perPage < MIN_PER_PAGE || perPage > MAX_PER_PAGE) {
      throw new ValidationError(`perPage must be an integer between ${MIN_PER_PAGE} and ${MAX_PER_PAGE}`);
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

  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {};
    if (this.apiToken) {
      headers["Authorization"] = `Bearer ${this.apiToken}`;
    }
    return headers;
  }

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: BodyInit;
      headers?: HeadersInit;
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
    }>("GET", "/api/config");

    this.configCache = {
      maxFileSize: response.max_file_size,
      chunkUploadThreshold: response.chunked_upload_threshold,
      chunkSize: response.chunk_size,
      maxExpirationHours: response.max_expiration_hours,
      registrationEnabled: response.registration_enabled,
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

    if (stats.size >= config.chunkUploadThreshold) {
      return this.uploadChunked(resolvedPath, options);
    }

    return this.uploadSimple(resolvedPath, options);
  }

  /**
   * Simple (non-chunked) file upload
   */
  private async uploadSimple(
    filePath: string,
    options: UploadOptions
  ): Promise<UploadResult> {
    const resolvedPath = resolve(filePath);
    const stats = statSync(resolvedPath);
    const filename = basename(resolvedPath);

    // Create form data
    const formData = new FormData();

    // Read file as buffer for FormData
    const chunks: Buffer[] = [];
    const stream = createReadStream(resolvedPath);

    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
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
      formData.append("download_limit", String(options.downloadLimit));
    }
    if (options.password) {
      formData.append("password", options.password);
    }

    const response = await this.request<{
      claim_code: string;
      filename: string;
      size: number;
      mime_type: string;
      expires_at: string | null;
      download_limit: number | null;
      password_protected: boolean;
      user_id?: number;
    }>("POST", "/api/upload", {
      body: formData,
    });

    return {
      claimCode: response.claim_code,
      filename: response.filename,
      size: response.size,
      mimeType: response.mime_type,
      expiresAt: response.expires_at,
      downloadLimit: response.download_limit,
      passwordProtected: response.password_protected,
      userId: response.user_id,
    };
  }

  /**
   * Chunked file upload for large files
   */
  private async uploadChunked(
    filePath: string,
    options: UploadOptions
  ): Promise<UploadResult> {
    const resolvedPath = resolve(filePath);
    const stats = statSync(resolvedPath);
    const filename = basename(resolvedPath);

    // Initialize chunked upload
    const initBody: Record<string, unknown> = {
      filename,
      total_size: stats.size,
    };
    if (options.expiresInHours !== undefined && options.expiresInHours !== null) {
      initBody.expires_in_hours = options.expiresInHours;
    }
    if (options.downloadLimit !== undefined && options.downloadLimit !== null) {
      initBody.download_limit = options.downloadLimit;
    }
    if (options.password) {
      initBody.password = options.password;
    }

    const session = await this.request<{
      upload_id: string;
      chunk_size: number;
      total_chunks: number;
      expires_at: string;
    }>("POST", "/api/upload/init", {
      body: JSON.stringify(initBody),
      headers: { "Content-Type": "application/json" },
    });

    const uploadId = session.upload_id;
    const chunkSize = session.chunk_size;
    const totalChunks = session.total_chunks;

    try {
      // Upload chunks
      let bytesUploaded = 0;
      const stream = createReadStream(resolvedPath, { highWaterMark: chunkSize });
      let chunkNumber = 0;

      for await (const chunk of stream) {
        const chunkBuffer = Buffer.from(chunk);
        const chunkFormData = new FormData();
        chunkFormData.append("chunk", new Blob([chunkBuffer]));

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
      const completeResult = await this.completeChunkedUpload(uploadId, filename, stats.size);

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
    fileSize: number
  ): Promise<UploadResult> {
    const url = `${this.baseUrl}/api/upload/complete/${uploadId}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: this.getHeaders(),
        signal: controller.signal,
      });

      if (!response.ok) {
        await handleErrorResponse(response);
      }

      // Check if async assembly (202 Accepted)
      if (response.status === 202) {
        return this.pollForCompletion(uploadId, filename, fileSize);
      }

      // Sync completion (200 OK)
      const result = await response.json() as {
        claim_code: string;
        filename: string;
        size: number;
        mime_type: string;
        expires_at: string | null;
        download_limit: number | null;
        password_protected: boolean;
        user_id?: number;
      };

      return {
        claimCode: result.claim_code,
        filename: result.filename,
        size: result.size,
        mimeType: result.mime_type,
        expiresAt: result.expires_at,
        downloadLimit: result.download_limit,
        passwordProtected: result.password_protected,
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
    fileSize: number
  ): Promise<UploadResult> {
    const INITIAL_DELAY = 500;
    const MAX_DELAY = 5000;
    const MAX_DURATION = 10 * 60 * 1000; // 10 minutes
    const MAX_ITERATIONS = 200;

    const deadline = Date.now() + MAX_DURATION;
    let delay = INITIAL_DELAY;

    for (let iteration = 0; iteration < MAX_ITERATIONS && Date.now() < deadline; iteration++) {
      // Get status
      const status = await this.getUploadStatusInternal(uploadId);

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
            downloadLimit: status.maxDownloads ?? null,
            passwordProtected: false, // Not available in status response
          };

        case "failed":
          throw new ChunkedUploadError(
            status.errorMessage ? `Assembly failed: "${status.errorMessage}"` : "Assembly failed",
            uploadId
          );

        case "processing":
        case "uploading":
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

    // Build URL with optional password
    let url = `/api/claim/${claimCode}`;
    if (options.password) {
      url += `?password=${encodeURIComponent(options.password)}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${url}`, {
        method: "GET",
        headers: this.getHeaders(),
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

    let url = `/api/claim/${claimCode}`;
    if (options.password) {
      url += `?password=${encodeURIComponent(options.password)}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${url}`, {
        method: "GET",
        headers: this.getHeaders(),
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

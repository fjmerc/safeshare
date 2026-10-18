/**
 * SafeShare SDK
 *
 * TypeScript/JavaScript SDK for the SafeShare file sharing service.
 *
 * @example
 * ```typescript
 * import { SafeShareClient } from "safeshare-sdk";
 *
 * const client = new SafeShareClient({
 *   baseUrl: "https://share.example.com",
 *   apiToken: "safeshare_abc123...",
 * });
 *
 * // Upload a file
 * const result = await client.upload("./myfile.txt", {
 *   expiresInHours: 24,
 *   onProgress: (progress) => {
 *     console.log(`Upload: ${progress.percentage}%`);
 *   },
 * });
 *
 * console.log(`Share link: ${client.baseUrl}/claim/${result.claimCode}`);
 * ```
 *
 * @packageDocumentation
 */

// Client
export { SafeShareClient } from "./client.js";

// Types
export type {
  ClientOptions,
  UploadResult,
  UploadOptions,
  UploadProgress,
  ChunkedUploadSession,
  ChunkUploadResult,
  UploadStatus,
  FileInfo,
  ScanStatus,
  UserFile,
  UserFilesResponse,
  DownloadOptions,
  DownloadProgress,
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

// End-to-end encryption (web-app compatible)
export * as e2e from "./e2e.js";
export {
  DecryptionError,
  InvalidPayloadError,
  PayloadTooLargeError,
  MetadataNotRemovedError,
  ClientEncryptionRequiredError,
  parseShareUrl,
  buildShareUrl,
  safeFilename,
} from "./e2e.js";
export type { DecryptedFile, ShareLink } from "./e2e.js";

// Errors
export {
  SafeShareError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  UploadError,
  DownloadError,
  ValidationError,
  QuotaExceededError,
  FileTooLargeError,
  PasswordRequiredError,
  DownloadLimitReachedError,
  ChunkedUploadError,
  MalwareDetectedError,
  FileQuarantinedError,
  ScanPendingError,
  ScanUnavailableError,
  ScanFailedError,
  UnscannableUploadError,
} from "./errors.js";

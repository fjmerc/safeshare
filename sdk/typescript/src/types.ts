/**
 * SafeShare SDK Type Definitions
 *
 * TypeScript interfaces for all SafeShare API responses and requests.
 */

// ============================================================================
// Upload Types
// ============================================================================

/**
 * Result of a successful file upload
 */
export interface UploadResult {
  /** Unique claim code for downloading the file */
  claimCode: string;
  /** Original filename */
  filename: string;
  /** File size in bytes */
  size: number;
  /** MIME type of the file */
  mimeType: string;
  /** ISO 8601 expiration timestamp (null if no expiration) */
  expiresAt: string | null;
  /** Maximum number of downloads allowed (null if unlimited) */
  downloadLimit: number | null;
  /** Whether the file is password protected */
  passwordProtected: boolean;
  /** User ID of the uploader (if authenticated) */
  userId?: number;
}

/**
 * Request options for uploading a file
 */
export interface UploadOptions {
  /** Hours until expiration (null for no expiration) */
  expiresInHours?: number | null;
  /** Maximum number of downloads (null for unlimited) */
  downloadLimit?: number | null;
  /** Password to protect the file */
  password?: string;
  /** Progress callback for upload progress */
  onProgress?: (progress: UploadProgress) => void;
}

/**
 * Upload progress information
 */
export interface UploadProgress {
  /** Bytes uploaded so far */
  bytesUploaded: number;
  /** Total bytes to upload */
  totalBytes: number;
  /** Progress percentage (0-100) */
  percentage: number;
  /** Current chunk number (for chunked uploads) */
  currentChunk?: number;
  /** Total number of chunks (for chunked uploads) */
  totalChunks?: number;
}

// ============================================================================
// Chunked Upload Types
// ============================================================================

/**
 * Response from initializing a chunked upload
 */
export interface ChunkedUploadSession {
  /** Unique upload ID for this session */
  uploadId: string;
  /** Size of each chunk in bytes */
  chunkSize: number;
  /** Total number of chunks expected */
  totalChunks: number;
  /** ISO 8601 timestamp when this session expires */
  expiresAt: string;
}

/**
 * Response from uploading a single chunk
 */
export interface ChunkUploadResult {
  /** Chunk number that was uploaded */
  chunkNumber: number;
  /** Size of the uploaded chunk in bytes */
  size: number;
  /** SHA-256 hash of the chunk */
  hash: string;
}

/**
 * Status of a chunked upload session
 */
export interface UploadStatus {
  /** Upload ID */
  uploadId: string;
  /** Original filename */
  filename: string;
  /** Total file size in bytes */
  totalSize: number;
  /** Bytes uploaded so far */
  uploadedSize: number;
  /** Array of chunk numbers that have been uploaded */
  uploadedChunks: number[];
  /** Total number of chunks expected */
  totalChunks: number;
  /** Size of each chunk in bytes */
  chunkSize: number;
  /** ISO 8601 timestamp when this session expires */
  expiresAt: string;
  /** Whether the upload is complete */
  complete: boolean;
}

// ============================================================================
// File Information Types
// ============================================================================

/**
 * Public file information (available without authentication)
 */
export interface FileInfo {
  /** Original filename */
  filename: string;
  /** File size in bytes */
  size: number;
  /** MIME type */
  mimeType: string;
  /** ISO 8601 expiration timestamp (null if no expiration) */
  expiresAt: string | null;
  /** Whether the file is password protected */
  passwordProtected: boolean;
  /** Number of downloads remaining (null if unlimited) */
  downloadsRemaining: number | null;
}

/**
 * File information for authenticated user's files
 */
export interface UserFile {
  /** Unique file ID */
  id: number;
  /** Claim code for downloading */
  claimCode: string;
  /** Original filename */
  filename: string;
  /** File size in bytes */
  size: number;
  /** MIME type */
  mimeType: string;
  /** ISO 8601 upload timestamp */
  uploadedAt: string;
  /** ISO 8601 expiration timestamp (null if no expiration) */
  expiresAt: string | null;
  /** Number of times file has been downloaded */
  downloadCount: number;
  /** Maximum downloads allowed (null if unlimited) */
  downloadLimit: number | null;
  /** Whether the file is password protected */
  passwordProtected: boolean;
}

/**
 * Response from listing user's files
 */
export interface UserFilesResponse {
  /** Array of user's files */
  files: UserFile[];
  /** Total number of files */
  total: number;
  /** Current page number */
  page: number;
  /** Number of files per page */
  perPage: number;
}

// ============================================================================
// Download Types
// ============================================================================

/**
 * Options for downloading a file
 */
export interface DownloadOptions {
  /** Password if file is protected */
  password?: string;
  /** Progress callback for download progress */
  onProgress?: (progress: DownloadProgress) => void;
}

/**
 * Download progress information
 */
export interface DownloadProgress {
  /** Bytes downloaded so far */
  bytesDownloaded: number;
  /** Total bytes to download (may be 0 if unknown) */
  totalBytes: number;
  /** Progress percentage (0-100, or -1 if unknown) */
  percentage: number;
}

// ============================================================================
// File Management Types
// ============================================================================

/**
 * Options for updating file expiration
 */
export interface UpdateExpirationOptions {
  /** New expiration hours from now (null to remove expiration) */
  expiresInHours: number | null;
}

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Public server configuration
 */
export interface PublicConfig {
  /** Maximum file size in bytes */
  maxFileSize: number;
  /** Threshold for chunked uploads in bytes */
  chunkUploadThreshold: number;
  /** Chunk size for chunked uploads in bytes */
  chunkSize: number;
  /** Maximum expiration hours allowed */
  maxExpirationHours: number;
  /** Whether user registration is enabled */
  registrationEnabled: boolean;
}

// ============================================================================
// API Token Types
// ============================================================================

/**
 * Request for creating a new API token
 */
export interface CreateTokenRequest {
  /** Human-readable token name */
  name: string;
  /** Array of scopes (upload, download, manage, admin) */
  scopes: string[];
  /** Days until expiration (null for no expiration, max 365) */
  expiresInDays?: number | null;
}

/**
 * Response when a token is created (includes the actual token value)
 */
export interface TokenCreatedResponse {
  /** The API token value (only shown once!) */
  token: string;
  /** Token name */
  name: string;
  /** Token scopes */
  scopes: string[];
  /** ISO 8601 expiration timestamp (null if no expiration) */
  expiresAt: string | null;
  /** ISO 8601 creation timestamp */
  createdAt: string;
}

/**
 * Token information (does not include token value)
 */
export interface TokenInfo {
  /** Token ID */
  id: number;
  /** Token name */
  name: string;
  /** Token scopes */
  scopes: string[];
  /** ISO 8601 expiration timestamp (null if no expiration) */
  expiresAt: string | null;
  /** ISO 8601 creation timestamp */
  createdAt: string;
  /** ISO 8601 timestamp of last use (null if never used) */
  lastUsedAt: string | null;
}

// ============================================================================
// Client Configuration Types
// ============================================================================

/**
 * Options for creating a SafeShareClient instance
 */
export interface ClientOptions {
  /** Base URL of the SafeShare server */
  baseUrl: string;
  /** API token for authentication */
  apiToken?: string;
  /** Request timeout in milliseconds (default: 300000 = 5 minutes) */
  timeout?: number;
  /** Custom fetch implementation (for testing or polyfills) */
  fetch?: typeof fetch;
}

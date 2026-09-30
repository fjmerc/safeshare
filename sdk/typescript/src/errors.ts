/**
 * SafeShare SDK Error Classes
 *
 * Custom error types for SafeShare API errors with proper HTTP status mapping.
 */

/**
 * Keys that may contain sensitive information and should be redacted from error responses
 */
const SENSITIVE_KEYS = [
  "token",
  "password",
  "secret",
  "key",
  "authorization",
  "cookie",
  "credential",
  "api_token",
  "apitoken",
];

/**
 * Sanitize response body to prevent credential leakage in error objects
 */
function sanitizeResponseBody(body: unknown): unknown {
  if (body === null || body === undefined) {
    return body;
  }

  if (typeof body !== "object") {
    return body;
  }

  if (Array.isArray(body)) {
    return body.map(sanitizeResponseBody);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_KEYS.some((sk) => lowerKey.includes(sk))) {
      sanitized[key] = "[REDACTED]";
    } else if (typeof value === "object" && value !== null) {
      sanitized[key] = sanitizeResponseBody(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Base error class for all SafeShare SDK errors
 */
export class SafeShareError extends Error {
  /** HTTP status code (if applicable) */
  public readonly statusCode?: number;
  /** Original response body (sanitized to remove sensitive data) */
  public readonly responseBody?: unknown;

  constructor(message: string, statusCode?: number, responseBody?: unknown) {
    super(message);
    this.name = "SafeShareError";
    this.statusCode = statusCode;
    this.responseBody = sanitizeResponseBody(responseBody);
    // Maintains proper stack trace for where error was thrown (only in V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Authentication failed - invalid or missing API token
 */
export class AuthenticationError extends SafeShareError {
  constructor(message = "Authentication failed", statusCode = 401, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "AuthenticationError";
  }
}

/**
 * Resource not found - file or endpoint doesn't exist
 */
export class NotFoundError extends SafeShareError {
  constructor(message = "Resource not found", statusCode = 404, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "NotFoundError";
  }
}

/**
 * Rate limit exceeded - too many requests
 */
export class RateLimitError extends SafeShareError {
  /** Seconds until rate limit resets */
  public readonly retryAfter?: number;

  constructor(message = "Rate limit exceeded", retryAfter?: number, responseBody?: unknown) {
    super(message, 429, responseBody);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

/**
 * File upload failed
 */
export class UploadError extends SafeShareError {
  constructor(message = "Upload failed", statusCode?: number, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "UploadError";
  }
}

/**
 * File download failed
 */
export class DownloadError extends SafeShareError {
  constructor(message = "Download failed", statusCode?: number, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "DownloadError";
  }
}

/**
 * Input validation failed
 */
export class ValidationError extends SafeShareError {
  constructor(message = "Validation failed", statusCode = 400, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "ValidationError";
  }
}

/**
 * User quota exceeded
 */
export class QuotaExceededError extends SafeShareError {
  constructor(message = "Quota exceeded", statusCode = 403, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "QuotaExceededError";
  }
}

/**
 * File too large for upload
 */
export class FileTooLargeError extends SafeShareError {
  constructor(message = "File too large", statusCode = 413, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "FileTooLargeError";
  }
}

/**
 * Password required to access file
 */
export class PasswordRequiredError extends SafeShareError {
  constructor(message = "Password required", statusCode = 401, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "PasswordRequiredError";
  }
}

/**
 * Download limit reached for file
 */
export class DownloadLimitReachedError extends SafeShareError {
  constructor(message = "Download limit reached", statusCode = 410, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "DownloadLimitReachedError";
  }
}

/**
 * Server's malware scan found a threat and rejected the upload before
 * storing it (error_code "MALWARE_DETECTED", ADR-015). Not retryable with
 * the same file content.
 */
export class MalwareDetectedError extends SafeShareError {
  constructor(message = "Malware detected", statusCode = 422, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "MalwareDetectedError";
  }
}

/**
 * The requested file was found infected by a scan and is permanently
 * unavailable for download (error_code "FILE_QUARANTINED", ADR-015).
 */
export class FileQuarantinedError extends SafeShareError {
  constructor(message = "File quarantined", statusCode = 410, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "FileQuarantinedError";
  }
}

/**
 * The file's malware scan has not completed yet; the request may succeed
 * on retry (error_code "SCAN_PENDING", ADR-015). Check the Retry-After
 * header for how long to wait.
 */
export class ScanPendingError extends SafeShareError {
  constructor(message = "Malware scan pending", statusCode = 423, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "ScanPendingError";
  }
}

/**
 * The malware scanner could not be reached or timed out; the request may
 * succeed on retry once the scanner recovers (error_code
 * "SCAN_UNAVAILABLE", ADR-015).
 */
export class ScanUnavailableError extends SafeShareError {
  constructor(message = "Malware scanner unavailable", statusCode = 503, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "ScanUnavailableError";
  }
}

/**
 * A file's malware scan previously errored and the server will not serve
 * it until re-verified (error_code "SCAN_FAILED", ADR-015). Not retryable
 * by the client.
 */
export class ScanFailedError extends SafeShareError {
  constructor(message = "Malware scan failed", statusCode = 403, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "ScanFailedError";
  }
}

/**
 * The server rejected an upload outright because its content can never be
 * scanned — end-to-end encrypted, or larger than the server's scan size
 * limit — and the server requires all uploads to be scannable (error_code
 * "UNSCANNABLE_UPLOAD", ADR-015).
 */
export class UnscannableUploadError extends SafeShareError {
  constructor(
    message = "Upload cannot be scanned for malware",
    statusCode = 422,
    responseBody?: unknown
  ) {
    super(message, statusCode, responseBody);
    this.name = "UnscannableUploadError";
  }
}

/**
 * Chunked upload specific error
 */
export class ChunkedUploadError extends SafeShareError {
  /** Upload ID if available */
  public readonly uploadId?: string;
  /**
   * Machine-readable failure reason reported by the server (e.g.
   * "MALWARE_DETECTED", "SCAN_UNAVAILABLE", "ASSEMBLY_RETRIES_EXHAUSTED"),
   * when this error represents a terminal assembly failure (ADR-016). Empty
   * for other kinds of chunked-upload errors (network, timeout, etc).
   */
  public readonly code?: string;

  constructor(
    message = "Chunked upload failed",
    uploadId?: string,
    statusCode?: number,
    responseBody?: unknown,
    code?: string
  ) {
    super(message, statusCode, responseBody);
    this.name = "ChunkedUploadError";
    this.uploadId = uploadId;
    this.code = code;
  }
}

/**
 * Map HTTP response to appropriate error type
 */
export async function handleErrorResponse(response: Response): Promise<never> {
  let body: unknown;
  let message: string;
  let code: string | undefined;

  try {
    body = await response.json();
    message = (body as { error?: string })?.error || response.statusText;
    code = (body as { code?: string })?.code;
  } catch {
    message = response.statusText || `HTTP ${response.status}`;
  }

  // ADR-015 scan-related error codes take priority over the status-code
  // heuristics below: several of them share an HTTP status with an older,
  // differently-meaning error (e.g. FILE_QUARANTINED and the legacy
  // download-limit-reached case both use 410), so the code is the only
  // reliable disambiguator. Mirrors sdk/go/errors.go's newAPIError and
  // sdk/python/safeshare/exceptions.py's raise_for_status.
  switch (code) {
    case "MALWARE_DETECTED":
      throw new MalwareDetectedError(message, response.status, body);
    case "FILE_QUARANTINED":
      throw new FileQuarantinedError(message, response.status, body);
    case "SCAN_PENDING":
      throw new ScanPendingError(message, response.status, body);
    case "SCAN_UNAVAILABLE":
      throw new ScanUnavailableError(message, response.status, body);
    case "SCAN_FAILED":
      throw new ScanFailedError(message, response.status, body);
    case "UNSCANNABLE_UPLOAD":
      throw new UnscannableUploadError(message, response.status, body);
  }

  switch (response.status) {
    case 400:
      throw new ValidationError(message, 400, body);
    case 401:
      // Check if it's password required vs auth error
      if (message.toLowerCase().includes("password")) {
        throw new PasswordRequiredError(message, 401, body);
      }
      throw new AuthenticationError(message, 401, body);
    case 403:
      if (message.toLowerCase().includes("quota")) {
        throw new QuotaExceededError(message, 403, body);
      }
      throw new SafeShareError(message, 403, body);
    case 404:
      throw new NotFoundError(message, 404, body);
    case 410:
      throw new DownloadLimitReachedError(message, 410, body);
    case 413:
      throw new FileTooLargeError(message, 413, body);
    case 429: {
      const retryAfter = parseInt(response.headers.get("Retry-After") || "", 10);
      throw new RateLimitError(message, isNaN(retryAfter) ? undefined : retryAfter, body);
    }
    default:
      throw new SafeShareError(message, response.status, body);
  }
}

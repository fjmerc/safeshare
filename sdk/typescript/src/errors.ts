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
 * Chunked upload specific error
 */
export class ChunkedUploadError extends SafeShareError {
  /** Upload ID if available */
  public readonly uploadId?: string;

  constructor(message = "Chunked upload failed", uploadId?: string, statusCode?: number, responseBody?: unknown) {
    super(message, statusCode, responseBody);
    this.name = "ChunkedUploadError";
    this.uploadId = uploadId;
  }
}

/**
 * Map HTTP response to appropriate error type
 */
export async function handleErrorResponse(response: Response): Promise<never> {
  let body: unknown;
  let message: string;

  try {
    body = await response.json();
    message = (body as { error?: string })?.error || response.statusText;
  } catch {
    message = response.statusText || `HTTP ${response.status}`;
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

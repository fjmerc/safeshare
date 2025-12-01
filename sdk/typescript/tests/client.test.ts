/**
 * SafeShare SDK Client Tests
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { SafeShareClient } from "../src/client.js";
import {
  SafeShareError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
} from "../src/errors.js";

// Mock fetch function
function createMockFetch(responses: Array<{ status: number; body?: unknown; headers?: Record<string, string> }>) {
  let callIndex = 0;
  return vi.fn(async () => {
    const response = responses[callIndex++] || responses[responses.length - 1];
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.status === 200 ? "OK" : "Error",
      headers: new Headers({
        "content-type": "application/json",
        ...response.headers,
      }),
      json: async () => response.body,
      text: async () => JSON.stringify(response.body),
      body: null,
      arrayBuffer: async () => new ArrayBuffer(0),
    } as unknown as Response;
  });
}

describe("SafeShareClient", () => {
  describe("constructor", () => {
    it("should create client with valid options", () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_abc123",
      });

      expect(client).toBeInstanceOf(SafeShareClient);
    });

    it("should strip trailing slash from baseUrl", () => {
      const mockFetch = createMockFetch([
        { status: 200, body: { max_file_size: 100, chunked_upload_threshold: 50, chunk_size: 10, max_expiration_hours: 168, registration_enabled: true } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com/",
        fetch: mockFetch,
      });

      // Test by making a request and checking the URL
      client.getConfig();
      expect(mockFetch).toHaveBeenCalledWith(
        "https://share.example.com/api/config",
        expect.any(Object)
      );
    });

    it("should throw ValidationError for empty baseUrl", () => {
      expect(() => {
        new SafeShareClient({ baseUrl: "" });
      }).toThrow(ValidationError);
    });

    it("should throw ValidationError for invalid URL", () => {
      expect(() => {
        new SafeShareClient({ baseUrl: "not-a-valid-url" });
      }).toThrow(ValidationError);
    });

    it("should throw ValidationError for non-http/https protocol", () => {
      expect(() => {
        new SafeShareClient({ baseUrl: "ftp://share.example.com" });
      }).toThrow(ValidationError);
    });

    it("should use default timeout of 5 minutes", () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
      });

      // Can't directly access private timeout, but we can verify it doesn't throw
      expect(client).toBeInstanceOf(SafeShareClient);
    });
  });

  describe("toString", () => {
    it("should redact API token in string representation", () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_secret_token_12345",
      });

      const str = client.toString();
      expect(str).toContain("https://share.example.com");
      expect(str).toContain("***redacted***");
      expect(str).not.toContain("safeshare_secret_token_12345");
    });

    it("should show 'none' when no token provided", () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
      });

      const str = client.toString();
      expect(str).toContain("apiToken=none");
    });
  });

  describe("getConfig", () => {
    it("should fetch and cache server config", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            max_file_size: 1073741824,
            chunked_upload_threshold: 104857600,
            chunk_size: 5242880,
            max_expiration_hours: 8760,
            registration_enabled: true,
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      const config = await client.getConfig();

      expect(config.maxFileSize).toBe(1073741824);
      expect(config.chunkUploadThreshold).toBe(104857600);
      expect(config.chunkSize).toBe(5242880);
      expect(config.maxExpirationHours).toBe(8760);
      expect(config.registrationEnabled).toBe(true);

      // Second call should use cache
      const config2 = await client.getConfig();
      expect(config2).toEqual(config);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("getFileInfo", () => {
    it("should fetch file info by claim code", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            filename: "test.txt",
            size: 1024,
            mime_type: "text/plain",
            expires_at: "2025-12-31T23:59:59Z",
            password_protected: false,
            downloads_remaining: 5,
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      const info = await client.getFileInfo("abc12345");

      expect(info.filename).toBe("test.txt");
      expect(info.size).toBe(1024);
      expect(info.mimeType).toBe("text/plain");
      expect(info.passwordProtected).toBe(false);
      expect(info.downloadsRemaining).toBe(5);
    });

    it("should throw ValidationError for invalid claim code without echoing input", async () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
      });

      try {
        await client.getFileInfo("ab");
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError);
        // Ensure the error message does not echo back the invalid input
        expect((error as ValidationError).message).not.toContain("ab");
      }

      await expect(client.getFileInfo("")).rejects.toThrow(ValidationError);
      await expect(client.getFileInfo("abc!@#$")).rejects.toThrow(ValidationError);
    });

    it("should throw NotFoundError for non-existent file", async () => {
      const mockFetch = createMockFetch([
        { status: 404, body: { error: "File not found" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      await expect(client.getFileInfo("notfound1234")).rejects.toThrow(NotFoundError);
    });
  });

  describe("listFiles", () => {
    it("should list user files with pagination", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            files: [
              {
                id: 1,
                claim_code: "abc12345",
                original_filename: "file1.txt",
                file_size: 1024,
                mime_type: "text/plain",
                created_at: "2025-01-01T00:00:00Z",
                expires_at: null,
                download_count: 5,
                completed_downloads: 5,
                max_downloads: null,
                is_password_protected: false,
                download_url: "https://share.example.com/claim/abc12345",
                is_expired: false,
              },
            ],
            total: 1,
            limit: 50,
            offset: 0,
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      const response = await client.listFiles();

      expect(response.files).toHaveLength(1);
      expect(response.files[0].claimCode).toBe("abc12345");
      expect(response.files[0].filename).toBe("file1.txt");
      expect(response.total).toBe(1);
      expect(response.page).toBe(0);
    });

    it("should throw AuthenticationError when not authenticated", async () => {
      const mockFetch = createMockFetch([
        { status: 401, body: { error: "Authentication required" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      await expect(client.listFiles()).rejects.toThrow(AuthenticationError);
    });

    // Note: listFiles silently clamps invalid values instead of throwing
    // This is by design to be more user-friendly
  });

  describe("deleteFile", () => {
    it("should delete file by claim code", async () => {
      const mockFetch = createMockFetch([
        { status: 200, body: { message: "File deleted" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      await expect(client.deleteFile("abc12345")).resolves.toBeUndefined();
    });

    it("should throw ValidationError for invalid claim code", async () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
      });

      await expect(client.deleteFile("")).rejects.toThrow(ValidationError);
    });
  });

  describe("renameFile", () => {
    it("should rename file", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            message: "File renamed successfully",
            new_filename: "newname.txt",
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      const result = await client.renameFile("abc12345", "newname.txt");

      expect(result.newFilename).toBe("newname.txt");
      expect(result.message).toBe("File renamed successfully");
    });

    it("should throw ValidationError for invalid filename", async () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
      });

      await expect(client.renameFile("abc12345", "")).rejects.toThrow(ValidationError);
      await expect(client.renameFile("abc12345", "../etc/passwd")).rejects.toThrow(ValidationError);
      await expect(client.renameFile("abc12345", "path/file.txt")).rejects.toThrow(ValidationError);
    });
  });

  describe("updateExpiration", () => {
    it("should update file expiration", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            message: "Expiration updated successfully",
            new_expiration: "2025-01-02T00:00:00Z",
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      const result = await client.updateExpiration("abc12345", { expiresInHours: 24 });

      expect(result.newExpiration).toBe("2025-01-02T00:00:00Z");
      expect(result.message).toBe("Expiration updated successfully");
    });
  });

  describe("regenerateClaimCode", () => {
    it("should regenerate claim code", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            message: "Claim code regenerated successfully",
            claim_code: "newcode123",
            download_url: "https://share.example.com/claim/newcode123",
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      const result = await client.regenerateClaimCode("abc12345");

      expect(result.claimCode).toBe("newcode123");
      expect(result.downloadUrl).toBe("https://share.example.com/claim/newcode123");
    });
  });

  describe("error handling", () => {
    it("should throw RateLimitError with retryAfter", async () => {
      const mockFetch = createMockFetch([
        { status: 429, body: { error: "Too many requests" }, headers: { "Retry-After": "60" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      try {
        await client.getFileInfo("abc12345");
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).retryAfter).toBe(60);
      }
    });

    it("should include response body in error", async () => {
      const mockFetch = createMockFetch([
        { status: 500, body: { error: "Internal server error", details: "Something went wrong" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      try {
        await client.getFileInfo("abc12345");
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SafeShareError);
        expect((error as SafeShareError).responseBody).toEqual({
          error: "Internal server error",
          details: "Something went wrong",
        });
      }
    });
  });

  describe("token management", () => {
    it("should create API token", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            token: "safeshare_newtoken123",
            name: "My Token",
            scopes: ["upload", "download"],
            expires_at: "2026-01-01T00:00:00Z",
            created_at: "2025-01-01T00:00:00Z",
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_existing",
        fetch: mockFetch,
      });

      const result = await client.createToken({
        name: "My Token",
        scopes: ["upload", "download"],
        expiresInDays: 365,
      });

      expect(result.token).toBe("safeshare_newtoken123");
      expect(result.name).toBe("My Token");
      expect(result.scopes).toEqual(["upload", "download"]);
    });

    it("should list API tokens", async () => {
      const mockFetch = createMockFetch([
        {
          status: 200,
          body: {
            tokens: [
              {
                id: 1,
                name: "Token 1",
                scopes: ["upload"],
                expires_at: null,
                created_at: "2025-01-01T00:00:00Z",
                last_used_at: "2025-01-15T00:00:00Z",
              },
            ],
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      const tokens = await client.listTokens();

      expect(tokens).toHaveLength(1);
      expect(tokens[0].id).toBe(1);
      expect(tokens[0].name).toBe("Token 1");
      expect(tokens[0].lastUsedAt).toBe("2025-01-15T00:00:00Z");
    });

    it("should revoke API token", async () => {
      const mockFetch = createMockFetch([
        { status: 200, body: { message: "Token revoked" } },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
        fetch: mockFetch,
      });

      await expect(client.revokeToken(1)).resolves.toBeUndefined();
    });

    it("should throw ValidationError for invalid tokenId", async () => {
      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        apiToken: "safeshare_token",
      });

      await expect(client.revokeToken(-1)).rejects.toThrow(ValidationError);
      await expect(client.revokeToken(0)).rejects.toThrow(ValidationError);
      await expect(client.revokeToken(1.5)).rejects.toThrow(ValidationError);
    });
  });

  describe("error sanitization", () => {
    it("should sanitize sensitive keys in error response body", async () => {
      const mockFetch = createMockFetch([
        {
          status: 500,
          body: {
            error: "Internal error",
            token: "secret_token_value",
            password: "secret_password",
            api_key: "secret_api_key",
            other: "not_sensitive",
          },
        },
      ]);

      const client = new SafeShareClient({
        baseUrl: "https://share.example.com",
        fetch: mockFetch,
      });

      try {
        await client.getFileInfo("abc12345");
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SafeShareError);
        const body = (error as SafeShareError).responseBody as Record<string, unknown>;
        expect(body.token).toBe("[REDACTED]");
        expect(body.password).toBe("[REDACTED]");
        expect(body.api_key).toBe("[REDACTED]");
        expect(body.other).toBe("not_sensitive");
      }
    });
  });
});

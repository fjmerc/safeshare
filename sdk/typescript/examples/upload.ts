/**
 * SafeShare SDK - Upload Example
 *
 * Demonstrates file upload with progress tracking.
 *
 * Usage:
 *   npx tsx examples/upload.ts /path/to/file.txt
 */

import { SafeShareClient } from "../src/index.js";

async function main() {
  const filePath = process.argv[2];

  if (!filePath) {
    console.error("Usage: npx tsx examples/upload.ts <file-path>");
    process.exit(1);
  }

  // Create client with API token
  const client = new SafeShareClient({
    baseUrl: process.env.SAFESHARE_URL || "http://localhost:8080",
    apiToken: process.env.SAFESHARE_TOKEN,
  });

  console.log(`Uploading: ${filePath}`);
  console.log(`Server: ${client.toString()}\n`);

  try {
    // Get server config to show limits
    const config = await client.getConfig();
    console.log(`Max file size: ${formatBytes(config.maxFileSize)}`);
    console.log(`Chunked upload threshold: ${formatBytes(config.chunkUploadThreshold)}\n`);

    // Upload with progress tracking
    const result = await client.upload(filePath, {
      expiresInHours: 24,
      downloadLimit: 10,
      onProgress: (progress) => {
        const bar = createProgressBar(progress.percentage);
        const current = formatBytes(progress.bytesUploaded);
        const total = formatBytes(progress.totalBytes);

        let status = `${bar} ${progress.percentage}% (${current}/${total})`;
        if (progress.currentChunk !== undefined) {
          status += ` - Chunk ${progress.currentChunk}/${progress.totalChunks}`;
        }

        process.stdout.write(`\r${status}`);
      },
    });

    console.log("\n\nUpload successful!");
    console.log("─".repeat(40));
    console.log(`Claim Code: ${result.claimCode}`);
    console.log(`Filename: ${result.filename}`);
    console.log(`Size: ${formatBytes(result.size)}`);
    console.log(`MIME Type: ${result.mimeType}`);
    console.log(`Expires: ${result.expiresAt || "Never"}`);
    console.log(`Download Limit: ${result.downloadLimit || "Unlimited"}`);
    console.log(`Password Protected: ${result.passwordProtected}`);
    console.log("─".repeat(40));

    const baseUrl = process.env.SAFESHARE_URL || "http://localhost:8080";
    console.log(`\nDownload URL: ${baseUrl}/claim/${result.claimCode}`);
  } catch (error) {
    console.error("\nUpload failed:", error);
    process.exit(1);
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function createProgressBar(percentage: number, width = 30): string {
  const filled = Math.round((percentage / 100) * width);
  const empty = width - filled;
  return `[${"█".repeat(filled)}${"░".repeat(empty)}]`;
}

main();

/**
 * SafeShare SDK - Download Example
 *
 * Demonstrates file download with progress tracking.
 *
 * Usage:
 *   npx tsx examples/download.ts <claim-code> [destination]
 */

import { SafeShareClient, NotFoundError, PasswordRequiredError } from "../src/index.js";
import * as readline from "node:readline";

async function main() {
  const claimCode = process.argv[2];
  const destination = process.argv[3];

  if (!claimCode) {
    console.error("Usage: npx tsx examples/download.ts <claim-code> [destination]");
    process.exit(1);
  }

  // Create client
  const client = new SafeShareClient({
    baseUrl: process.env.SAFESHARE_URL || "http://localhost:8080",
    apiToken: process.env.SAFESHARE_TOKEN,
  });

  console.log(`Fetching file info for: ${claimCode}\n`);

  try {
    // Get file info first
    const info = await client.getFileInfo(claimCode);

    console.log("File Information:");
    console.log("─".repeat(40));
    console.log(`Filename: ${info.filename}`);
    console.log(`Size: ${formatBytes(info.size)}`);
    console.log(`MIME Type: ${info.mimeType}`);
    console.log(`Expires: ${info.expiresAt || "Never"}`);
    console.log(`Downloads Remaining: ${info.downloadsRemaining ?? "Unlimited"}`);
    console.log(`Password Protected: ${info.passwordProtected}`);
    console.log("─".repeat(40));

    // Determine destination path
    const destPath = destination || `./${info.filename}`;
    console.log(`\nDownloading to: ${destPath}`);

    // Get password if needed
    let password: string | undefined;
    if (info.passwordProtected) {
      password = await promptPassword("Enter password: ");
    }

    // Download with progress
    const savedPath = await client.download(claimCode, destPath, {
      password,
      onProgress: (progress) => {
        const bar = createProgressBar(progress.percentage);
        const current = formatBytes(progress.bytesDownloaded);
        const total = progress.totalBytes > 0 ? formatBytes(progress.totalBytes) : "?";
        const pct = progress.percentage >= 0 ? `${progress.percentage}%` : "?%";

        process.stdout.write(`\r${bar} ${pct} (${current}/${total})`);
      },
    });

    console.log("\n\nDownload complete!");
    console.log(`Saved to: ${savedPath}`);
  } catch (error) {
    if (error instanceof NotFoundError) {
      console.error("\nFile not found. It may have expired or been deleted.");
    } else if (error instanceof PasswordRequiredError) {
      console.error("\nIncorrect password.");
    } else {
      console.error("\nDownload failed:", error);
    }
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
  if (percentage < 0) {
    return `[${"?".repeat(width)}]`;
  }
  const filled = Math.round((percentage / 100) * width);
  const empty = width - filled;
  return `[${"█".repeat(filled)}${"░".repeat(empty)}]`;
}

function promptPassword(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

main();

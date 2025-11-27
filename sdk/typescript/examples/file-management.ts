/**
 * SafeShare SDK - File Management Example
 *
 * Demonstrates file listing, renaming, updating expiration, and deletion.
 *
 * Usage:
 *   npx tsx examples/file-management.ts
 *
 * Requires SAFESHARE_TOKEN environment variable.
 */

import { SafeShareClient, AuthenticationError } from "../src/index.js";

async function main() {
  const apiToken = process.env.SAFESHARE_TOKEN;

  if (!apiToken) {
    console.error("Error: SAFESHARE_TOKEN environment variable is required.");
    console.error("Create a token in the SafeShare web UI and set it:");
    console.error("  export SAFESHARE_TOKEN=safeshare_...");
    process.exit(1);
  }

  const client = new SafeShareClient({
    baseUrl: process.env.SAFESHARE_URL || "http://localhost:8080",
    apiToken,
  });

  console.log("SafeShare File Management Example");
  console.log("═".repeat(50));
  console.log(`Server: ${process.env.SAFESHARE_URL || "http://localhost:8080"}\n`);

  try {
    // List files
    console.log("📁 Listing your files...\n");
    const response = await client.listFiles(1, 10);

    if (response.files.length === 0) {
      console.log("No files found. Upload some files first!");
      return;
    }

    console.log(`Found ${response.total} file(s) (showing ${response.files.length}):\n`);

    for (const file of response.files) {
      console.log("─".repeat(40));
      console.log(`ID: ${file.id}`);
      console.log(`Claim Code: ${file.claimCode}`);
      console.log(`Filename: ${file.filename}`);
      console.log(`Size: ${formatBytes(file.size)}`);
      console.log(`MIME Type: ${file.mimeType}`);
      console.log(`Uploaded: ${file.uploadedAt}`);
      console.log(`Expires: ${file.expiresAt || "Never"}`);
      console.log(`Downloads: ${file.downloadCount}/${file.downloadLimit || "∞"}`);
      console.log(`Password: ${file.passwordProtected ? "Yes" : "No"}`);
    }
    console.log("─".repeat(40));

    // Demonstrate management operations on the first file
    const firstFile = response.files[0];
    console.log(`\n📝 Demonstrating operations on: ${firstFile.filename}`);

    // Rename file (append timestamp to make it unique)
    const timestamp = Date.now();
    const ext = firstFile.filename.includes(".") 
      ? "." + firstFile.filename.split(".").pop()
      : "";
    const baseName = firstFile.filename.replace(ext, "");
    const newName = `${baseName}-renamed-${timestamp}${ext}`;

    console.log(`\n1. Renaming to: ${newName}`);
    const renamedFile = await client.renameFile(firstFile.claimCode, newName);
    console.log(`   ✓ Renamed successfully`);

    // Update expiration
    console.log(`\n2. Setting expiration to 48 hours`);
    const updatedFile = await client.updateExpiration(renamedFile.claimCode, {
      expiresInHours: 48,
    });
    console.log(`   ✓ New expiration: ${updatedFile.expiresAt}`);

    // Regenerate claim code
    console.log(`\n3. Regenerating claim code`);
    const regeneratedFile = await client.regenerateClaimCode(updatedFile.claimCode);
    console.log(`   ✓ Old code: ${updatedFile.claimCode}`);
    console.log(`   ✓ New code: ${regeneratedFile.claimCode}`);

    // Rename back to original
    console.log(`\n4. Renaming back to original: ${firstFile.filename}`);
    await client.renameFile(regeneratedFile.claimCode, firstFile.filename);
    console.log(`   ✓ Restored original name`);

    console.log("\n═".repeat(50));
    console.log("All operations completed successfully!");

    // Note: We don't delete the file in this example to preserve user data
    // Uncomment below to demonstrate deletion:
    // console.log(`\n⚠️  Deleting file: ${regeneratedFile.claimCode}`);
    // await client.deleteFile(regeneratedFile.claimCode);
    // console.log("   ✓ File deleted");

  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error("\n❌ Authentication failed. Check your API token.");
    } else {
      console.error("\n❌ Operation failed:", error);
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

main();

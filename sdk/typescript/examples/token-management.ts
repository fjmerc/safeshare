/**
 * SafeShare SDK - API Token Management Example
 *
 * Demonstrates creating, listing, and revoking API tokens.
 *
 * Usage:
 *   npx tsx examples/token-management.ts
 *
 * Note: Token creation and revocation require session authentication,
 * not API token authentication. This example shows the API structure.
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

  console.log("SafeShare API Token Management Example");
  console.log("═".repeat(50));
  console.log(`Server: ${process.env.SAFESHARE_URL || "http://localhost:8080"}\n`);

  try {
    // List existing tokens
    console.log("🔑 Listing your API tokens...\n");
    const tokens = await client.listTokens();

    if (tokens.length === 0) {
      console.log("No API tokens found.");
    } else {
      console.log(`Found ${tokens.length} token(s):\n`);

      for (const token of tokens) {
        console.log("─".repeat(40));
        console.log(`ID: ${token.id}`);
        console.log(`Name: ${token.name}`);
        console.log(`Scopes: ${token.scopes.join(", ")}`);
        console.log(`Created: ${token.createdAt}`);
        console.log(`Expires: ${token.expiresAt || "Never"}`);
        console.log(`Last Used: ${token.lastUsedAt || "Never"}`);
      }
      console.log("─".repeat(40));
    }

    // Note about token creation
    console.log("\n📌 Note: Creating and revoking tokens requires session authentication.");
    console.log("   Use the SafeShare web UI to manage tokens, or authenticate with a session.");

    console.log("\nExample code for creating a token (requires session auth):");
    console.log(`
  const newToken = await client.createToken({
    name: "My Automation Token",
    scopes: ["upload", "download", "manage"],
    expiresInDays: 90,
  });

  console.log("New token (save this!):", newToken.token);
`);

    console.log("\n═".repeat(50));
    console.log("Token listing completed!");

  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error("\n❌ Authentication failed. Check your API token.");
    } else {
      console.error("\n❌ Operation failed:", error);
    }
    process.exit(1);
  }
}

main();

import { createRemoteJWKSet, jwtVerify } from 'jose';
import util from 'util';

// Note: This script simulates the CLIENT side logic.
// In a real scenario, this would be the "Cursor" or "Claude Desktop" app.

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const AUTH_SERVER = 'https://localhost:3000';
const MCP_SERVER = 'http://localhost:3001';
const CLIENT_ID = 'mcp_client';
const REDIRECT_URI = 'https://oauth.pstmn.io/v1/callback'; // Must match server config

async function runTest() {
    console.log("🚀 Starting verification flow...");

    // 1. We assume the user has logged in manually or we can't easily simulate browser interaction here purely with fetch 
    // without parsing HTML forms (CSRF etc).
    // So for this automated test, we will cheat slightly:
    // We will verify the MCP server rejects unauthenticated requests first.

    console.log("\n1️⃣ Testing MCP Access without Token...");
    try {
        const res = await fetch(`${MCP_SERVER}/mcp/sse`);
        if (res.status === 401) {
            console.log("✅ MCP correctly rejected unauthenticated request (401).");
        } else {
            console.error("❌ MCP did not reject request! Status:", res.status);
        }
    } catch (e) {
        console.error("Error connecting to MCP:", e.message);
    }

    // 2. To get a token, we usually need a browser.
    // However, looking at the plan: "Manual Verification: Login Flow".
    // This script can just Print instructions for the user if we can't fully automate the UI login.

    console.log("\n2️⃣ Manual Verification Required for Token Generation");
    console.log(`   Detailed steps:`);
    console.log(`   1. Open Browser: ${AUTH_SERVER}/auth?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${REDIRECT_URI}`);
    console.log(`   2. Login with email: test@example.com, password: password`);
    console.log(`   3. Copy the 'code' parameter from the URL you are redirected to.`);

    // We can allow the user to input the code here if we were interactive, but we are in a non-interactive shell often.
    // So instead, we will just simulate the "Exchange" part if we HAD a code.
    // ...

    console.log("\nℹ️ For automated testing of the API, we need a valid JWT.");
    console.log("   Since we cannot interactively login in this script, please follow the manual steps.");

    // 3. Verify JWKS Endpoint works
    console.log("\n3️⃣ Verifying Auth Server JWKS...");
    try {
        const res = await fetch(`${AUTH_SERVER}/jwks`); // or .well-known/jwks.json
        // Provider usually exposes it at /jwks based on our log "check /.well-known/openid-configuration" 
        // which points to it.
        if (res.ok) {
            const jwks = await res.json();
            console.log("✅ JWKS fetched successfully.");
            console.log("   Keys found:", jwks.keys.length);
        } else {
            // Try standard path
            const res2 = await fetch(`${AUTH_SERVER}/.well-known/jwks.json`); // Default for some
            if (res2.ok) console.log("✅ JWKS fetched at /.well-known/jwks.json");
            else console.error("❌ Could not fetch JWKS. Status:", res.status);
        }
    } catch (e) {
        console.error("❌ Error fetching JWKS:", e.message);
    }
}

runTest();

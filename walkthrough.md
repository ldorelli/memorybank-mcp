# MemoryBank: Completed Architecture & Walkthrough

We have successfully implemented **MemoryBank**, a secure MCP Server with a custom OIDC Authentication Provider.

## Architecture

1.  **Auth Server** (`/auth-server`):
    *   **Role**: OIDC Provider. Handles Login, Consent, and Token Issuance.
    *   **Features**:
        *   Supports Dynamic Client Registration (DCR).
        *   Custom Login & Consent UI.
        *   Secure HTTP Only/Lax Cookies (works on Localhost & Prod).
    *   **Endpoints**:
        *   `/.well-known/openid-configuration`: Discovery.
        *   `/jwks`: Public Signing Keys.
        *   `/auth`: Authorization Endpoint.

2.  **MCP Server** (`/mcp-server`):
    *   **Role**: Provides the `save_note` tool.
    *   **Security**: Verifies JWTs signed by Auth Server.
    *   **Discovery**: Advertises OAuth endpoints in `capabilities`.

3.  **Database** (PostgreSQL):
    *   Shared by both services.
    *   Stores `users`, `notes`, and OIDC sessions (`oauth_payloads`).

## Local Development (Docker)

We have verified the stack using Docker Compose.

1.  **Start Services**:
    ```bash
    docker-compose up --build
    ```
2.  **Verify Auth Server**:
    *   Retrieve configuration: `curl http://localhost:3000/.well-known/openid-configuration`
3.  **Verify MCP Server**:
    *   Check logs: `docker-compose logs mcp-server` -> "MCP Server running on port 3001"

## Deployment (Railway)

The repository is configured for Railway deployment with `railway.toml` files.

**Steps**:
1.  **Push to GitHub**.
2.  **Create New Project** on Railway.
3.  **Add Services**:
    *   **Database**: Add PostgreSQL.
    *   **Auth Server**: Connect GitHub Repo, Root Directory = `/auth-server`.
    *   **MCP Server**: Connect GitHub Repo, Root Directory = `/mcp-server`.
4.  **Configure Environment Variables**:

    | Variable | Service | Value (Example) |
    | :--- | :--- | :--- |
    | `DATABASE_URL` | Both | `postgresql://...` (Railway provides this) |
    | `ISSUER` | Auth Server | `https://your-auth-server.up.railway.app` |
    | `COOKIE_KEYS` | Auth Server | `secret1,secret2` |
    | `AUTH_SERVER_URL` | MCP Server | `https://your-auth-server.up.railway.app` |
    | `JWKS_URL` | MCP Server | `https://your-auth-server.up.railway.app/jwks` |

## 4. Final Updates (Sign Up & Verification)
**Goal**: Allow users to register accounts and ensure secure cookies work in both Local (HTTP) and Production (HTTPS) environments.

**Changes:**
1.  **Architecture**: Configured `auth-server` to run on HTTP universally (relying on Railway's SSL termination in prod).
2.  **Cookie Security**: Implemented dynamic `secure` flag:
    *   `secure: false` (Development/HTTP)
    *   `secure: true` (Production/HTTPS)
3.  **Sign Up Flow**: Created `signup.ejs` and backend logic to hash passwords and create users.

**Verification Success:**
*   [x] **Local**: `docker-compose up` (HTTP). I successfully created an account and logged in.
*   [x] **Production (Railway)**: Fully Deployed & Verified.
    *   Auth Server: Issues JWT access tokens with `resourceIndicators`.
    *   MCP Server: Issues 4 tools (`save_memory`, `list_memories`, `search_memories`, `delete_memory`) via proper `StreamableHTTPServerTransport`.

## 5. Journey Retrospective: Summary of Challenges & Solutions

We encountered several complex issues during implementation. Here is a summary of the key hurdles and how we solved them:

### 1. OIDC Configuration & Cookies
*   **Challenge**: Cookies were not being set correctly in production vs localhost.
*   **Reason**: `secure: true` requires HTTPS, but Railway terminates SSL at the edge, so the internal app sees HTTP.
*   **Solution**: Dynamic cookie configuration based on `NODE_ENV`. `SameSite: Lax` + `proxy: true` in `oidc-provider` config properly handles the proxied requests.

### 2. Authorization Loop & Consent
*   **Challenge**: The client entered an infinite loop of `access_denied` or repeated consent screens.
*   **Reason 1**: The initial custom consent policy (`native_client_prompt`) was forcing repeated interactions.
*   **Reason 2**: MCP clients (like Claude/Gateway) sometimes make authorization requests without `scope` parameters, which `oidc-provider` rejects by default.
*   **Solution**:
    *   Removed custom policy in favor of standard oidc-provider behavior.
    *   Added **middleware** to inject default scopes (`openid memories:read memories:write`) if the client sends none.
    *   Updated `consent.ejs` to properly display and grant these custom scopes.

### 3. Token Format (Opaque vs JWT for MCP)
*   **Challenge**: The MCP Server rejected tokens with "Invalid Compact JWS".
*   **Reason**: By default, `oidc-provider` (especially v8+) issues **Opaque** access tokens (random strings) designed for introspection, but standardized MCP servers expect **JWTs** for stateless verification.
*   **Solution**: Configured the `resourceIndicators` feature (the correct way in v8) to mandate `accessTokenFormat: 'jwt'` for our resource server.

### 4. JWKS & Security
*   **Challenge**: "Key modulus length" errors and security risks.
*   **Reason**: Using short keys or hardcoded keys in source control.
*   **Solution**:
    *   Generated proper 2048-bit RSA keys.
    *   Implemented `process.env.JWKS_PRIVATE_KEY` to load keys from environment variables in production, keeping the repo secret-free.
    *   Fixed MCP server's `JWKS_URL` to point to the Auth Server (not itself).

### 5. MCP Protocol (SSE vs Streamable HTTP)
*   **Challenge**: Client got `404` errors when POSTing to `/`.
*   **Reason**: We implemented the legacy SSE-only transport (`SSEServerTransport`), but the client was using the modern **MCP Streamable HTTP** protocol (POST JSON-RPC).
*   **Solution**:
    *   Switched to `StreamableHTTPServerTransport`.
    *   Implemented proper POST handlers at `/` and `/mcp`.
    *   Added aliases (`/sse`, `/messages`) to ensure compatibility with various client implementations.
    *   Added full Server Metadata (`serverDescription`, `title`) to satisfy robust client requirements.

## Codebase Highlights

*   **Security**: All secrets are moved to `process.env`. Passwords are hashed with `scrypt`.
*   **Git**: `.gitignore` is set up to prevent leakage of keys and logs.
*   **Configuration**:
    *   `auth-server/index.js`: Universal HTTP + JWT issuance via `resourceIndicators`.
    *   `mcp-server/index.js`: Universal Transport (HTTP + SSE) + Proper Metadata.


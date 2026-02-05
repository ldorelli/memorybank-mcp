# MemoryBank: Secure MCP & OAuth Server Implementation Plan

## Goal Description
Build a secure architecture for "MemoryBank" - a system to store and retrieve memory notes using MCP, consisting of two services sharing a PostgreSQL database:
1.  **Auth Server**: OIDC Provider using `node-oidc-provider` to issue JWTs.
2.  **MCP Server**: Exposes AI tools (`save_note`) protected by JWT validation from the Auth Server.

## User Review Required
> [!IMPORTANT]
> **Database Schema**: We are using a shared database approach for simplicity.
> **Encryption**: `oauth_payloads` usually contains session data. `node-oidc-provider` can encrypt sensitive fields. For this MVP, we will rely on the provider's default protections, but we can verify if the library supports adapter-level encryption if strictly required.

> [!NOTE]
> **Ports**:
> - Auth Server: 3000
> - MCP Server: 3001
> - Postgres: 5432

## Proposed Changes

### Infrastructure & Documentation
#### [NEW] [docker-compose.yml](file:///home/lfdorelli/memorymcp/docker-compose.yml)
- PostgreSQL service configuration.
- Volume persistence.

#### [NEW] [init.sql](file:///home/lfdorelli/memorymcp/init.sql)
- SQL script to initialize tables: `users`, `oauth_payloads`, `notes`.

#### [NEW] [README.md](file:///home/lfdorelli/memorymcp/README.md)
- **Local Development**: Guide on how to run `docker-compose up` and start services.
- **Testing**: How to run `test_flow.js`.
- **Deployment**: Step-by-step for Railway (Auth Server first, then MCP Server).

## Part 6: UX/UI Overhaul & Standalone Signup

### Auth Server
#### [MODIFY] [index.js](file:///home/lfdorelli/memorymcp/auth-server/index.js)
- Add `GET /signup` (Standalone)
- Add `POST /signup` (Standalone)
- Serve static assets (logo, styles)

#### [MODIFY] [signup.ejs](file:///home/lfdorelli/memorymcp/auth-server/views/signup.ejs)
- Support standalone mode (no `uid` required in form action).
- Apply new "Pastel-Retro" styles.

#### [MODIFY] [login.ejs](file:///home/lfdorelli/memorymcp/auth-server/views/login.ejs)
- Apply new "Pastel-Retro" styles.

#### [NEW] [style.css](file:///home/lfdorelli/memorymcp/auth-server/public/style.css)
- Define variables for Pastel Palette.
- Import 'VT323' font.
- Pixel-art styled components.

### Auth Server (`/auth-server`)
#### [NEW] [package.json](file:///home/lfdorelli/memorymcp/auth-server/package.json)
- Dependencies: `node-oidc-provider`, `pg`, `ejs`, `dotenv`.

#### [NEW] [db_init.js](file:///home/lfdorelli/memorymcp/auth-server/db_init.js)

### Feature: User Registration (Sign Up)
#### [NEW] [signup.ejs](file:///home/lfdorelli/memorymcp/auth-server/views/signup.ejs)
#### [MODIFY] [auth-server/index.js](file:///home/lfdorelli/memorymcp/auth-server/index.js)
*   Add `node:crypto` import
*   Add `POST /interaction/:uid/login` logic to verify password (using scrypt)
*   Add `GET /interaction/:uid/signup` route
*   Add `POST /interaction/:uid/signup` route (creates user with hashed password)
#### [MODIFY] [login.ejs](file:///home/lfdorelli/memorymcp/auth-server/views/login.ejs)
*   Link "Create one" to `/interaction/:uid/signup`

#### [NEW] [index.js](file:///home/lfdorelli/memorymcp/auth-server/index.js)
- OIDC Provider setup.
- Configuration for clients (`mcp_client`).
- `GET /jwks` endpoint.
- `GET /auth` login page rendering.

#### [NEW] [adapter.js](file:///home/lfdorelli/memorymcp/auth-server/adapter.js)
- Custom Redis-like adapter using PostgreSQL for OIDC session persistence.

#### [NEW] [views/login.ejs](file:///home/lfdorelli/memorymcp/auth-server/views/login.ejs)
- **MemoryBank** branded login form.
- Premium aesthetics (CSS/Tailwind) to look nice.

### MCP Server (`/mcp-server`)
#### [NEW] [package.json](file:///home/lfdorelli/memorymcp/mcp-server/package.json)
- Dependencies: `@modelcontextprotocol/sdk`, `express`, `jose`, `cors`, `dotenv`, `pg`.

#### [NEW] [index.js](file:///home/lfdorelli/memorymcp/mcp-server/index.js)
- Express server setup.
- SSEServerTransport for MCP.
- JWT Verification middleware using `jose`.
- Tool definition: `save_note` (Store snaps/quick memory notes).

## Verification Plan

### Automated Tests
- `test_flow.js`:
    1.  Register/Seed a user in DB.
    2.  Simulate OAuth flow to get Access Token.
    3.  Call MCP Server with Token.
    4.  Verify Note is saved in DB.

### Manual Verification
1.  **Login Flow**:
    - Open Browser to `http://localhost:3000/auth?client_id=mcp_client...`
    - Login with test credentials.
    - Receive Authorization Code -> Exchange for Token.
2.  **MCP Tool**:
    - Use token to call `http://localhost:3001/mcp`.
    - Verify note appears in Database.
3.  **Deployment**:
    - Follow `README.md` steps to deploy to Railway and verify live URLs.

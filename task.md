# Secure MCP & OAuth Server

## Part 0: Initialization & Planning
- [x] Initialize Monorepo structure (`mcp-project/`, `auth-server/`, `mcp-server/`)
- [x] Create `docker-compose.yml` for PostgreSQL
- [x] Create Implementation Plan (Polish Specs)

## Part 1: Database Setup
- [x] Define SQL schemas (Users, OAuth Sessions, Notes)
- [/] Verify Docker PostgreSQL connection

## Part 2: Auth Server (`/auth`)
- [x] Setup Node.js project for `auth-server`
- [x] Install dependencies (`node-oidc-provider`, `pg`, etc.)
- [x] Implement `adapter.js` for PostgreSQL persistence
- [x] Configure `node-oidc-provider` (Clients, Keys)
- [x] Create Login UI (`views/login.ejs`)
- [ ] specific Endpoint: `GET /jwks`

## Part 3: MCP Server (`/mcp`)
- [x] Setup Node.js project for `mcp-server`
- [x] Install dependencies (`@modelcontextprotocol/sdk`, `express`, `jose`)
- [x] Implement Authentication Middleware (JWT Verification)
- [x] Implement `save_note` tool
- [x] Setup SSE Server Transport

## Part 4: Integration & Verification
- [x] Helper script to seed users/clients
- [x] Verify Auth Flow (Login -> Token)
- [x] Fix OIDC cookie issue on localhost (Upgraded to HTTPS + SameSite=Lax + Consent Screen)
- [x] Verify MCP Access (Token -> Save Note)
- [x] Implement Dynamic Client Registration


## Part 5: Deployment Preparation (Railway)
- [x] Prepare Dockerfiles (if needed or standard start scripts)
- [x] Create deploy workflow
- [x] Verify Environment Variables
- [x] Local Docker Verification
- [x] Implement Sign Up Flow
    - [x] Create signup.ejs
    - [x] Add signup routes in index.js
    - [x] Link login.ejs to signup
    - [x] Verify locally
- [x] Final Deployment & Test
- [x] Verify Local Docker Deployment
- [x] Create Railway deployment config (railway.toml)
- [x] Security Audit (gitignore, secrets scan)

## Part 6: UX/UI Overhaul & Standalone Signup
- [/] Implement Standalone Signup (Direct Web access)
- [/] Visual Refresh: "Pixelated/Game/Pastel-Retro" Theme
    - [x] Create Logo (Pixel Art Style)
    - [/] Update Typography (Google Fonts: VT323 or similar)
    - [/] Update Colors (Pastel Palette)
    - [/] Refactor CSS for `login.ejs`, `signup.ejs`, `consent.ejs`
- [ ] Verify Standalone Signup Flow

# MemoryBank MCP 🧠

> **A secure, personal memory vault for your AI assistants.**

<div align="center">
  <img src="./logo.svg" alt="MemoryBank Logo" width="200" style="image-rendering: pixelated;">
  <p><em>Secure. Private. Retro-Chic.</em></p>
</div>

MemoryBank allows LLMs (via Model Context Protocol) to store, retrieve, and organize "memories" about you in a secure PostgreSQL vault. It features a full OIDC Authentication Server with a custom **Pastel-Retro Pixel Art** UI.

## Features

- **🔐 Secure Authentication**: Custom OIDC Provider with JWT access tokens.
- **🎨 Pastel-Retro UI**: Beautiful pixel-art themed Login, Signup, and Consent screens (`VT323` typography).
- **🚀 Standalone Signup**: Direct account creation at `/signup`.
- **🧠 Memory Tools**: `save_memory`, `list_memories`, `search_memories`, `delete_memory`.
- **🔌 Universal Transport**: Supports both MCP Streamable HTTP (POST) and SSE (GET).
 of an OIDC Auth Server and an MCP Server specifically designed for AI agents.

## Project Structure
- `auth-server/`: OIDC Provider (Node.js + node-oidc-provider)
- `mcp-server/`: MCP Server (Node.js + @modelcontextprotocol/sdk)
- `docker-compose.yml`: PostgreSQL database
- `init.sql`: Database schema initialization

## Local Development

### Prerequisites
- Docker & Docker Compose
- Node.js 20+

### 1. Start the Database
```bash
docker-compose up -d
```
This starts PostgreSQL on port 5432 with the schemas defined in `init.sql`.

### 2. Start the Auth Server
```bash
cd auth-server
npm install
# Generates self-signed certs if missing and starts server
npm start
```
Runs on `https://localhost:3000`.

### 3. Start the MCP Server
```bash
cd mcp-server
npm install
npm start
```
Runs on `http://localhost:3001`.

## Testing

### Automated Flow
Run the test script to verify the full flow (User -> Login -> Token -> Save Note):
```bash
node test_flow.js
```

### Manual Verification
1.  **Login**: Go to `https://localhost:3000/auth?client_id=mcp_client&response_type=code&scope=openid&redirect_uri=https://oauth.pstmn.io/v1/callback`
2.  **MCP**: Use the token to access the MCP tools.

## Deployment (Railway)

1.  **Database**: Create a PostgreSQL service.
2.  **Auth Server**: Deploy `auth-server/`. Set `DATABASE_URL`.
3.  **MCP Server**: Deploy `mcp-server/`. Set `JWKS_URL` to `<auth-url>/jwks`.

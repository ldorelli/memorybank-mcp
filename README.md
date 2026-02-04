# MemoryBank: Secure MCP & OAuth Server

A secure architecture for storing and retrieving memory notes using MCP, consisting of an OIDC Auth Server and an MCP Server specifically designed for AI agents.

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

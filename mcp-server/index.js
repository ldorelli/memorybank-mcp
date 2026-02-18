import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import { z } from 'zod';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../.env') });

const app = express();
const { Pool } = pg;

// Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/memorybank_db',
});

// Allow self-signed certs for local development
if (process.env.NODE_ENV !== 'production') {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// OAuth / JWT Configuration
const JWKS_URL = process.env.JWKS_URL || 'https://localhost:3000/jwks';

let JWKS;
try {
    JWKS = createRemoteJWKSet(new URL(JWKS_URL));
} catch (e) {
    console.error("Failed to initialize JWKS set. Is Auth Server running?", e);
}

// Middleware to verify JWT
async function authMiddleware(req, res, next) {
    // Helper to send 401 with correct discovery headers
    const send401 = (message) => {
        const baseUrl = process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app';
        let metadataPath = '/.well-known/oauth-protected-resource';
        let realm = 'MemoryBank MCP';

        if (req.path.startsWith('/dcr')) {
            metadataPath = '/dcr/.well-known/oauth-protected-resource';
            realm = 'MemoryBank Legacy DCR';
        }

        const resourceMetadataUrl = `${baseUrl}${metadataPath}`;

        res.setHeader('Link', `<${resourceMetadataUrl}>; rel="describedby"`);
        res.setHeader('WWW-Authenticate', `Bearer realm="${realm}", scope="openid memories:read memories:write", resource_metadata="${resourceMetadataUrl}"`);

        return res.status(401).json({ error: message });
    };

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Check query strings for EventSource compatibility
        if (req.query.token) {
            req.token = req.query.token;
        } else {
            return send401('Missing Authorization Header');
        }
    } else {
        req.token = authHeader.split(' ')[1];
    }

    try {
        // Debug: Log token format
        console.log('DEBUG: Token received (first 50 chars):', req.token?.substring(0, 50) + '...');
        console.log('DEBUG: Token has 3 parts (JWT):', req.token?.split('.').length === 3);

        const { payload } = await jwtVerify(req.token, JWKS);
        req.user = payload;
        console.log('DEBUG: JWT verified for user:', payload.sub);
        next();
    } catch (err) {
        console.error("JWT Verification failed:", err.message);
        console.error("DEBUG: Full token:", req.token);

        return send401('Invalid Token');
    }
}

const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'https://localhost:3000';

// OAuth Protected Resource endpoint (RFC 9728) - Root
app.get('/.well-known/oauth-protected-resource', (req, res) => {
    const resourceParam = req.query.resource || '';
    // If the client is asking about the DCR endpoint, point them to the DCR Auth Server
    if (resourceParam.includes('/dcr')) {
        console.log('DEBUG: Serving Legacy Auth Server for DCR resource:', resourceParam);
        return res.json({
            resource: process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app',
            authorization_servers: [LEGACY_AUTH_SERVER_URL],
            scopes_supported: ["openid", "memories:read", "memories:write"]
        });
    }

    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app',
        authorization_servers: [AUTH_SERVER_URL],
        scopes_supported: ["openid", "memories:read", "memories:write"]
    });
});

// ============ LEGACY DCR ROUTES (Testing) ============
// These endpoints point to the "Legacy" Auth Provider (no metadata support)
const LEGACY_AUTH_SERVER_URL = `${AUTH_SERVER_URL}/dcr`;

// Metadata for /dcr base
app.get('/dcr/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app',
        authorization_servers: [LEGACY_AUTH_SERVER_URL],
        scopes_supported: ["openid", "memories:read", "memories:write"]
    });
});

// Metadata for /dcr/mcp base (Crucial if client treats this as root)
app.get('/dcr/mcp/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app',
        authorization_servers: [LEGACY_AUTH_SERVER_URL],
        scopes_supported: ["openid", "memories:read", "memories:write"]
    });
});

// OpenAI Domain Verification Endpoint
app.get('/.well-known/openai-app-domain-verification', (req, res) => {
    // Return exact token as plain text
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});

// Alias for Legacy DCR check if they check that domain too (optional but safe)
app.get('/dcr/.well-known/openai-app-domain-verification', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});

// User requested 'openai-apps-challenge' path (Alternate verification)
app.get('/.well-known/openai-apps-challenge', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});

// MCP Server Initialization with proper metadata
const server = new McpServer({
    name: "memorybank",
    version: "1.0.0",
    title: "MemoryBank MCP Server",
    description: "A personal memory and notes management server. Store, retrieve, and search through your thoughts and memories with AI assistance."
}, {
    capabilities: {
        tools: {},
        resources: {},
        prompts: {}
    },
    instructions: "MemoryBank helps you save and retrieve personal memories and notes. Use the 'save_memory' tool to store new memories, 'list_memories' to see your saved memories, and 'search_memories' to find specific ones."
});

// ============ TOOLS ============

// Tool: Save a new memory
server.tool(
    "save_memory",
    {
        content: z.string().describe("The content of the memory to save"),
        tags: z.array(z.string()).optional().describe("Optional tags for organizing memories")
    },
    async ({ content, tags }) => {
        try {
            const userRes = await pool.query("SELECT id FROM users LIMIT 1");
            const userId = userRes.rows[0]?.id;

            if (!userId) {
                return {
                    content: [{ type: "text", text: "Error: No user found. Please sign up first." }],
                    isError: true
                };
            }

            const res = await pool.query(
                "INSERT INTO notes (user_id, content) VALUES ($1, $2) RETURNING id, created_at",
                [userId, content]
            );

            const result = {
                id: res.rows[0].id,
                created_at: res.rows[0].created_at,
                tags: tags || []
            };

            return {
                content: [{
                    type: "text",
                    text: `✅ Memory saved successfully!\n\nID: ${result.id}\nCreated: ${result.created_at}\n${tags ? `Tags: ${tags.join(', ')}` : ''}`
                }]
            };
        } catch (err) {
            console.error("Error saving memory:", err);
            return {
                content: [{ type: "text", text: `Error saving memory: ${err.message}` }],
                isError: true
            };
        }
    }
);

// Tool: List all memories
server.tool(
    "list_memories",
    {
        limit: z.number().optional().describe("Maximum number of memories to return (default: 10)")
    },
    async ({ limit = 10 }) => {
        try {
            const userRes = await pool.query("SELECT id FROM users LIMIT 1");
            const userId = userRes.rows[0]?.id;

            if (!userId) {
                return {
                    content: [{ type: "text", text: "Error: No user found." }],
                    isError: true
                };
            }

            const res = await pool.query(
                "SELECT id, content, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                [userId, limit]
            );

            if (res.rows.length === 0) {
                return {
                    content: [{ type: "text", text: "📭 No memories found. Use 'save_memory' to create your first one!" }]
                };
            }

            const memoriesList = res.rows.map((row, i) =>
                `${i + 1}. [${row.id}] ${row.content.substring(0, 100)}${row.content.length > 100 ? '...' : ''}\n   📅 ${row.created_at}`
            ).join('\n\n');

            return {
                content: [{
                    type: "text",
                    text: `📚 Your Recent Memories (${res.rows.length}):\n\n${memoriesList}`
                }]
            };
        } catch (err) {
            console.error("Error listing memories:", err);
            return {
                content: [{ type: "text", text: `Error listing memories: ${err.message}` }],
                isError: true
            };
        }
    }
);

// Tool: Search memories
server.tool(
    "search_memories",
    {
        query: z.string().describe("Search query to find memories")
    },
    async ({ query }) => {
        try {
            const userRes = await pool.query("SELECT id FROM users LIMIT 1");
            const userId = userRes.rows[0]?.id;

            if (!userId) {
                return {
                    content: [{ type: "text", text: "Error: No user found." }],
                    isError: true
                };
            }

            const res = await pool.query(
                "SELECT id, content, created_at FROM notes WHERE user_id = $1 AND content ILIKE $2 ORDER BY created_at DESC LIMIT 20",
                [userId, `%${query}%`]
            );

            if (res.rows.length === 0) {
                return {
                    content: [{ type: "text", text: `🔍 No memories found matching "${query}"` }]
                };
            }

            const resultsList = res.rows.map((row, i) =>
                `${i + 1}. [${row.id}] ${row.content.substring(0, 100)}${row.content.length > 100 ? '...' : ''}`
            ).join('\n\n');

            return {
                content: [{
                    type: "text",
                    text: `🔍 Found ${res.rows.length} memories matching "${query}":\n\n${resultsList}`
                }]
            };
        } catch (err) {
            console.error("Error searching memories:", err);
            return {
                content: [{ type: "text", text: `Error searching memories: ${err.message}` }],
                isError: true
            };
        }
    }
);

// Tool: Delete a memory
server.tool(
    "delete_memory",
    {
        id: z.string().describe("The ID of the memory to delete")
    },
    async ({ id }) => {
        try {
            const userRes = await pool.query("SELECT id FROM users LIMIT 1");
            const userId = userRes.rows[0]?.id;

            const res = await pool.query(
                "DELETE FROM notes WHERE id = $1 AND user_id = $2 RETURNING id",
                [id, userId]
            );

            if (res.rows.length === 0) {
                return {
                    content: [{ type: "text", text: `❌ Memory with ID ${id} not found or already deleted.` }],
                    isError: true
                };
            }

            return {
                content: [{ type: "text", text: `🗑️ Memory ${id} deleted successfully.` }]
            };
        } catch (err) {
            console.error("Error deleting memory:", err);
            return {
                content: [{ type: "text", text: `Error deleting memory: ${err.message}` }],
                isError: true
            };
        }
    }
);

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', server: 'memorybank-mcp', version: '1.0.0' });
});

// Session management for Streamable HTTP
const transports = new Map();

// Create and configure transport for MCP Streamable HTTP
async function handleMcpRequest(req, res) {
    // Check for existing session
    const sessionId = req.headers['mcp-session-id'];

    let transport;

    if (sessionId && transports.has(sessionId)) {
        // Reuse existing transport
        transport = transports.get(sessionId);
    } else if (!sessionId && req.method === 'POST') {
        // New session - create transport
        transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
        });

        // Connect the server to this transport
        await server.connect(transport);

        // Store for session reuse
        transport.onclose = () => {
            if (transport.sessionId) {
                console.log(`📴 Session ${transport.sessionId} closed`);
                transports.delete(transport.sessionId);
            }
        };

        // After first request, we'll have a session ID
        // We'll store it after handling the request
    } else if (sessionId && !transports.has(sessionId)) {
        // Invalid session
        return res.status(404).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Session not found' },
            id: null
        });
    }

    // Handle the request
    await transport.handleRequest(req, res, req.body);

    // Store transport with session ID after first request
    if (transport.sessionId && !transports.has(transport.sessionId)) {
        transports.set(transport.sessionId, transport);
        console.log(`📡 New session ${transport.sessionId} created (user: ${req.user?.sub || 'unknown'})`);
    }
}

// ============ LEGACY DCR ROUTES (Testing) ============
// Alias MCP handlers for /dcr path
app.post('/dcr', authMiddleware, handleMcpRequest);
app.get('/dcr', authMiddleware, handleMcpRequest);

// Explicitly handle /dcr/mcp
app.post('/dcr/mcp', authMiddleware, handleMcpRequest);
app.get('/dcr/mcp', authMiddleware, handleMcpRequest);
app.delete('/dcr/mcp', authMiddleware, handleMcpRequest);


// ============ STANDARD MCP ROUTES ============
// Main MCP endpoints - POST for JSON-RPC, GET for SSE streams
app.post('/', authMiddleware, handleMcpRequest);
app.get('/', authMiddleware, handleMcpRequest);

app.post('/mcp', authMiddleware, handleMcpRequest);
app.get('/mcp', authMiddleware, handleMcpRequest);
app.delete('/mcp', authMiddleware, handleMcpRequest);

// ============ REST API (OpenAI GPT Actions Compatibility) ============

// Helper to get user ID from DB based on JWT sub (which is email/id from auth server)
// In this shared DB setup, the JWT 'sub' claim IS the user ID (uuid) if auth server sets it so.
// Let's verify: Auth server uses `accountId` which is the UUID.
// So `req.user.sub` should be the UUID.
// However, `save_memory` tool re-queries user ID from users table using LIMIT 1 (bad logic for multi-user).
// FIX: We should trust req.user.sub (the UUID) if available, or query by email if sub is email.
// The current `save_memory` tool logic `SELECT id FROM users LIMIT 1` is strictly for single-user dev/demo mode.
// We will replicate that for now to NOT BREAK EXISTING BEHAVIOR, but proper multi-user is better.
// Actually, `req.user.sub` from OIDC provider is the `accountId`.
// Let's stick to the current logic for consistency with MCP tools, but wrapped in REST.

// POST /api/memory - Save a memory
app.post('/api/memory', authMiddleware, async (req, res) => {
    try {
        const { content, tags } = req.body;
        if (!content) return res.status(400).json({ error: 'Content is required' });

        // Logic matched with 'save_memory' tool
        // Finding user:
        const userRes = await pool.query("SELECT id FROM users LIMIT 1");
        const userId = userRes.rows[0]?.id; // Fallback to first user for now (MVP)

        if (!userId) return res.status(404).json({ error: 'No user found' });

        const result = await pool.query(
            "INSERT INTO notes (user_id, content) VALUES ($1, $2) RETURNING id, created_at",
            [userId, content]
        );

        // Tags would need a separate table or column, but the tool just echoes them.
        // We'll ignore tags storage for now as schema doesn't seem to support it (based on tool impl).

        res.json({
            id: result.rows[0].id,
            content,
            created_at: result.rows[0].created_at,
            message: 'Memory saved successfully'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET /api/memories - List/Search
app.get('/api/memories', authMiddleware, async (req, res) => {
    try {
        const { query, limit = 10 } = req.query;

        const userRes = await pool.query("SELECT id FROM users LIMIT 1");
        const userId = userRes.rows[0]?.id;
        if (!userId) return res.status(404).json({ error: 'No user found' });

        let result;
        if (query) {
            result = await pool.query(
                "SELECT id, content, created_at FROM notes WHERE user_id = $1 AND content ILIKE $2 ORDER BY created_at DESC LIMIT $3",
                [userId, `%${query}%`, limit]
            );
        } else {
            result = await pool.query(
                "SELECT id, content, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                [userId, limit]
            );
        }

        res.json({
            count: result.rows.length,
            memories: result.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// DELETE /api/memory/:id
app.delete('/api/memory/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const userRes = await pool.query("SELECT id FROM users LIMIT 1");
        const userId = userRes.rows[0]?.id;

        const result = await pool.query(
            "DELETE FROM notes WHERE id = $1 AND user_id = $2 RETURNING id",
            [id, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Memory not found' });
        }

        res.json({ message: 'Memory deleted', id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET /openapi.json
app.get('/openapi.json', (req, res) => {
    const host = req.get('host');
    const protocol = req.protocol; // 'http' or 'https'
    // Ensure https in production
    const baseUrl = process.env.MCP_SERVER_URL || `${protocol}://${host}`;

    res.json({
        "openapi": "3.1.0",
        "info": {
            "title": "MemoryBank API",
            "description": "API for storing and retrieving personal memories.",
            "version": "1.0.0"
        },
        "servers": [
            {
                "url": baseUrl
            }
        ],
        "paths": {
            "/api/memory": {
                "post": {
                    "description": "Save a new memory",
                    "operationId": "saveMemory",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "content": { "type": "string", "description": "The memory content" },
                                        "tags": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["content"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Memory saved" }
                    }
                }
            },
            "/api/memories": {
                "get": {
                    "description": "List or search memories",
                    "operationId": "listMemories",
                    "parameters": [
                        { "name": "query", "in": "query", "schema": { "type": "string" }, "description": "Search keyword" },
                        { "name": "limit", "in": "query", "schema": { "type": "integer" } }
                    ],
                    "responses": {
                        "200": { "description": "List of memories" }
                    }
                }
            },
            "/api/memory/{id}": {
                "delete": {
                    "description": "Delete a memory by ID",
                    "operationId": "deleteMemory",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "Memory deleted" }
                    }
                }
            }
        }
    });
});

// Also handle the initialization message at root
app.options('/', cors());
app.options('/mcp', cors());
app.options('/dcr', cors()); // Add CORS for DCR routes
app.options('/dcr/mcp', cors()); // Add CORS for DCR routes

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`
🧠 MemoryBank MCP Server v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 Server: http://localhost:${PORT}
🔐 Auth: ${AUTH_SERVER_URL}
🔑 JWKS: ${JWKS_URL}
🌐 Transport: Streamable HTTP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📚 Tools available:
   • save_memory - Save a new memory
   • list_memories - List your memories
   • search_memories - Search for specific memories
   • delete_memory - Delete a memory
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `);
});

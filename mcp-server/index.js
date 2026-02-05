import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import { z } from 'zod';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

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
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Check query strings for EventSource compatibility
        if (req.query.token) {
            req.token = req.query.token;
        } else {
            return res.status(401).json({ error: 'Missing Authorization Header' });
        }
    } else {
        req.token = authHeader.split(' ')[1];
    }

    try {
        const { payload } = await jwtVerify(req.token, JWKS);
        req.user = payload;
        next();
    } catch (err) {
        console.error("JWT Verification failed:", err.message);
        return res.status(401).json({ error: 'Invalid Token' });
    }
}

const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'https://localhost:3000';

// OAuth Protected Resource endpoint (RFC 9728)
app.get('/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://memorybank-mcp.up.railway.app',
        authorization_servers: [AUTH_SERVER_URL],
        scopes_supported: ["openid", "memories:read", "memories:write"]
    });
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
            // Get the first user for now (in production, extract from token context)
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

// Root endpoint - provide server info and available endpoints
app.get('/', (req, res) => {
    res.json({
        name: "memorybank",
        version: "1.0.0",
        title: "MemoryBank MCP Server",
        description: "A personal memory and notes management server.",
        endpoints: {
            sse: "/mcp",
            messages: "/mcp/messages",
            health: "/health",
            oauth_metadata: "/.well-known/oauth-protected-resource"
        }
    });
});

// Session management for SSE
const sessions = new Map();

// SSE Endpoint - Main MCP connection (at /mcp)
app.get('/mcp', authMiddleware, async (req, res) => {
    const transport = new SSEServerTransport("/mcp/messages", res);
    const sessionId = transport.sessionId || Date.now().toString();

    sessions.set(sessionId, transport);
    console.log(`📡 Session ${sessionId} connected (user: ${req.user?.sub || 'unknown'})`);

    // Clean up on close
    res.on('close', () => {
        console.log(`📴 Session ${sessionId} closed`);
        sessions.delete(sessionId);
    });

    await server.connect(transport);
});

// Alias: /sse for clients expecting SSE at /sse
app.get('/sse', authMiddleware, async (req, res) => {
    const transport = new SSEServerTransport("/messages", res);
    const sessionId = transport.sessionId || Date.now().toString();

    sessions.set(sessionId, transport);
    console.log(`📡 Session ${sessionId} connected via /sse (user: ${req.user?.sub || 'unknown'})`);

    res.on('close', () => {
        console.log(`📴 Session ${sessionId} closed`);
        sessions.delete(sessionId);
    });

    await server.connect(transport);
});

// Handle incoming messages for SSE transport
app.post('/mcp/messages', authMiddleware, async (req, res) => {
    const sessionId = req.query.sessionId;
    let transport;

    if (sessionId && sessions.has(sessionId)) {
        transport = sessions.get(sessionId);
    } else {
        // Fallback to the last created session for single-client demo
        const keys = Array.from(sessions.keys());
        if (keys.length > 0) {
            transport = sessions.get(keys[keys.length - 1]);
        }
    }

    if (!transport) {
        return res.status(404).json({ error: "Session not found. Please reconnect." });
    }

    await transport.handlePostMessage(req, res);
});

// Alias: /messages for clients using /sse
app.post('/messages', authMiddleware, async (req, res) => {
    const sessionId = req.query.sessionId;
    let transport;

    if (sessionId && sessions.has(sessionId)) {
        transport = sessions.get(sessionId);
    } else {
        const keys = Array.from(sessions.keys());
        if (keys.length > 0) {
            transport = sessions.get(keys[keys.length - 1]);
        }
    }

    if (!transport) {
        return res.status(404).json({ error: "Session not found. Please reconnect." });
    }

    await transport.handlePostMessage(req, res);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`
🧠 MemoryBank MCP Server v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 Server: http://localhost:${PORT}
🔐 Auth: ${AUTH_SERVER_URL}
🔑 JWKS: ${JWKS_URL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📚 Tools available:
   • save_memory - Save a new memory
   • list_memories - List your memories
   • search_memories - Search for specific memories
   • delete_memory - Delete a memory
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `);
});

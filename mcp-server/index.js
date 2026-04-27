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
import { AsyncLocalStorage } from 'node:async_hooks';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Context for passing User Auth to tools
const requestContext = new AsyncLocalStorage();

dotenv.config({ path: join(__dirname, '../.env') });

const app = express();
app.set('trust proxy', true); // Required: Railway terminates SSL, forwards HTTP internally
app.set('strict routing', false);

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
        const baseUrl = process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com';
        let metadataPath = '/.well-known/oauth-protected-resource';
        let realm = 'MemoryBank MCP';

        if (req.path.startsWith('/dcr')) {
            metadataPath = '/dcr/.well-known/oauth-protected-resource';
            realm = 'MemoryBank Legacy DCR';
        } else if (req.path.startsWith('/basicauth')) {
            metadataPath = '/basicauth/.well-known/oauth-protected-resource';
            realm = 'MemoryBank BasicAuth';
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
const LEGACY_AUTH_SERVER_URL = `${AUTH_SERVER_URL}/dcr`;

import { encrypt, decrypt } from './utils/crypto.js';

// Server instance creation factory
// In MCP SDK, a Server instance connects 1-to-1 with a Transport.
// For Web/HTTP Transports where multiple clients can connect simultaneously,
// we MUST create a new McpServer and Transport pair per session.
function createMcpServer() {
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
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized (No User Context)" }], isError: true };
                }

                // Verify Scope
                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub; // The UUID from the Auth Server

                // Encrypt content before storage
                const encryptedContent = encrypt(content);

                const res = await pool.query(
                    "INSERT INTO notes (user_id, content) VALUES ($1, $2) RETURNING id, created_at",
                    [userId, encryptedContent]
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
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized (No User Context)" }], isError: true };
                }

                // Verify Scope
                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:read')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:read' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, content, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                    [userId, limit]
                );

                if (res.rows.length === 0) {
                    return {
                        content: [{ type: "text", text: "📭 No memories found. Use 'save_memory' to create your first one!" }]
                    };
                }

                const memoriesList = res.rows.map((row, i) => {
                    const decryptedContent = decrypt(row.content);
                    return `${i + 1}. [${row.id}] ${decryptedContent.substring(0, 100)}${decryptedContent.length > 100 ? '...' : ''}\n   📅 ${row.created_at}`;
                }).join('\n\n');

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

    // Tool: List all memories (UI Version)
    server.tool(
        "ui_list_memories",
        {
            limit: z.number().optional().describe("Maximum number of memories to return (default: 10)")
        },
        async ({ limit = 10 }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized (No User Context)" }], isError: true };
                }

                // Verify Scope
                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:read')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:read' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, content, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                    [userId, limit]
                );

                if (res.rows.length === 0) {
                    return {
                        content: [{ type: "text", text: "📭 No memories found. Use 'save_memory' to create your first one!" }]
                    };
                }

                const components = [];
                const childIds = [];

                // Add a header
                components.push({
                    id: "memories-header",
                    component: {
                        Text: { text: { literal: `📚 Your Recent Memories (${res.rows.length})` }, usageHint: "h2" }
                    }
                });
                childIds.push("memories-header");

                // Add memories
                res.rows.forEach((row, i) => {
                    const decryptedContent = decrypt(row.content);
                    const memId = `memory-${i}`;
                    components.push({
                        id: memId,
                        component: {
                            Text: {
                                text: { literal: `[${row.id.substring(0, 8)}] ${decryptedContent.substring(0, 100)}${decryptedContent.length > 100 ? '...' : ''}\n📅 ${row.created_at}` },
                                usageHint: "body"
                            }
                        }
                    });
                    childIds.push(memId);
                });

                // Root column to contain all children
                components.push({
                    id: "root",
                    component: {
                        Column: { children: { explicitList: childIds } }
                    }
                });

                const a2ui_payload = [
                    {
                        beginRendering: {
                            surfaceId: "default",
                            root: "root"
                        }
                    },
                    {
                        surfaceUpdate: {
                            surfaceId: "default",
                            components: components
                        }
                    }
                ];

                return {
                    content: [
                        {
                            type: "text",
                            text: `Displayed ${res.rows.length} memories in the UI`
                        },
                        {
                            type: "resource",
                            resource: {
                                uri: "a2ui://memories-list",
                                mimeType: "application/json+a2ui",
                                text: JSON.stringify(a2ui_payload)
                            }
                        }
                    ]
                };
            } catch (err) {
                console.error("Error listing memories (UI):", err);
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
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized (No User Context)" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:read')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:read' scope." }], isError: true };
                }

                const userId = user.sub;

                // Fetch ALL notes for user (cannot use SQL LIKE on encrypted data)
                const res = await pool.query(
                    "SELECT id, content, created_at FROM notes WHERE user_id = $1 ORDER BY created_at DESC",
                    [userId]
                );

                // Decrypt and filter in memory
                const matches = res.rows
                    .map(row => ({
                        ...row,
                        content: decrypt(row.content)
                    }))
                    .filter(row => row.content.toLowerCase().includes(query.toLowerCase()))
                    .slice(0, 20); // Limit to top 20 matches

                if (matches.length === 0) {
                    return {
                        content: [{ type: "text", text: `🔍 No memories found matching "${query}"` }]
                    };
                }

                const resultsList = matches.map((row, i) =>
                    `${i + 1}. [${row.id}] ${row.content.substring(0, 100)}${row.content.length > 100 ? '...' : ''}\n   📅 ${row.created_at}`
                ).join('\n\n');

                return {
                    content: [{
                        type: "text",
                        text: `🔍 Found ${matches.length} memories matching "${query}":\n\n${resultsList}`
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
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized (No User Context)" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

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

    // ============ TABLE TOOLS ============

    // Helper: Validate a row against a table schema
    function validateRow(schema, row) {
        const errors = [];
        for (const col of schema) {
            const val = row[col.name];
            if (val === undefined || val === null) {
                if (col.required) {
                    errors.push(`Missing required field: "${col.name}"`);
                }
                continue;
            }
            // Type check
            if (col.type === 'number' && typeof val !== 'number') {
                errors.push(`"${col.name}" must be a number, got ${typeof val}`);
            } else if (col.type === 'string' && typeof val !== 'string') {
                errors.push(`"${col.name}" must be a string, got ${typeof val}`);
            } else if (col.type === 'boolean' && typeof val !== 'boolean') {
                errors.push(`"${col.name}" must be a boolean, got ${typeof val}`);
            }
        }
        // Check for unknown columns
        const knownCols = new Set(schema.map(c => c.name));
        for (const key of Object.keys(row)) {
            if (!knownCols.has(key)) {
                errors.push(`Unknown column: "${key}"`);
            }
        }
        return errors;
    }

    // Helper: Apply defaults from schema to a row
    function applyDefaults(schema, row) {
        const result = { ...row };
        for (const col of schema) {
            if ((result[col.name] === undefined || result[col.name] === null) && col.default !== undefined) {
                result[col.name] = col.default;
            }
        }
        return result;
    }

    // Tool: Create a new table
    server.tool(
        "create_table",
        {
            name: z.string().describe("Name of the table to create"),
            schema: z.array(z.object({
                name: z.string().describe("Column name"),
                type: z.enum(["string", "number", "boolean"]).describe("Column data type"),
                required: z.boolean().optional().describe("Whether this column is required (default: false)"),
                default: z.any().optional().describe("Default value for this column")
            })).describe("Array of column definitions")
        },
        async ({ name, schema }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

                // Check for duplicate column names
                const colNames = schema.map(c => c.name);
                const dupes = colNames.filter((n, i) => colNames.indexOf(n) !== i);
                if (dupes.length > 0) {
                    return { content: [{ type: "text", text: `Error: Duplicate column names: ${dupes.join(', ')}` }], isError: true };
                }

                const encryptedData = encrypt('[]');

                await pool.query(
                    "INSERT INTO user_tables (user_id, name, schema, data) VALUES ($1, $2, $3, $4)",
                    [userId, name, JSON.stringify(schema), encryptedData]
                );

                const colSummary = schema.map(c =>
                    `  - ${c.name} (${c.type})${c.required ? ' [required]' : ''}${c.default !== undefined ? ` [default: ${c.default}]` : ''}`
                ).join('\n');

                return {
                    content: [{
                        type: "text",
                        text: `📊 Table "${name}" created!\n\nColumns:\n${colSummary}`
                    }]
                };
            } catch (err) {
                if (err.code === '23505') { // unique_violation
                    return { content: [{ type: "text", text: `Error: Table "${name}" already exists.` }], isError: true };
                }
                console.error("Error creating table:", err);
                return { content: [{ type: "text", text: `Error creating table: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: List all tables
    server.tool(
        "list_tables",
        {},
        async () => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:read')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:read' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT name, schema, created_at, updated_at FROM user_tables WHERE user_id = $1 ORDER BY name",
                    [userId]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: "📭 No tables found. Use 'create_table' to create one!" }] };
                }

                const list = res.rows.map((t, i) => {
                    const cols = t.schema.map(c => `${c.name}:${c.type}`).join(', ');
                    return `${i + 1}. **${t.name}** (${cols})\n   📅 Created: ${t.created_at}`;
                }).join('\n\n');

                return {
                    content: [{ type: "text", text: `📊 Your Tables (${res.rows.length}):\n\n${list}` }]
                };
            } catch (err) {
                console.error("Error listing tables:", err);
                return { content: [{ type: "text", text: `Error listing tables: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: Get table data
    server.tool(
        "get_table",
        {
            name: z.string().describe("Name of the table to retrieve")
        },
        async ({ name }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:read')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:read' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT schema, data FROM user_tables WHERE user_id = $1 AND name = $2",
                    [userId, name]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: `❌ Table "${name}" not found.` }], isError: true };
                }

                const table = res.rows[0];
                const decryptedData = JSON.parse(decrypt(table.data));

                if (decryptedData.length === 0) {
                    const cols = table.schema.map(c => c.name).join(' | ');
                    return { content: [{ type: "text", text: `📊 Table "${name}" (empty)\n\nColumns: ${cols}\n\nUse 'add_row' to add data.` }] };
                }

                // Format as a text table
                const cols = table.schema.map(c => c.name);
                const header = `_row_id | ${cols.join(' | ')}`;
                const separator = '-'.repeat(header.length);
                const rows = decryptedData.map(row => {
                    const vals = cols.map(c => String(row[c] ?? ''));
                    return `${row._row_id} | ${vals.join(' | ')}`;
                });

                return {
                    content: [{
                        type: "text",
                        text: `📊 Table "${name}" (${decryptedData.length} rows):\n\n${header}\n${separator}\n${rows.join('\n')}`
                    }]
                };
            } catch (err) {
                console.error("Error getting table:", err);
                return { content: [{ type: "text", text: `Error getting table: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: Add a row to a table
    server.tool(
        "add_row",
        {
            name: z.string().describe("Name of the table to add a row to"),
            row: z.record(z.any()).describe("Object with column values, e.g. {\"task\": \"Buy milk\", \"priority\": 1}")
        },
        async ({ name, row }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, schema, data FROM user_tables WHERE user_id = $1 AND name = $2",
                    [userId, name]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: `❌ Table "${name}" not found.` }], isError: true };
                }

                const table = res.rows[0];
                const tableSchema = table.schema;
                const data = JSON.parse(decrypt(table.data));

                // Apply defaults and validate
                const fullRow = applyDefaults(tableSchema, row);
                const errors = validateRow(tableSchema, fullRow);
                if (errors.length > 0) {
                    return { content: [{ type: "text", text: `❌ Validation errors:\n${errors.map(e => `  - ${e}`).join('\n')}` }], isError: true };
                }

                // Auto-increment _row_id
                const maxId = data.reduce((max, r) => Math.max(max, r._row_id || 0), 0);
                fullRow._row_id = maxId + 1;

                data.push(fullRow);

                const encryptedData = encrypt(JSON.stringify(data));

                await pool.query(
                    "UPDATE user_tables SET data = $1, updated_at = NOW() WHERE id = $2",
                    [encryptedData, table.id]
                );

                return {
                    content: [{
                        type: "text",
                        text: `✅ Row added to "${name}" (row_id: ${fullRow._row_id})\n\n${JSON.stringify(fullRow, null, 2)}`
                    }]
                };
            } catch (err) {
                console.error("Error adding row:", err);
                return { content: [{ type: "text", text: `Error adding row: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: Update a row in a table
    server.tool(
        "update_row",
        {
            name: z.string().describe("Name of the table"),
            row_id: z.number().describe("The _row_id of the row to update"),
            updates: z.record(z.any()).describe("Object with fields to update, e.g. {\"status\": \"done\"}")
        },
        async ({ name, row_id, updates }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, schema, data FROM user_tables WHERE user_id = $1 AND name = $2",
                    [userId, name]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: `❌ Table "${name}" not found.` }], isError: true };
                }

                const table = res.rows[0];
                const data = JSON.parse(decrypt(table.data));

                const rowIndex = data.findIndex(r => r._row_id === row_id);
                if (rowIndex === -1) {
                    return { content: [{ type: "text", text: `❌ Row ${row_id} not found in "${name}".` }], isError: true };
                }

                // Validate update fields against schema
                const knownCols = new Set(table.schema.map(c => c.name));
                for (const key of Object.keys(updates)) {
                    if (!knownCols.has(key)) {
                        return { content: [{ type: "text", text: `❌ Unknown column: "${key}"` }], isError: true };
                    }
                }

                // Type check updates
                for (const col of table.schema) {
                    if (updates[col.name] !== undefined) {
                        const val = updates[col.name];
                        if (col.type === 'number' && typeof val !== 'number') {
                            return { content: [{ type: "text", text: `❌ "${col.name}" must be a number` }], isError: true };
                        }
                        if (col.type === 'string' && typeof val !== 'string') {
                            return { content: [{ type: "text", text: `❌ "${col.name}" must be a string` }], isError: true };
                        }
                        if (col.type === 'boolean' && typeof val !== 'boolean') {
                            return { content: [{ type: "text", text: `❌ "${col.name}" must be a boolean` }], isError: true };
                        }
                    }
                }

                data[rowIndex] = { ...data[rowIndex], ...updates };

                const encryptedData = encrypt(JSON.stringify(data));

                await pool.query(
                    "UPDATE user_tables SET data = $1, updated_at = NOW() WHERE id = $2",
                    [encryptedData, table.id]
                );

                return {
                    content: [{
                        type: "text",
                        text: `✅ Row ${row_id} updated in "${name}":\n\n${JSON.stringify(data[rowIndex], null, 2)}`
                    }]
                };
            } catch (err) {
                console.error("Error updating row:", err);
                return { content: [{ type: "text", text: `Error updating row: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: Delete a row from a table
    server.tool(
        "delete_row",
        {
            name: z.string().describe("Name of the table"),
            row_id: z.number().describe("The _row_id of the row to delete")
        },
        async ({ name, row_id }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, data FROM user_tables WHERE user_id = $1 AND name = $2",
                    [userId, name]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: `❌ Table "${name}" not found.` }], isError: true };
                }

                const table = res.rows[0];
                const data = JSON.parse(decrypt(table.data));

                const newData = data.filter(r => r._row_id !== row_id);
                if (newData.length === data.length) {
                    return { content: [{ type: "text", text: `❌ Row ${row_id} not found in "${name}".` }], isError: true };
                }

                const encryptedData = encrypt(JSON.stringify(newData));

                await pool.query(
                    "UPDATE user_tables SET data = $1, updated_at = NOW() WHERE id = $2",
                    [encryptedData, table.id]
                );

                return {
                    content: [{ type: "text", text: `🗑️ Row ${row_id} deleted from "${name}".` }]
                };
            } catch (err) {
                console.error("Error deleting row:", err);
                return { content: [{ type: "text", text: `Error deleting row: ${err.message}` }], isError: true };
            }
        }
    );

    // Tool: Add a column to a table
    server.tool(
        "add_column",
        {
            name: z.string().describe("Name of the table"),
            column_name: z.string().describe("Name of the new column"),
            type: z.enum(["string", "number", "boolean"]).describe("Data type of the new column"),
            default_value: z.any().describe("Default value to backfill existing rows with")
        },
        async ({ name, column_name, type, default_value }) => {
            try {
                const user = requestContext.getStore();
                if (!user) {
                    return { content: [{ type: "text", text: "Error: Unauthorized" }], isError: true };
                }

                const scopes = (user.scope || '').split(' ');
                if (!scopes.includes('memories:write')) {
                    return { content: [{ type: "text", text: "Error: Forbidden. Requires 'memories:write' scope." }], isError: true };
                }

                const userId = user.sub;

                const res = await pool.query(
                    "SELECT id, schema, data FROM user_tables WHERE user_id = $1 AND name = $2",
                    [userId, name]
                );

                if (res.rows.length === 0) {
                    return { content: [{ type: "text", text: `❌ Table "${name}" not found.` }], isError: true };
                }

                const table = res.rows[0];

                // Check if column already exists
                if (table.schema.some(c => c.name === column_name)) {
                    return { content: [{ type: "text", text: `❌ Column "${column_name}" already exists in "${name}".` }], isError: true };
                }

                // Add to schema
                const newSchema = [...table.schema, { name: column_name, type, default: default_value }];

                // Backfill existing rows
                const data = JSON.parse(decrypt(table.data));
                for (const row of data) {
                    row[column_name] = default_value;
                }

                const encryptedData = encrypt(JSON.stringify(data));

                await pool.query(
                    "UPDATE user_tables SET schema = $1, data = $2, updated_at = NOW() WHERE id = $3",
                    [JSON.stringify(newSchema), encryptedData, table.id]
                );

                return {
                    content: [{
                        type: "text",
                        text: `✅ Column "${column_name}" (${type}) added to "${name}" with default value: ${JSON.stringify(default_value)}.\n${data.length} existing rows backfilled.`
                    }]
                };
            } catch (err) {
                console.error("Error adding column:", err);
                return { content: [{ type: "text", text: `Error adding column: ${err.message}` }], isError: true };
            }
        }
    );

    return server;
}

app.use(cors());
app.use(express.json());

// ========================
// Discovery & Metadata Routes
// IMPORTANT: These MUST be after app.use(cors/json) — routes before middleware
// get 301 redirects due to MCP SDK tool registration affecting the Express route stack.
// ========================

// OAuth Protected Resource endpoint (RFC 9728) - Root
app.get('/.well-known/oauth-protected-resource', (req, res) => {
    const resourceParam = req.query.resource || '';
    if (resourceParam.includes('/dcr')) {
        return res.json({
            resource: process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
            authorization_servers: [LEGACY_AUTH_SERVER_URL],
            scopes_supported: ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"]
        });
    }
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
        authorization_servers: [AUTH_SERVER_URL],
        scopes_supported: ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"]
    });
});


// Legacy DCR metadata endpoints
app.get('/dcr/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
        authorization_servers: [`${process.env.AUTH_SERVER_URL || 'https://8bitmemory.com'}/dcr`],
        scopes_supported: ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"]
    });
});

// BasicAuth metadata endpoints
app.get('/basicauth/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
        authorization_servers: [`${process.env.AUTH_SERVER_URL || 'https://8bitmemory.com'}/basicauth`],
        scopes_supported: ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"]
    });
});

app.get('/dcr/mcp/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
        resource: process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
        authorization_servers: [LEGACY_AUTH_SERVER_URL],
        scopes_supported: ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"]
    });
});

// OpenAI Domain Verification
app.get('/.well-known/openai-app-domain-verification', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});
app.get('/dcr/.well-known/openai-app-domain-verification', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});
app.get('/basicauth/.well-known/openai-app-domain-verification', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});
app.get('/.well-known/openai-apps-challenge', (req, res) => {
    res.type('text/plain').send('9VWnNzE6C_PBsAtelBomF88tKEoSv0lGu_wYDNZ5X04');
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', server: 'memorybank-mcp', version: '1.0.0' });
});

// Session management for Streamable HTTP
const sessions = new Map();

// Create and configure transport for MCP Streamable HTTP
async function handleMcpRequest(req, res) {
    // Check for existing session
    const sessionId = req.headers['mcp-session-id'];

    let sessionData;

    if (sessionId && sessions.has(sessionId)) {
        // Reuse existing transport
        sessionData = sessions.get(sessionId);
    } else if (!sessionId) {
        // New session - create transport and a dedicated server instance
        const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
        });

        const server = createMcpServer();

        // Connect the server to this transport (1-to-1 relationship required by MCP SDK)
        await server.connect(transport);

        sessionData = { transport, server };

        // Store for session reuse
        transport.onclose = () => {
            if (transport.sessionId) {
                console.log(`📴 Session ${transport.sessionId} closed`);
                sessions.delete(transport.sessionId);
            }
        };

        // After first request, we'll have a session ID
        // We'll store it after handling the request
    } else {
        // Invalid session
        return res.status(404).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Session not found' },
            id: null
        });
    }

    // Handle the request with User Context
    if (req.user) {
        await requestContext.run(req.user, async () => {
            await sessionData.transport.handleRequest(req, res, req.body);
        });
    } else {
        // Fallback or unauthenticated (should be blocked by middleware usually)
        await sessionData.transport.handleRequest(req, res, req.body);
    }

    // Store transport with session ID after first request
    if (sessionData.transport.sessionId && !sessions.has(sessionData.transport.sessionId)) {
        sessions.set(sessionData.transport.sessionId, sessionData);
        console.log(`📡 New session ${sessionData.transport.sessionId} created (user: ${req.user?.sub || 'unknown'})`);
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

// ============ BASICAUTH ROUTES ============
// Alias MCP handlers for /basicauth path
app.post('/basicauth', authMiddleware, handleMcpRequest);
app.get('/basicauth', authMiddleware, handleMcpRequest);

// Explicitly handle /basicauth/mcp
app.post('/basicauth/mcp', authMiddleware, handleMcpRequest);
app.get('/basicauth/mcp', authMiddleware, handleMcpRequest);
app.delete('/basicauth/mcp', authMiddleware, handleMcpRequest);


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

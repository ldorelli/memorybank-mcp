import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../.env') }); // Load .env from parent for Docker/Local split

import pg from 'pg';
const { Pool } = pg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/memorybank_db',
});

// Test connection
pool.query('SELECT NOW()', (err, res) => {
    if (err) console.error("Database connection error:", err);
    else console.log("Database connected:", res.rows[0]);
});

class PgAdapter {
    constructor(name) {
        this.name = name;
    }

    async upsert(id, payload, expiresIn) {
        console.log(`DEBUG: Upserting ${this.name} (${id})`);
        try {
            const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
            await pool.query(
                `INSERT INTO oauth_payloads (id, type, payload, grant_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO UPDATE SET payload = $3, expires_at = $5, grant_id = $4`,
                [id, this.name, payload, payload.grantId, expiresAt]
            );
        } catch (err) {
            console.error(`PgAdapter upsert error (${this.name}, ${id}):`, err);
            throw err;
        }
    }

    async find(id) {
        console.log(`DEBUG: Finding ${this.name} (${id})`);

        // CIMD (draft-ietf-oauth-client-id-metadata-document): when oidc-provider
        // looks up a Client by a URL-shaped client_id, fetch the Client ID
        // Metadata Document at that URL and return it as an ephemeral public
        // client. This is the path used by claude.ai and other modern MCP hosts.
        if (this.name === 'Client' && /^https?:\/\//.test(id)) {
            try {
                console.log('DEBUG: Fetching Client Metadata from:', id);
                const response = await fetch(id, { signal: AbortSignal.timeout(5000) });
                if (!response.ok) {
                    console.error(`CIMD fetch failed (${id}): HTTP ${response.status}`);
                    return undefined;
                }
                const metadata = await response.json();
                if (metadata.client_id !== id) {
                    console.error(`CIMD client_id mismatch (id=${id}, metadata.client_id=${metadata.client_id})`);
                    return undefined;
                }
                return {
                    client_id: id,
                    token_endpoint_auth_method: metadata.token_endpoint_auth_method || 'none',
                    grant_types: metadata.grant_types || ['authorization_code'],
                    redirect_uris: metadata.redirect_uris,
                    response_types: metadata.response_types || ['code'],
                    scope: metadata.scope || 'openid profile email offline_access memories:read memories:write',
                    client_name: metadata.client_name,
                    logo_uri: metadata.logo_uri,
                    client_uri: metadata.client_uri,
                    policy_uri: metadata.policy_uri,
                    tos_uri: metadata.tos_uri,
                };
            } catch (err) {
                console.error(`CIMD fetch error (${id}):`, err.message);
                return undefined;
            }
        }

        try {
            const res = await pool.query('SELECT payload, expires_at FROM oauth_payloads WHERE id = $1 AND type = $2', [id, this.name]);
            if (res.rows.length === 0) {
                console.log(`DEBUG: ${id} NOT FOUND`);
                return undefined;
            }
            const { payload, expires_at } = res.rows[0]; // Restoring this line
            if (expires_at) {
                const now = new Date();
                console.log(`DEBUG: Expiry Check for ${id}. Expires: ${expires_at.toISOString()}, Now: ${now.toISOString()}`);
                if (expires_at < now) {
                    console.log(`DEBUG: ${id} EXPIRED`);
                    return undefined;
                }
            }
            console.log(`DEBUG: ${id} FOUND (Active)`);
            return payload;
        } catch (err) {
            console.error(`PgAdapter find error (${this.name}, ${id}):`, err);
            throw err;
        }
    }

    async findByUserCode(userCode) {
        try {
            const res = await pool.query("SELECT payload, expires_at FROM oauth_payloads WHERE payload->>'userCode' = $1 AND type = $2", [userCode, this.name]);
            if (res.rows.length === 0) return undefined;
            const { payload, expires_at } = res.rows[0];
            if (expires_at && expires_at < new Date()) return undefined;
            return payload;
        } catch (err) {
            console.error(`PgAdapter findByUserCode error (${this.name}):`, err);
            throw err;
        }
    }

    async findByUid(uid) {
        try {
            const res = await pool.query("SELECT payload, expires_at FROM oauth_payloads WHERE payload->>'uid' = $1 AND type = $2", [uid, this.name]);
            if (res.rows.length === 0) return undefined;
            const { payload, expires_at } = res.rows[0];
            if (expires_at && expires_at < new Date()) return undefined;
            return payload;
        } catch (err) {
            console.error(`PgAdapter findByUid error (${this.name}, ${uid}):`, err);
            throw err;
        }
    }

    async destroy(id) {
        try {
            await pool.query('DELETE FROM oauth_payloads WHERE id = $1 AND type = $2', [id, this.name]);
        } catch (err) {
            console.error(`PgAdapter destroy error (${this.name}, ${id}):`, err);
            throw err;
        }
    }

    async revokeByGrantId(grantId) {
        try {
            await pool.query('DELETE FROM oauth_payloads WHERE grant_id = $1', [grantId]);
        } catch (err) {
            console.error(`PgAdapter revokeByGrantId error (${this.name}, ${grantId}):`, err);
            throw err;
        }
    }

    async consume(id) {
        try {
            await pool.query(
                "UPDATE oauth_payloads SET payload = jsonb_set(payload, '{consumed}', 'true'::jsonb) WHERE id = $1 AND type = $2",
                [id, this.name]
            );
        } catch (err) {
            console.error(`PgAdapter consume error (${this.name}, ${id}):`, err);
            throw err;
        }
    }
}

export default PgAdapter;

import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

export async function initializeDatabase() {
    console.log("Checking database schema...");
    try {
        const sqlPath = path.join(__dirname, '../init.sql'); // init.sql is in root
        const sql = fs.readFileSync(sqlPath, 'utf8');
        await pool.query(sql);
        console.log("Database schema applied successfully.");

        // Ensure test user exists for MVP (Optional, but helps avoids first-login issues)
        // We do this safely with ON CONFLICT DO NOTHING in the logic below if needed, 
        // but seed.js already existed. Let's just stick to schema for now.
    } catch (err) {
        console.error("Error applying database schema:", err);
        // Don't exit, might be transient or already exists issue (though IF NOT EXISTS handles that)
    }
}

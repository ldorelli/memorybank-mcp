import pg from 'pg';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from parent if needed, or local
dotenv.config({ path: join(__dirname, '../.env') });
// Fallback to local if parent one fails or merging? No, just simple path.

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
    console.warn("DATABASE_URL not found in environment (checked ../.env), falling back to default.");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/memorybank_db',
});

async function seed() {
    try {
        // Basic table check (optional, but good for verify)
        await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

        // Create Test User
        const res = await pool.query("INSERT INTO users (email, password_hash) VALUES ('test@example.com', 'password') ON CONFLICT (email) DO NOTHING RETURNING *");
        if (res.rows.length > 0) {
            console.log('✅ User created:', res.rows[0]);
        } else {
            console.log('ℹ️ User already exists');
        }
    } catch (err) {
        console.error('❌ Seed error:', err);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

seed();

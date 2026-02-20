import pg from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, '../.env') });

const { Pool } = pg;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/memorybank_db',
});

async function cleanup() {
    console.log('🧹 Starting cleanup of unverified accounts...');

    try {
        // Delete unverified accounts older than 48 hours
        const result = await pool.query(
            `DELETE FROM users 
             WHERE email_verified = false 
             AND created_at < NOW() - INTERVAL '48 hours'
             RETURNING email, created_at`
        );

        if (result.rows.length > 0) {
            console.log(`🗑️  Deleted ${result.rows.length} unverified accounts:`);
            result.rows.forEach(row => {
                console.log(`   - ${row.email} (created: ${row.created_at})`);
            });
        } else {
            console.log('✅ No unverified accounts to clean up.');
        }
    } catch (err) {
        console.error('❌ Cleanup error:', err.message);
    } finally {
        await pool.end();
    }
}

cleanup();

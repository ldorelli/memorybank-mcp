const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_Length = 32; // 256 bits

// Get key from environment
function getKey() {
    const keyHex = process.env.ENCRYPTION_KEY;
    if (!keyHex) {
        throw new Error('ENCRYPTION_KEY environment variable is not set. Cannot encrypt/decrypt data.');
    }
    const key = Buffer.from(keyHex, 'hex');
    if (key.length !== KEY_Length) {
        throw new Error(`Invalid ENCRYPTION_KEY length. Expected 32 bytes (64 hex chars), got ${key.length} bytes.`);
    }
    return key;
}

/**
 * Encrypts text using AES-256-GCM
 * Format: iv:authTag:encryptedContent (hex encoded parts joined by :)
 */
function encrypt(text) {
    if (!text) return text;

    const iv = crypto.randomBytes(16); // 12 bytes is standard for GCM, but 16 is fine too. Let's stick to 12 (96 bits) as per NIST? 
    // Actually crypto.randomBytes(16) is often used for CBC. For GCM 12 is recommended.
    // Let's use 16 to be safe if we ever switch modes, but 12 is optimal for GCM.
    // Implementation details: Node documentation says "The IV is usually passed to cipher.update()... For GCM... the IV length must be 12 bytes".
    // Wait, let's verify.
    // standard is 12 bytes (96 bits) for GCM. 

    const iv12 = crypto.randomBytes(12);
    const key = getKey();

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv12);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag().toString('hex');

    // Return combined string
    return `${iv12.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts text using AES-256-GCM
 * Expects format: iv:authTag:encryptedContent
 */
function decrypt(text) {
    if (!text) return text;
    // Check if it looks encrypted (3 parts separated by :)
    // If not, return original (migration path for existing unencrypted notes!)
    const parts = text.split(':');
    if (parts.length !== 3) {
        // Assume plain text fallback
        return text;
    }

    try {
        const [ivHex, authTagHex, encryptedHex] = parts;

        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const key = getKey();

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        console.error('Decryption failed:', err.message);
        return '[Encrypted Content - De/Encryption Failed]';
    }
}

module.exports = { encrypt, decrypt };

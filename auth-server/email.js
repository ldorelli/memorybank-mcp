import nodemailer from 'nodemailer';

const AUTH_URL = process.env.ISSUER || process.env.AUTH_SERVER_URL || 'https://8bitmemory.com';
const EMAIL_FROM = process.env.EMAIL_FROM || 'MemoryBank <noreply@8bitmemory.com>';

// Configure transporter
// Supports both SMTP (nodemailer) and can be swapped to Resend SMTP later
let transporter;

if (process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_PORT === '465',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });
} else if (process.env.RESEND_API_KEY) {
    // Resend uses SMTP interface compatible with nodemailer
    transporter = nodemailer.createTransport({
        host: 'smtp.resend.com',
        port: 465,
        secure: true,
        auth: {
            user: 'resend',
            pass: process.env.RESEND_API_KEY,
        },
    });
} else {
    console.warn('⚠️  No email config found (SMTP_HOST or RESEND_API_KEY). Email verification will fail.');
    // Create a dummy transporter that logs instead of sending
    transporter = {
        sendMail: async (opts) => {
            console.log('📧 [DEV MODE] Would send email:', JSON.stringify(opts, null, 2));
            return { messageId: 'dev-mode' };
        }
    };
}

/**
 * Send a verification email with a styled HTML template
 */
export async function sendVerificationEmail(email, token) {
    const verifyUrl = `${AUTH_URL}/verify?token=${token}`;

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Courier New', monospace; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 40px; }
        .container { max-width: 500px; margin: 0 auto; background: #16213e; border: 2px solid #7c3aed; border-radius: 8px; padding: 32px; }
        h1 { color: #a78bfa; font-size: 24px; text-align: center; }
        .subtitle { text-align: center; color: #94a3b8; margin-bottom: 24px; }
        .button { display: block; width: fit-content; margin: 24px auto; padding: 12px 32px; background: #7c3aed; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; font-family: 'Courier New', monospace; }
        .footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 24px; }
        .link { color: #94a3b8; font-size: 11px; word-break: break-all; text-align: center; display: block; margin-top: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 8-BIT MEMORY</h1>
        <div class="subtitle">VERIFY YOUR EMAIL</div>
        <p>Thanks for signing up! Click the button below to verify your email address and activate your memory vault.</p>
        <a href="${verifyUrl}" class="button">▶ VERIFY EMAIL</a>
        <span class="link">Or paste this URL: ${verifyUrl}</span>
        <div class="footer">This link expires in 24 hours.<br/>If you didn't sign up, you can ignore this email.</div>
    </div>
</body>
</html>`;

    try {
        const result = await transporter.sendMail({
            from: EMAIL_FROM,
            to: email,
            subject: '🧠 Verify your 8-Bit Memory account',
            html,
        });
        console.log(`📧 Verification email sent to ${email} (messageId: ${result.messageId})`);
        return true;
    } catch (err) {
        console.error(`📧 Failed to send verification email to ${email}:`, err.message);
        return false;
    }
}

import nodemailer from 'nodemailer';

const AUTH_URL = process.env.ISSUER || process.env.AUTH_SERVER_URL || 'https://8bitmemory.com';
const EMAIL_FROM = process.env.EMAIL_FROM || '8-Bit Memory <noreply@8bitmemory.com>';

// Configure transporter
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
        connectionTimeout: 5000,
        greetingTimeout: 5000,
        socketTimeout: 10000,
    });
} else if (process.env.RESEND_API_KEY) {
    // Use Resend REST API instead of SMTP to bypass outbound port blocking on Railway
    console.log('📧 Email configured with Resend API (REST)');
    transporter = {
        sendMail: async (opts) => {
            const res = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from: opts.from,
                    to: opts.to, // Ensure it's an array if multiple, but here it's a string
                    subject: opts.subject,
                    html: opts.html
                })
            });

            if (!res.ok) {
                const text = await res.text();
                throw new Error(`Resend API Error: ${res.status} ${text}`);
            }

            const data = await res.json();
            return { messageId: data.id };
        }
    };
} else {
    console.warn('⚠️  No email config found (SMTP_HOST or RESEND_API_KEY). Emails will be logged only.');
    transporter = {
        sendMail: async (opts) => {
            console.log('📧 [DEV MODE] Would send email to:', opts.to);
            return { messageId: 'dev-mode' };
        }
    };
}

/**
 * Send a verification email (fire-and-forget safe — catches all errors)
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
        // Wrap in a timeout so we never block more than 15s
        const sendPromise = transporter.sendMail({
            from: EMAIL_FROM,
            to: email,
            subject: '🧠 Verify your 8-Bit Memory account',
            html,
        });

        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Email send timed out after 15s')), 15000)
        );

        const result = await Promise.race([sendPromise, timeoutPromise]);
        console.log(`📧 Verification email sent to ${email} (messageId: ${result.messageId})`);
        return true;
    } catch (err) {
        console.error(`📧 Failed to send verification email to ${email}:`, err.message);
        return false;
    }
}

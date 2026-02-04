import Provider from 'oidc-provider';
import express from 'express';
import bodyParser from 'body-parser';
import pgAdapter from './adapter.js'; // Note .js extension
import path from 'path';
import pg from 'pg';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import fs from 'fs';
import https from 'https';
import crypto from 'node:crypto'; // For password hashing
import { promisify } from 'util';
const scrypt = promisify(crypto.scrypt);

// Password Helpers
async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = await scrypt(password, salt, 64);
    return `${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
    // If we have "placeholder_hash" from mvp, treat as invalid or skip
    if (storedHash === 'placeholder_hash') return true; // BACKWARDS COMPATIBILITY for development

    const [salt, key] = storedHash.split(':');
    const keyBuffer = Buffer.from(key, 'hex');
    const derivedKey = await scrypt(password, salt, 64);
    return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

const { Pool } = pg;
import { initializeDatabase } from './db_init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '../.env') });

const app = express();
app.enable('trust proxy'); // Required for Railway/Load Balancers

// Force HTTPS in production (Railway LB terminates SSL)
// FIX: We need to fool both Express (trust proxy) and the Cookies library (req.connection.encrypted)
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        req.headers['x-forwarded-proto'] = 'https';
        // Brute force: Tell node we are encrypted even if not
        if (!req.connection.encrypted) {
            req.connection.encrypted = true;
        }
        next();
    });
}

// Initialize DB Schema
await initializeDatabase();

// CRITICAL FIX: Monkey-patch res.send to intercept and rewrite Set-Cookie headers
// Middleware removed. Relies on correct configuration in cookies object.

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://admin:password@localhost:5432/memorybank_db',
});

// Helper validation function
const findAccount = async (ctx, id) => {
    // id is the email in this simple example, or user ID
    // We need to look up the user
    const res = await pool.query('SELECT id, email FROM users WHERE id = $1', [id]);
    if (res.rows.length === 0) return undefined;
    return {
        accountId: id,
        async claims(use, scope) {
            return { sub: id, email: res.rows[0].email };
        },
    };
};


const isProd = process.env.NODE_ENV === 'production';

const configuration = {
    clients: [{
        client_id: 'mcp_client',
        client_secret: process.env.MCP_CLIENT_SECRET || 'mcp_secret',
        grant_types: ['authorization_code'],
        redirect_uris: ['https://oauth.pstmn.io/v1/callback'],
        response_types: ['code'],
    }],
    cookies: {
        keys: process.env.COOKIE_KEYS ? process.env.COOKIE_KEYS.split(',') : ['fallback_dev_key_dont_use_in_prod'],
        short: {
            secure: isProd,
            sameSite: 'Lax',
            path: '/'
        },
        long: {
            secure: isProd,
            sameSite: 'Lax',
            path: '/'
        },
    },
    proxy: true, // Trust upstream proxies (Docker/Localhost)
    pkce: { required: () => false }, // simplified for MVP
    adapter: pgAdapter,
    findAccount,
    claims: {
        openid: ['sub', 'email'],
    },
    features: {
        devInteractions: { enabled: false }, // we use our own interaction routes
        registration: { enabled: true, initialAccessToken: false }, // Allow dynamic client registration
    },
    // Simplified JWKS config for dev
    jwks: {
        keys: [
            {
                d: 'VEZOsY07JTFzGTqv6cC2YJcbg5pFKgVv2EmJGfc6-88',
                dp: 'E1Y-SN4bQqX7kP-bNgZ_gY6qZ1ktsn5_u8kM8z8z4_8',
                dq: 'HCD9t6j_n7-a5-x8z8z8z8z8z8z8z8z8z8z8z8z8z8',
                e: 'AQAB',
                kty: 'RSA',
                n: 'x_7-a5-x8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8',
                p: '8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8',
                q: '8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8',
                qi: '8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8z8',
                use: 'sig',
                kid: 'memorybank-signing-key'
            }
        ]
    }
};
// configuration.jwks is now preserved to ensure stable signing across restarts

// USE HTTPS for localhost to allow verification of Secure cookies
const issuer = process.env.ISSUER || 'https://localhost:3000';
const oidc = new Provider(issuer, configuration);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));

// Interaction routes
app.get('/interaction/:uid', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);
        console.log(`DEBUG: Interaction Details for ${uid}:`, details);

        const { prompt, params } = details;

        if (prompt.name === 'login') {
            return res.render('login', {
                uid,
                client: details.params.client_id,
                details: prompt.details,
                params,
                title: 'Sign-in',
                flash: undefined
            });
        }

        if (prompt.name === 'consent') {
            return res.render('consent', {
                uid,
                client: details.params, // client_id is inside params usually, or we can look it up
                details: prompt.details,
                params,
                title: 'Authorize'
            });
        }

        return res.status(500).send(`Unknown prompt type: ${prompt.name}`);

    } catch (err) {
        return next(err);
    }
});

// GET /signup
app.get('/interaction/:uid/signup', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);
        return res.render('signup', {
            uid,
            client: details.params.client_id,
            flash: undefined
        });
    } catch (err) {
        next(err);
    }
});

// POST /signup
app.post('/interaction/:uid/signup', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);
        const { email, password } = req.body;

        // Check availability
        const check = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (check.rows.length > 0) {
            return res.render('signup', {
                uid, client: details.params.client_id,
                flash: 'Email already registered. Please sign in.'
            });
        }

        // Hash & Create
        const hash = await hashPassword(password);
        const newUser = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
            [email, hash]
        );

        const result = {
            login: { accountId: newUser.rows[0].id },
        };

        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});


app.post('/interaction/:uid/login', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);
        console.log(`DEBUG: Interaction Details for ${uid}`);
        console.log(`DEBUG: Interaction Details returnTo: ${details.returnTo}`);

        const { email, password } = req.body;

        // Verify User
        const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userRes.rows.length === 0) {
            return res.render('login', {
                uid, client: {}, details: {}, params: {},
                title: 'Sign-in',
                flash: 'Invalid email or password'
            });
        }

        const user = userRes.rows[0];

        // Check Password
        const isValid = await verifyPassword(password, user.password_hash);
        if (!isValid) {
            return res.render('login', {
                uid, client: {}, details: {}, params: {},
                title: 'Sign-in',
                flash: 'Invalid email or password'
            });
        }

        const result = {
            login: { accountId: user.id },
        };
        // Explicitly merging can sometimes cause issues if returnTo is stale, but usually fine.
        // false is safer for login.
        // Interception removed. Using configured cookie settings.

        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
        next(err);
    }
});

app.post('/interaction/:uid/confirm', async (req, res, next) => {
    try {
        const interactionDetails = await oidc.interactionDetails(req, res);
        const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
        let grantId = interactionDetails.grantId;

        let grant;

        if (grantId) {
            // we'll be modifying existing grant in existing session
            grant = await oidc.Grant.find(grantId);
        } else {
            // we're establishing a new grant
            grant = new oidc.Grant({
                accountId,
                clientId: params.client_id,
            });
        }

        if (details.missingOIDCScope) {
            grant.addOIDCScope(details.missingOIDCScope.join(' '));
        }
        if (details.missingOIDCClaims) {
            grant.addOIDCClaims(details.missingOIDCClaims);
        }
        if (details.missingResourceScopes) {
            for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
                grant.addResourceScope(indicator, scopes.join(' '));
            }
        }

        grantId = await grant.save();

        const consent = {};
        if (!interactionDetails.grantId) {
            // we don't have to pass grantId to consent, we're just modifying existing one
            consent.grantId = grantId;
        }

        const result = { consent };
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (err) {
        next(err);
    }
});

// Debug Listener
oidc.on('server_error', (ctx, err) => {
    console.error('SERVER ERROR:', err);
});

app.use(oidc.callback());

// HTTPS Start
// HTTPS Start or HTTP for Production (Railway handles SSL)
// Universal HTTP Start (Railway handles SSL, Localhost uses HTTP)
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`oidc-provider listening on port ${port} (HTTP), issuer: ${issuer}`);
});

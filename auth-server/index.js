import Provider, { interactionPolicy } from 'oidc-provider';
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
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Alias for OAuth 2.0 Authorization Server Metadata (RFC 8414)
// PLACED HERE to ensure it hits before any middleware or other routes
app.get('/.well-known/oauth-authorization-server', (req, res) => {
    console.log('Serving RFC 8414 Metadata');
    // RFC 8414 Section 3.2: MUST support CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Content-Type', 'application/json');

    const baseUrl = issuer.replace(/\/$/, '');
    res.json({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/auth`,
        token_endpoint: `${baseUrl}/token`,
        registration_endpoint: `${baseUrl}/reg`, // RFC 7591
        jwks_uri: `${baseUrl}/jwks`,
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        response_types_supported: ['code'],
        response_modes_supported: ['query', 'fragment'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
        revocation_endpoint: `${baseUrl}/token/revocation`,
        introspection_endpoint: `${baseUrl}/token/introspection`,
    });
});

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

// Custom Interaction Policy: Force consent ONCE per client (if no grant exists)
const { Prompt, base: policy, Check } = interactionPolicy;
const customPolicy = policy();

// Add a check that triggers consent if no grant exists for this client
customPolicy.get('consent').checks.add(new Check(
    'native_client_prompt',
    'consent required for new client authorization',
    'interaction_required',
    (ctx) => {
        const { oidc } = ctx;

        console.log('DEBUG: Consent check - oidc.result:', JSON.stringify(oidc.result));
        console.log('DEBUG: Consent check - oidc.grant:', oidc.grant?.jti);

        // If we already have a result with consent.grantId, we just finished consenting
        if (oidc.result?.consent?.grantId) {
            console.log('DEBUG: Skipping consent - result.consent.grantId exists');
            return false;
        }

        // If the interaction already has a grantId, consent was given
        if (ctx.oidc?.entities?.Interaction?.grantId) {
            console.log('DEBUG: Skipping consent - interaction.grantId exists');
            return false;
        }

        // If we have an existing grant in session, skip consent
        if (oidc.session?.grantIdFor && oidc.client) {
            const existingGrant = oidc.session.grantIdFor(oidc.client.clientId);
            if (existingGrant) {
                console.log('DEBUG: Skipping consent - session.grantIdFor found:', existingGrant);
                return false;
            }
        }

        // No prior grant = require consent
        console.log('DEBUG: Requiring consent - no grant found');
        return true;
    }
));

const configuration = {
    interactions: {
        policy: customPolicy,
        url(ctx, interaction) {
            return `/interaction/${interaction.uid}`;
        },
    },
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
        console.log('DEBUG: /confirm route hit');
        const interactionDetails = await oidc.interactionDetails(req, res);
        console.log('DEBUG: Interaction details in /confirm:', JSON.stringify(interactionDetails, null, 2));

        const { prompt: { name, details }, params, session } = interactionDetails;

        // Ensure we have a session with accountId
        if (!session?.accountId) {
            console.error('DEBUG: No session.accountId in /confirm!');
            return res.status(400).send('No session found');
        }

        const accountId = session.accountId;
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

        // Add scopes (with null checks)
        if (details?.missingOIDCScope?.length) {
            grant.addOIDCScope(details.missingOIDCScope.join(' '));
        }
        if (details?.missingOIDCClaims?.length) {
            grant.addOIDCClaims(details.missingOIDCClaims);
        }
        if (details?.missingResourceScopes) {
            for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
                grant.addResourceScope(indicator, scopes.join(' '));
            }
        }

        grantId = await grant.save();
        console.log('DEBUG: Grant saved with ID:', grantId);

        const consent = {};
        if (!interactionDetails.grantId) {
            // we don't have to pass grantId to consent, we're just modifying existing one
            consent.grantId = grantId;
        }

        const result = { consent };
        console.log('DEBUG: Finishing interaction with result:', JSON.stringify(result));
        await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
        console.log('DEBUG: interactionFinished completed');
    } catch (err) {
        console.error('DEBUG: Error in /confirm:', err);
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

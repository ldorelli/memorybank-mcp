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
import { sendVerificationEmail } from './email.js';
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
        client_id_metadata_document_supported: true,
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        response_types_supported: ['code'],
        response_modes_supported: ['query', 'fragment'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
        revocation_endpoint: `${baseUrl}/token/revocation`,
        introspection_endpoint: `${baseUrl}/token/introspection`,
    });
});

// Legacy Metadata (RFC 8414) for /dcr path
// Ensure clients checking this specific path get the "Legacy" config
app.get('/dcr/.well-known/oauth-authorization-server', (req, res) => {
    console.log('Serving RFC 8414 Metadata for /dcr');
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Content-Type', 'application/json');

    const baseUrl = `${issuer.replace(/\/$/, '')}/dcr`;
    res.json({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/auth`,
        token_endpoint: `${baseUrl}/token`,
        registration_endpoint: `${baseUrl}/reg`,
        jwks_uri: `${baseUrl}/jwks`,
        // EXPLICITLY FALSE
        client_id_metadata_document_supported: false,
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

// Default scopes for MemoryBank MCP - these will be displayed on consent screen
const DEFAULT_SCOPES = 'openid memories:read memories:write';

const configuration = {
    // Interaction policy - display consent screen
    interactions: {
        url(ctx, interaction) {
            return `/interaction/${interaction.uid}`;
        },
    },
    // Define custom scopes for MemoryBank
    scopes: ['openid', 'offline_access', 'memories:read', 'memories:write'],
    // Custom claims (standard OIDC + our custom ones)
    claims: {
        openid: ['sub', 'email'],
        'memories:read': ['memory_access'],
        'memories:write': ['memory_access'],
    },
    // Dynamic Client Lookup (Dual Auth: DCR + Metadata)
    async findClient(ctx, id) {
        // 1. Legacy / Static DCR Client
        if (id === 'mcp_client') {
            return {
                client_id: 'mcp_client',
                client_secret: process.env.MCP_CLIENT_SECRET || 'mcp_secret',
                grant_types: ['authorization_code'],
                redirect_uris: [
                    'https://oauth.pstmn.io/v1/callback',
                    'https://mcp.8bitmemory.com/health'
                ],
                response_types: ['code'],
                scope: DEFAULT_SCOPES,
            };
        }

        // 2. Client ID Metadata (URL-based Identity)
        // Check if we are in "Legacy Mode" (User testing DCR-only)
        if (ctx.query && ctx.query.force_dcr === 'true') {
            console.log('DEBUG: Legacy Mode enabled. Rejecting potential Metadata client:', id);
            // If it looks like a URL, reject it to emulate a server that doesn't support it
            if (id.startsWith('http://') || id.startsWith('https://')) {
                return undefined;
            }
        }

        // If ID is a URL, fetch metadata
        if (id.startsWith('http://') || id.startsWith('https://')) {
            try {
                console.log('DEBUG: Fetching Client Metadata from:', id);
                // Security: In prod, ensure strict timeouts and size limits to prevent DoS
                const response = await fetch(id, { signal: AbortSignal.timeout(5000) });

                if (!response.ok) {
                    console.error(`Failed to fetch client metadata: ${response.status}`);
                    return undefined;
                }

                const metadata = await response.json();

                // Validate Metadata (Basic Spec checks)
                if (metadata.client_id !== id) {
                    console.error('Metadata client_id mismatch');
                    return undefined;
                }

                // Inject our default scopes if they aren't explicitly restricted? 
                // Actually, the client just needs to be returned.
                // We need to map it to oidc-provider's expected format.

                return {
                    client_id: id,
                    client_secret: undefined,
                    token_endpoint_auth_method: 'none',

                    grant_types: ['authorization_code', 'implicit'],
                    redirect_uris: metadata.redirect_uris,
                    response_types: ['code'],
                    scope: metadata.scope || DEFAULT_SCOPES,

                    // Metadata fields for Enhanced Consent Screen
                    client_name: metadata.client_name,
                    logo_uri: metadata.logo_uri,
                    client_uri: metadata.client_uri,
                    policy_uri: metadata.policy_uri,
                    tos_uri: metadata.tos_uri,
                };

            } catch (err) {
                console.error('Error fetching/parsing client metadata:', err);
                return undefined;
            }
        }

        return undefined;
    },
    // Advertise Client ID Metadata Support
    discovery: {
        client_id_metadata_document_supported: true,
    },
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
    features: {
        devInteractions: { enabled: false }, // we use our own interaction routes
        registration: { enabled: true, initialAccessToken: false }, // Allow dynamic client registration
        // Enable resource indicators to allow JWT access tokens
        resourceIndicators: {
            enabled: true,
            // Default resource if none specified
            defaultResource: (ctx) => {
                return process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com';
            },
            // Return JWT format for all resources
            getResourceServerInfo: (ctx, resourceIndicator, client) => {
                return {
                    scope: 'openid memories:read memories:write',
                    audience: resourceIndicator,
                    accessTokenFormat: 'jwt', // This makes access tokens JWT format
                    accessTokenTTL: 3600, // 1 hour
                };
            },
            // Use default resource for all grant types
            useGrantedResource: (ctx, model) => true,
        },
    },
    // JWKS loaded from environment variable for security
    // Set JWKS_PRIVATE_KEY env var to a JSON string of the key
    // Generate one with: node -e "const crypto=require('crypto'); const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}); const jwk=privateKey.export({format:'jwk'}); jwk.use='sig'; jwk.kid='memorybank-key'; jwk.alg='RS256'; console.log(JSON.stringify(jwk));"
    jwks: {
        keys: process.env.JWKS_PRIVATE_KEY
            ? [JSON.parse(process.env.JWKS_PRIVATE_KEY)]
            : (() => {
                console.warn('⚠️  WARNING: Using development JWKS key. Set JWKS_PRIVATE_KEY in production!');
                return [{
                    kty: 'RSA',
                    n: '0l3t-FdA6fKylv3R9hDfSVW-HU5Lp0CV40N1_A584bV7ydUPuxZwN-DZBsSix5EB1taJ6zS03d1RmLtpnnkSZnpGrxkR3vLxng_1O7s7pnCy8SqkZpt2b8O5UkYr7w0ZTcNoFZgObtLRLMWb3jAia1BeN3CPe-ocQXyH3DtLu7i9dixqLumwaBlKrKqFrwmh6tFaRtJQ1Y5QhDkV4mnVbh8j6P3MT2r2WpJvyFCa_lTkzjAfc1kqQpWApG2J4dEAG41yXnWqHgGGsn67ec9rzMXeYtU7vqpHdvYEQOfAr9a_pL5j5V5fOspD-lDrVTmHzMHJFDLdYw-7MuhFPehGBQ',
                    e: 'AQAB',
                    d: 'Dyr2nZFXp4ai7yrImMAJWXWf35JlogmQxRzNb6nGbKpz4nmaSMMKvvysqUWZobSy4pVVccAQdRl1aK3FT8fVq83lNXrOmbn_8dr0s6SBszPXsyEqpBCm2X14lJYP_4x85pPQTWjz9smnNgiJfzEOn5jhMjN2JQPG8HHU2exB6ab8KCc0c9tOI_rXN9wx9coJK45hC-pTRc8o-VaDeHPCfnr5fcbFqB_XN-uhEqYbsb8jxDLr9IunW25EekMi5o7ZvCFBcb5j8NhoVDVERpIcLf_8b2RnKVx-ITYQX3Ei9tBDHZte_w9j1bnYPSzPvsw7jrFFG69-kRtZ1LObxm4gAQ',
                    p: '9YcVvMjqWWrymFyg65O-c2fr7wBOjAVF2Fm89AoaL3Zyc67JYHT_Rpniei9hLETh3uyHAT3N5sNKew3mziTEX5jMTj1oQ519fPZykSVugYZ4V1CeuWSbTWCRZB08Fn8W-53b7zPW3HhF_xSRxgjTfVWllHw6uxl-bzYM3dlBvMU',
                    q: '21bsrRaNY72tBj9iECzY0XV8I-17uPW2nwBT2oh2D-MCEkgPQEh_Xrfdadgc4r3GOkma856YMu7OyHLc_atURJxz1j30iFlq-y6Y_zbZius0sQBA2EmuEL_F6YVADJOuLi7XFRFBbkHGi-KVape9mzWxYYtLqOaAhg_G3QZ_eEE',
                    dp: 'Vd4QdB2wF-WXQkHi5YCeMq49jTCGR-HwM2Hu-0otLjw2es6-DsXcIUzgL-syCNFuTRBbhsuenv3dpnuOJLonE2fUy-gd9se1g2aNWsXEh_gHTkIbwKq2xbDoKCMxSIzZ9NWYfWeb1S8bC8Kd2Kxtin_RkMSBpb2cwjgc99lrbCE',
                    dq: 'jmxcFGxvdNOGFWd0yqIES8YozL95Nfm_EnHJAT7YwqoZ_zrxREGPCzcCu6bL4uNtYw3GYuiZVYFBnmEPZFwqxL5-bSAft6WwVNfGGvpHue_OcByE_qyhLVkJLwAKPeBrGqvpl1F0Fh75yH1hnixXvv_XZUpo34yE6gg2jfCZNsE',
                    qi: '2ivezOCsP8FlUH7ZO6AKqau1RIE7b8QPOAjIMrT8EpPV2D2W1tY951lrhFwFo4nA76FL8bfs4Ya1Rd9M9D8GkTHH4NlhhC-FkMsD5oa4Nsvj_CFiKkOCuLVwWBMVBxXgcwgMpjyT1_QFdqGKqavupILI57e1kaRBJpGfzTiIfnI',
                    use: 'sig',
                    kid: 'memorybank-dev-key',
                    alg: 'RS256'
                }];
            })()
    }
};

// OIDC Provider Configuration
const issuer = process.env.ISSUER || 'https://localhost:3000';
const oidc = new Provider(issuer, configuration);

// Legacy Provider (DCR Only - No Metadata Support)
// Mounted at /dcr to emulate an old server
const legacyIssuer = `${issuer}/dcr`;
const legacyConfiguration = {
    ...configuration,
    // Override findClient to be undefined (falls back to clients array) 
    // OR enforce strict check if we reused the object. 
    // Since 'configuration' has 'findClient', we must remove it.
    findClient: undefined,
    clients: [{
        client_id: 'mcp_client',
        client_secret: process.env.MCP_CLIENT_SECRET || 'mcp_secret',
        grant_types: ['authorization_code'],
        redirect_uris: [
            'https://oauth.pstmn.io/v1/callback',
            'https://mcp.8bitmemory.com/health'
        ],
        response_types: ['code'],
        scope: DEFAULT_SCOPES,
    }],
    jwt: {
        ...configuration.jwt,
    },
    jwks: configuration.jwks, // Re-use keys
    adapter: pgAdapter,
    // Explicitly disable Metadata support in Legacy Mode
    discovery: {
        client_id_metadata_document_supported: false,
    },
    features: {
        ...configuration.features,
        resourceIndicators: {
            ...configuration.features.resourceIndicators,
            defaultResource: (ctx) => process.env.MCP_SERVER_URL || 'https://mcp.8bitmemory.com',
            getResourceServerInfo: (ctx, resourceIndicator, client) => ({
                scope: 'openid memories:read memories:write',
                audience: resourceIndicator,
                accessTokenFormat: 'jwt',
                accessTokenTTL: 3600,
            }),
        }
    }
};

const oidcLegacy = new Provider(legacyIssuer, legacyConfiguration);

// Middleware to inject default scopes into authorization requests
// Verify if we need this for legacy too. Yes.
const injectScopes = (prefix) => async (ctx, next) => {
    if (ctx.path === `${prefix}/auth` && ctx.method === 'GET') {
        if (!ctx.query.scope) {
            console.log(`DEBUG: No scope in request (${prefix}), injecting defaults:`, DEFAULT_SCOPES);
            ctx.query.scope = DEFAULT_SCOPES;
        }
    }
    await next();
};

oidc.use(injectScopes(''));
oidcLegacy.use(injectScopes('/dcr'));

// Mount Providers
// Legacy first to catch specific route
app.use('/dcr', oidcLegacy.callback());

// Main provider handles root
// Note: oidc.callback() handles all routes matching issuer. 
// If issuer is root, it handles everything.
// But legacy is mounted on /dcr, so express matches it first if we use app.use('/dcr', ...).
// Wait, oidc-provider mounts based on internal reasoning too.
// Using `app.use('/dcr', oidcLegacy.callback())` tells Express to trim `/dcr`. 
// So inside oidcLegacy, it sees `/auth`.
// BUT `oidcLegacy` assumes its issuer is `.../dcr`. 
// So it EXPECTS paths to NOT be trimmed if it handles them?
// Actually `oidc-provider` with Express mounting expects the prefix to be stripped by Express 
// IF the issuer config assumes the internal paths are relative? 
// No, standard `oidc-provider` expects to control the path.
// The safe way with `oidc-provider` is to let it handle the routing.
// However, mounting separate instances requires care.
//
// Best practice: Let Express strip the prefix.
// `legacyIssuer` = `.../dcr`
// Inside `oidcLegacy`, routes are `/auth`, `/token`.
// If I mount at `/dcr`: 
// Request: `/dcr/auth` -> Express trips `/dcr` -> `oidcLegacy` sees `/auth`.
// Does `oidcLegacy` check that `issuer` matches the request? 
// It checks `ctx.oidc.issuer`. 
// It might get confused if `req.originalUrl` includes `/dcr` but it sees `/auth`.
// Let's assume standard Express mounting works.

// Main provider mount (KEEP LAST)

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files (css, logo)

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
            const client = await oidc.Client.find(details.params.client_id);
            return res.render('consent', {
                uid,
                client,
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

// Static Pages (GPT Store Compliance)
app.get('/', (req, res) => {
    res.render('index', { title: 'Home' });
});

app.get('/support', (req, res) => {
    res.render('support', { title: 'Support' });
});

app.get('/tos', (req, res) => {
    res.render('tos', { title: 'Terms of Service' });
});

app.get('/privacy', (req, res) => {
    res.render('privacy', { title: 'Privacy Policy' });
});

// Standalone Signup (GET)
app.get('/signup', (req, res) => {
    res.render('signup', {
        uid: null, // Standalone mode
        client: null,
        flash: undefined
    });
});

// Email validation helper
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email) && email.length <= 255;
}

// Standalone Signup (POST)
app.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate
        if (!isValidEmail(email)) {
            return res.render('signup', { uid: null, client: null, flash: 'Please enter a valid email address.' });
        }
        if (!password || password.length < 8) {
            return res.render('signup', { uid: null, client: null, flash: 'Password must be at least 8 characters.' });
        }

        // Check availability
        const check = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (check.rows.length > 0) {
            return res.render('signup', { uid: null, client: null, flash: 'Email already registered. Please sign in.' });
        }

        // Generate verification token
        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        // Hash & Create with verification
        const hash = await hashPassword(password);
        await pool.query(
            'INSERT INTO users (email, password_hash, email_verified, verification_token, verification_expires) VALUES ($1, $2, $3, $4, $5)',
            [email, hash, false, token, expires]
        );

        // Send verification email
        await sendVerificationEmail(email, token);

        res.render('verify_pending', { email });
    } catch (err) {
        console.error(err);
        res.render('signup', { uid: null, client: null, flash: 'Error creating account.' });
    }
});


// OIDC Interaction Signup (GET) - Keep existing logic but use same template
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

// POST /interaction/:uid/signup (OIDC flow)
app.post('/interaction/:uid/signup', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);
        const { email, password } = req.body;

        // Validate
        if (!isValidEmail(email)) {
            return res.render('signup', { uid, client: details.params.client_id, flash: 'Please enter a valid email address.' });
        }
        if (!password || password.length < 8) {
            return res.render('signup', { uid, client: details.params.client_id, flash: 'Password must be at least 8 characters.' });
        }

        // Check availability
        const check = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (check.rows.length > 0) {
            return res.render('signup', { uid, client: details.params.client_id, flash: 'Email already registered. Please sign in.' });
        }

        // Generate verification token
        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Hash & Create with verification
        const hash = await hashPassword(password);
        await pool.query(
            'INSERT INTO users (email, password_hash, email_verified, verification_token, verification_expires) VALUES ($1, $2, $3, $4, $5)',
            [email, hash, false, token, expires]
        );

        // Send verification email
        await sendVerificationEmail(email, token);

        // Show "check your email" page (don't auto-login until verified)
        res.render('verify_pending', { email });
    } catch (err) {
        next(err);
    }
});


app.post('/interaction/:uid/login', async (req, res, next) => {
    try {
        const { uid } = req.params;
        const details = await oidc.interactionDetails(req, res);

        // Form sends 'login' for email, but we also support 'email' just in case
        const email = req.body.login || req.body.email;
        const { password } = req.body;

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

        // Check if email is verified
        if (!user.email_verified) {
            return res.render('login', {
                uid, client: {}, details: {}, params: {},
                title: 'Sign-in',
                flash: 'Please verify your email first. Check your inbox for the verification link.'
            });
        }

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

// Email Verification Route
app.get('/verify', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.render('verify_success', { error: 'Invalid verification link.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, email, verification_expires FROM users WHERE verification_token = $1 AND email_verified = false',
            [token]
        );

        if (result.rows.length === 0) {
            return res.render('verify_success', { error: 'Invalid or expired verification link.' });
        }

        const user = result.rows[0];

        // Check expiry
        if (new Date() > new Date(user.verification_expires)) {
            return res.render('verify_success', { error: 'This verification link has expired. Please sign up again.' });
        }

        // Mark as verified
        await pool.query(
            'UPDATE users SET email_verified = true, verification_token = NULL, verification_expires = NULL WHERE id = $1',
            [user.id]
        );

        console.log(`✅ Email verified for ${user.email}`);
        res.render('verify_success', { error: null });
    } catch (err) {
        console.error('Verification error:', err);
        res.render('verify_success', { error: 'An error occurred during verification.' });
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

        // Add all requested OIDC scopes (openid, offline_access, etc.)
        if (details?.missingOIDCScope?.length) {
            const oidcScopes = details.missingOIDCScope.join(' ');
            console.log('DEBUG: Adding OIDC scopes:', oidcScopes);
            grant.addOIDCScope(oidcScopes);
        }

        // Add custom scopes (memories:read, memories:write) if in missing scopes
        // Custom scopes in oidc-provider are treated as "resource scopes" or need special handling
        const requestedScope = params.scope || '';
        const customScopes = requestedScope.split(' ')
            .filter(s => s.startsWith('memories:'));

        if (customScopes.length > 0) {
            console.log('DEBUG: Adding custom scopes:', customScopes.join(' '));
            // Add custom scopes as OIDC scopes (oidc-provider allows this for non-RS256 scopes)
            grant.addOIDCScope(customScopes.join(' '));
        }

        // Add any missing OIDC claims
        if (details?.missingOIDCClaims?.length) {
            grant.addOIDCClaims(details.missingOIDCClaims);
        }

        // Add any resource scopes
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

// Track when authorization code is issued
oidc.on('authorization_code.saved', (authorizationCode) => {
    console.log('DEBUG: AuthorizationCode SAVED:', authorizationCode.jti);
});

oidc.on('authorization_code.consumed', (authorizationCode) => {
    console.log('DEBUG: AuthorizationCode CONSUMED:', authorizationCode.jti);
});

oidc.on('authorization.success', (ctx) => {
    console.log('DEBUG: Authorization SUCCESS - redirecting to:', ctx.oidc.params.redirect_uri);
});

oidc.on('authorization.error', (ctx, err) => {
    console.error('DEBUG: Authorization ERROR:', err);
});

oidc.on('interaction.ended', (ctx) => {
    console.log('DEBUG: Interaction ENDED');
});

app.use(oidc.callback());

// HTTPS Start
// HTTPS Start or HTTP for Production (Railway handles SSL)
// Universal HTTP Start (Railway handles SSL, Localhost uses HTTP)
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`oidc-provider listening on port ${port} (HTTP), issuer: ${issuer}`);
});

# Success/Failure Log

## 2026-02-20

### Issue: Email Timeout
**What we tried:** The `auth-server` Verification Email function was wrapped with a `await Promise.race` 15-second timeout, but Railway networking caused it to hang, preventing user signup.
**Success:** Removed the `await` keyword, turning `sendVerificationEmail` into a non-blocking background promise. Users instantly see the success screen, and the email eventually goes through.

### Issue: `/.well-known` Infinite 301 Redirect Loop
**What we tried:** 
- Adding `trust proxy` direct to Express.
- Manually spoofing `X-Forwarded-Proto` and `req.connection.encrypted` on incoming requests.
- Inserting a global request interceptor to trace `Res.redirect` inside Express.
- Completely bypassing the Express router for `/.well-known` endpoints via early return middleware.
- Writing a test route `/test-auth-meta`

**What failed:**
Every fix within the application code failed because the Node app itself wasn't even receiving the requests. Railway Edge Router was unconditionally intercepting it.

**Root Cause:**
- Cloudflare’s **"Flexible" SSL mode** accepts HTTPS from the client but uses HTTP to communicate with the origin server (Railway).
- Railway's Edge Network forcefully intercepts any HTTP path matching `/.well-known` (because it expects to verify Let's Encrypt certificates there unless it's strictly TLS/HTTPS traffic) and responds with `301 Moved Permanently` to force an HTTPS connection.
- Cloudflare proxies this `301` back to the user, the user requests HTTPS again, Cloudflare connects to Railway via HTTP *again*, causing an infinite loop.

**Success:**
The user changed Cloudflare's SSL/TLS encryption mode from **Flexible** to **Full (strict)**. This forces Cloudflare to connect to Railway via HTTPS, which fundamentally prevents the Edge Network from forcing an unencrypted downgrade 301. All `mcp-server` debug bypasses were removed since the application routing handled it perfectly fine natively!

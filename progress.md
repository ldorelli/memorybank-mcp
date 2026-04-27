# Progress Log
- Researched A2UI protocol over MCP and drafted plan for list notes UI.
- Investigating email timeout on Railway and OAuth config routing issue.

## 2026-02-20
- Investigated `/.well-known/oauth-protected-resource` 301 infinite loop on `mcp-server`.
- Identified that `auth-server` also experienced the same 301 loop.
- Traced the bug back to Cloudflare's **"Flexible" SSL mode**, which proxies HTTPS client traffic back to Railway as HTTP. Railway Edge Router natively forces HTTPS for `.well-known` domains to protect ACME challenges, resulting in a 301 redirect back to Cloudflare, starting the loop over.
- The user switched Cloudflare to **"Full" SSL mode**, fixing the loop immediately. 
- Reverted all messy Express router bypasses and debugging middleware since the code was originally correct.
- Fixed an issue where `sendVerificationEmail` was failing in the background via Nodemailer SMTP due to Railway blocking outbound SMTP ports. Switched to `fetch` sending via the direct Resend REST API which bypasses blockages over standard 443.
- Implemented `/basicauth` static OIDC provider endpoint on `auth-server` and advertised it via `/basicauth/.well-known/oauth-protected-resource` on `mcp-server` to allow a hardcoded Google client with specific redirect URIs, disabling DCR and Client Metadata discovery for this route.

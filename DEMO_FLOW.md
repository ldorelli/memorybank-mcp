# MemoryBank MCP — Per-Tool Auth, End-to-End

This is the exact interaction that happened when claude.ai connected to the
MemoryBank MCP server, called an open tool, then attempted a protected tool —
reconstructed from the deployed server logs and the implementation. Each phase
is annotated with the actual headers, scopes, and identifiers exchanged.

> Open this file on GitHub (or any Mermaid-aware viewer) for the rendered
> diagram. To export as PNG/SVG for slides: paste into <https://mermaid.live>
> or run `mmdc -i DEMO_FLOW.md -o flow.png`.

## The flow

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as Claude (claude.ai)
    participant B as Browser
    participant M as MCP Server<br/>mcp.8bitmemory.com
    participant A as Auth Server<br/>8bitmemory.com
    participant D as Claude CIMD doc<br/>claude.ai/oauth/...

    rect rgb(232, 244, 255)
    Note over U,M: 1 · Anonymous connect & open-tool demo
    U->>C: "Add MemoryBank connector"
    C->>M: POST /mcp · initialize (no token)
    M-->>C: 200 · Mcp-Session-Id
    C->>M: POST /mcp · tools/list (no token)
    M-->>C: 200 · 14 tools (incl. ping, get_random_quote)
    U->>C: "Give me a random quote"
    C->>M: POST /mcp · tools/call get_random_quote
    M-->>C: 200 · "The unexamined life…" — Socrates
    end

    rect rgb(255, 240, 232)
    Note over U,M: 2 · Protected tool → per-operation 401 challenge
    U->>C: "Save that quote"
    C->>M: POST /mcp · tools/call save_memory
    Note right of M: softAuth: no token<br/>toolAuthGate: Mcp-Name=save_memory<br/>→ challenge
    M-->>C: 401 Unauthorized<br/>WWW-Authenticate: Bearer<br/>  scope="memories:write"<br/>  resource_metadata="…/.well-known/oauth-protected-resource"
    end

    rect rgb(244, 232, 255)
    Note over C,A: 3 · OAuth + CIMD discovery (no DCR)
    C->>M: GET /.well-known/oauth-protected-resource
    M-->>C: { authorization_servers: ["https://8bitmemory.com"],<br/>scopes_supported: [openid, profile, email, offline_access,<br/>memories:read, memories:write] }
    C->>A: GET /.well-known/oauth-authorization-server
    A-->>C: { authorize/token endpoints,<br/>client_id_metadata_document_supported: true }
    Note over C,A: Claude uses its CIMD URL as client_id<br/>(no Dynamic Client Registration)
    end

    rect rgb(232, 255, 240)
    Note over U,A: 4 · Authorization, login & consent
    C->>B: Open /authorize<br/>client_id=https://claude.ai/oauth/mcp-oauth-client-metadata<br/>scope=openid profile email offline_access memories:read memories:write<br/>resource=https://mcp.8bitmemory.com/<br/>code_challenge_method=S256 · prompt=consent
    B->>A: GET /authorize
    A->>D: GET https://claude.ai/oauth/mcp-oauth-client-metadata  (CIMD fetch)
    D-->>A: { client_name: "Claude",<br/>redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],<br/>grant_types: ["authorization_code","refresh_token"],<br/>token_endpoint_auth_method: "none" }
    A-->>B: Redirect → /interaction/&lt;uid&gt;<br/>prompt: consent (op_scopes_missing, rs_scopes_missing)
    B->>A: GET /interaction/&lt;uid&gt;  (login page)
    U->>B: email / password
    B->>A: POST /interaction/&lt;uid&gt;/login
    A-->>B: Redirect → consent screen
    U->>B: clicks "Allow"
    B->>A: POST /interaction/&lt;uid&gt;/confirm
    A->>A: interactionFinished({ consent: { grantId } })
    A-->>B: Redirect → https://claude.ai/api/mcp/auth_callback?code=…&state=…
    B->>C: forwards callback (code + state)
    end

    rect rgb(255, 250, 232)
    Note over C,A: 5 · Token exchange & retry
    C->>A: POST /token<br/>grant_type=authorization_code · code · code_verifier (PKCE)<br/>client_id=&lt;CIMD URL&gt; · resource=https://mcp.8bitmemory.com/
    A->>D: GET CIMD doc (re-validate client)
    D-->>A: client metadata
    A-->>C: { access_token (JWT, aud=mcp.8bitmemory.com),<br/>refresh_token, id_token (sub, email, name) }
    C->>M: POST /mcp · tools/call save_memory<br/>Authorization: Bearer &lt;jwt&gt;
    Note right of M: softAuth verifies JWT → attaches req.user<br/>toolAuthGate: token present, pass<br/>handler re-checks scopes.includes('memories:write')
    M-->>C: 200 · "✅ Memory saved"
    C-->>U: "Saved the quote to your memories."
    end
```

## What's notable for the demo

- **Lazy OAuth.** Steps 1–2 happen with zero authentication; the OAuth flow
  only starts after a *protected* tool is invoked. That's the per-tool
  authorization model — open tools (`ping`, `get_random_quote`) and discovery
  (`tools/list`) are reachable anonymously, gated by `Mcp-Name` (SEP-2243) at
  the HTTP layer.

- **Per-operation scope challenge.** The 401 at step 11 names the *exact* scope
  required for `save_memory` (`memories:write`) — this is the MCP spec's
  step-up authorization mechanism, and what triggers Claude to start the OAuth
  flow on demand.

- **No DCR, no shared secret.** Claude doesn't register a client. It just sends
  its public Client ID Metadata Document URL as the `client_id`, the AS fetches
  that URL, and uses it as an ephemeral public client
  (`token_endpoint_auth_method: "none"`, PKCE only). The AS supports both DCR
  and CIMD — Claude picks CIMD.

- **Defense in depth at the MCP server.** The HTTP gate (`toolAuthGate`) is the
  fast reject, but each tool handler still re-checks the JWT's scope claim, so
  a slipped request can't execute a protected operation unauthorized.

- **Resource indicator.** The access token's `aud` is bound to
  `https://mcp.8bitmemory.com/` (RFC 8707) — it cannot be replayed against any
  other MCP server that trusts the same AS.

## Drawn from

- Auth-server logs captured live via `railway logs` during the actual flow
  (CIMD `Fetching Client Metadata`, interaction `prompt: consent` with reasons
  `op_scopes_missing / rs_scopes_missing`, `Authorization SUCCESS` redirect,
  token-exchange body).
- Server implementation: `mcp-server/index.js` (soft auth + per-tool gate),
  `auth-server/index.js` (resource server + interactions), and
  `auth-server/adapter.js` (CIMD lookup at `find('Client', URL)`).
- See [`mcp-server/AUTH.md`](mcp-server/AUTH.md) for the authoritative per-tool
  scope matrix and capability manifest.

# MemoryBank MCP Server — Authorization Capabilities

`memorybank` v1.0.0 · MCP Server (Streamable HTTP)
Resource identifier: `https://mcp.8bitmemory.com`

MemoryBank implements **per-tool authorization**: some tools are open (no
authentication) and others require an OAuth 2.1 access token carrying a specific
scope. This document describes that model, the per-tool access matrix, and how
clients authenticate.

## Authorization model

- The server is an **OAuth 2.1 Resource Server**. Protected tools require a
  Bearer access token on each request (`Authorization: Bearer <token>`).
- Authorization is enforced **per request / per tool**, not per session — every
  call is independently authorized. There is no session-bound login state.
- Tokens are JWTs verified against the authorization server's JWKS; granted
  scopes are read from the token's `scope` claim.

## MCP `2026-07-28` conformance

- **Stateless transport** — no `initialize` handshake or `Mcp-Session-Id`
  required (SEP-2575 / SEP-2567); each request is self-contained.
- **Routing headers** — honors `Mcp-Method` and `Mcp-Name` (SEP-2243). The
  per-tool auth gate keys off `Mcp-Name` to decide whether a request needs a
  token *before* dispatching into the tool. Header values are validated against
  the request body; mismatches are rejected (`-32001`).
- **Protected Resource Metadata** — RFC 9728 discovery via
  `.well-known/oauth-protected-resource` plus a `WWW-Authenticate` challenge on
  `401`.
- **Per-operation scope challenge** — a `401` for a protected tool carries
  `scope="..."` naming the scope required for *that* tool, aligning with the
  spec's step-up authorization flow.

## Scopes

| Scope | Grants |
|-------|--------|
| `memories:read` | Read: list / search / read memories and tables |
| `memories:write` | Write: create / update / delete memories, tables, rows, columns |
| `openid`, `profile`, `email`, `offline_access` | Standard OIDC identity + refresh |

Advertised `scopes_supported`: `openid profile email offline_access memories:read memories:write`

## Per-tool authorization matrix

Legend: 🟢 open (no auth) · 🔒 requires token + scope

| Tool | Access | Required scope |
|------|--------|----------------|
| `ping` | 🟢 open | — |
| `get_random_quote` | 🟢 open | — |
| `save_memory` | 🔒 | `memories:write` |
| `list_memories` | 🔒 | `memories:read` |
| `show_memories` | 🔒 | `memories:read` |
| `search_memories` | 🔒 | `memories:read` |
| `delete_memory` | 🔒 | `memories:write` |
| `create_table` | 🔒 | `memories:write` |
| `list_tables` | 🔒 | `memories:read` |
| `get_table` | 🔒 | `memories:read` |
| `add_row` | 🔒 | `memories:write` |
| `update_row` | 🔒 | `memories:write` |
| `delete_row` | 🔒 | `memories:write` |
| `add_column` | 🔒 | `memories:write` |

## Discovery endpoints

- `GET /.well-known/oauth-protected-resource` — resource metadata
  (`resource`, `authorization_servers`, `scopes_supported`)
- Alt-flow variants: `/dcr/.well-known/oauth-protected-resource`,
  `/basicauth/.well-known/oauth-protected-resource`,
  `/dcr/mcp/.well-known/oauth-protected-resource`

MCP endpoints: `POST /mcp` (also `/`, `/dcr/mcp`, `/basicauth/mcp`).

## Authentication flow (protected tools)

1. Client calls a protected tool with no/insufficient token.
2. Server returns `401 Unauthorized` with
   `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`.
3. Client fetches Protected Resource Metadata and discovers the authorization
   server.
4. Client runs OAuth 2.1 (PKCE; DCR or client-id-metadata) and obtains a token
   for `resource=https://mcp.8bitmemory.com`.
5. Client retries with `Authorization: Bearer <token>`; the server validates the
   scope and executes.

Open tools (🟢) skip all of the above — they run on an anonymous request.

> **Current policy:** `tools/list` itself requires authentication — an anonymous
> list request gets a `401` scope challenge, so the OAuth flow is triggered at
> connect time rather than lazily on the first protected call. Open tools remain
> callable anonymously at `tools/call` time. (The earlier lazy model —
> anonymous discovery + per-call challenge — is one config change away:
> the `tools/list` branch in `toolAuthGate`.)

## Machine-readable manifest

```json
{
  "server": { "name": "memorybank", "version": "1.0.0" },
  "resource": "https://mcp.8bitmemory.com",
  "auth": {
    "model": "oauth2.1-resource-server",
    "enforcement": "per-tool",
    "scopes_supported": ["openid", "profile", "email", "offline_access", "memories:read", "memories:write"],
    "protected_resource_metadata": "/.well-known/oauth-protected-resource"
  },
  "tools": {
    "ping":              { "auth": "open" },
    "get_random_quote":  { "auth": "open" },
    "save_memory":      { "auth": "scoped", "scopes": ["memories:write"] },
    "list_memories":    { "auth": "scoped", "scopes": ["memories:read"] },
    "show_memories":    { "auth": "scoped", "scopes": ["memories:read"] },
    "search_memories":  { "auth": "scoped", "scopes": ["memories:read"] },
    "delete_memory":    { "auth": "scoped", "scopes": ["memories:write"] },
    "create_table":     { "auth": "scoped", "scopes": ["memories:write"] },
    "list_tables":      { "auth": "scoped", "scopes": ["memories:read"] },
    "get_table":        { "auth": "scoped", "scopes": ["memories:read"] },
    "add_row":          { "auth": "scoped", "scopes": ["memories:write"] },
    "update_row":       { "auth": "scoped", "scopes": ["memories:write"] },
    "delete_row":       { "auth": "scoped", "scopes": ["memories:write"] },
    "add_column":       { "auth": "scoped", "scopes": ["memories:write"] }
  }
}
```

## Status

- **Implemented:** OAuth 2.1 resource-server auth, RFC 9728 discovery, per-tool
  scope enforcement for the 12 memory/table tools, the open/no-auth tools
  (`ping`, `get_random_quote`), and the soft-auth gate (`softAuth` +
  `toolAuthGate`) that lets anonymous requests reach open tools while
  challenging protected ones and `tools/list`.
- **MCP Apps (SEP-1865):** the `show_memories` tool renders an interactive
  memory browser via the `ui://memorybank/memories` HTML resource
  (`text/html;profile=mcp-app`). The iframe's own actions (save/delete/refresh)
  round-trip through the host as real `tools/call` requests, so they are subject
  to the exact same per-tool scope enforcement as model-initiated calls.
- Enforcement is layered: the HTTP gate keys off `Mcp-Name`, and each protected
  tool also re-checks its scope in-handler as defense in depth.

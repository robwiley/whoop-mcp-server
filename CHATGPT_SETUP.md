# Private ChatGPT connections

The WHOOP account's OAuth tokens remain independent of ChatGPT's authorization.

Set these additional service variables:

- `MCP_PUBLIC_URL`: this service's public HTTPS origin, ending with `/`.
- `HEVY_MCP_URL`: optional, fixed HTTPS endpoint of the Hevy MCP service.
- `HEVY_MCP_TOKEN`: optional Railway reference to the Hevy service's `AUTH_TOKEN`.

Keep the existing `AUTH_TOKEN`, `ENCRYPTION_SECRET`, and persistent `DB_PATH`.
OAuth state is stored in `mcp-oauth.db` next to the WHOOP database. Registered
client credentials are encrypted; issued codes and tokens are stored as hashes.
Back up the volume and encryption secret together. Use one service replica.

Create two private developer-mode connections in ChatGPT, using OAuth with
dynamic client registration (leave client ID and secret blank):

1. WHOOP: `https://YOUR_SERVICE/mcp`
2. Hevy: `https://YOUR_SERVICE/hevy/mcp`

During each connection, enter the WHOOP service's `AUTH_TOKEN` into the private
consent page. Copy it directly from Railway; do not put it in a chat or URL.
This grants access only after owner authentication and explicit consent.
Do not use the WHOOP developer client ID/secret for ChatGPT's connection.

Only ChatGPT's stable or callback-specific HTTPS redirect addresses are accepted.
Tokens are bound to their resource. Access tokens expire after one hour; refresh
tokens rotate and last 90 days. Refresh-token replay revokes the grant family.
Revocation is supported at `/revoke`. Rotating AUTH_TOKEN changes the connection
password and legacy access, but does not revoke previously issued OAuth grants.
To revoke all ChatGPT connections, stop the service and remove only
`mcp-oauth.db` and its SQLite sidecars; never remove the WHOOP database.

Validation: `npm run build && node scripts/test-oauth.mjs` (Node 20 recommended).
The Hevy gateway forwards only to the configured upstream, replacing incoming
credentials with its server-side token. It preserves MCP session headers.
No routine weights are changed as part of setup.

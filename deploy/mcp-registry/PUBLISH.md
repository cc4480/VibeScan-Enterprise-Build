# Listing SecScan on the official MCP Registry

`server.json` here describes the remote MCP server at `https://secscan.us/api/mcp`
for [registry.modelcontextprotocol.io](https://github.com/modelcontextprotocol/registry).
It validates against the 2025-12-11 schema. Directories such as Glama, PulseMCP
and mcp.so read from the registry, so listing here is the first step.

## How ownership is proved

The name `us.secscan/secscan` is the reverse-DNS form of secscan.us. The registry
lets you publish under it only if you prove you control the domain. Two files
make up that proof:

| File | Where | Public? |
| --- | --- | --- |
| `artifacts/vibescan/public/.well-known/mcp-registry-auth` | Served at https://secscan.us/.well-known/mcp-registry-auth | Yes — it holds only the public key |
| `~/.secscan/mcp-registry-key.pem` | This machine only, outside every repo | **No. Never commit it.** |

`express.static` serves `/.well-known/` because app.ts sets `dotfiles: "allow"`
(the same reason security.txt works).

## Publish (once the auth file is live on secscan.us)

1. Check the auth file is live:

   ```bash
   curl https://secscan.us/.well-known/mcp-registry-auth
   # v=MCPv1; k=ed25519; p=...
   ```

2. Install `mcp-publisher`. Download the build for your OS from
   https://github.com/modelcontextprotocol/registry/releases (Windows:
   `mcp-publisher_windows_amd64.tar.gz`), unpack it and put it on your PATH.

3. Log in by proving the domain (Git Bash):

   ```bash
   PRIVATE_KEY="$(openssl pkey -in ~/.secscan/mcp-registry-key.pem -noout -text | grep -A3 "priv:" | tail -n +2 | tr -d ' :\n')"
   mcp-publisher login http --domain secscan.us --private-key "${PRIVATE_KEY}"
   ```

4. Publish, from this directory:

   ```bash
   cd deploy/mcp-registry
   mcp-publisher publish
   ```

5. Confirm the listing:

   ```bash
   curl "https://registry.modelcontextprotocol.io/v0/servers?search=us.secscan/secscan"
   ```

## Updating the listing

The registry never overwrites a published version. When the tools, URL or auth
change, bump `version` in server.json, keeping it the same as the version in
`McpServer({ name: "secscan", version })` in
artifacts/api-server/src/routes/mcp.ts. Then publish again.

If the key is lost, generate a new one and replace the public file:

```bash
openssl genpkey -algorithm Ed25519 -out ~/.secscan/mcp-registry-key.pem
PUB="$(openssl pkey -in ~/.secscan/mcp-registry-key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "v=MCPv1; k=ed25519; p=${PUB}" > artifacts/vibescan/public/.well-known/mcp-registry-auth
```

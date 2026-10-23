/**
 * End-to-end check of the MCP endpoint, driven by the official MCP client —
 * the same way Claude Code or Cursor would use it.
 *
 * Checks the tools work AND that there is no side door: the SSRF guard and
 * free-trial limits apply to MCP scans, one user cannot read another's scans,
 * and an API token authenticates ONLY /api/mcp (never the account routes).
 *
 * WRITES TEST DATA (registers users, edits scans, inserts a report). Run it
 * only against a local server backed by a throwaway database:
 *
 *   SECSCAN_URL=http://localhost:4300 \
 *   MCP_VERIFY_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5440/billing \
 *     node artifacts/api-server/scripts/verify-mcp.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createRequire } from "node:module";
const pg = createRequire(new URL("../../../lib/db/package.json", import.meta.url))("pg");
const B = process.env.SECSCAN_URL ?? "http://localhost:4300";
const db = new pg.Pool({ connectionString: process.env.MCP_VERIFY_DATABASE_URL });
const out = (label, v) => console.log(`${label.padEnd(44)} ${v}`);
async function register(email) {
  const r = await fetch(B + "/api/account/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "CorrectHorse-Battery-9" }) });
  const sid = (r.headers.getSetCookie?.() ?? []).map(c => c.split(";")[0]).find(c => c.startsWith("sid="));
  const me = await (await fetch(B + "/api/auth/user", { headers: { cookie: sid } })).json();
  return { sid, id: me.user.id };
}
const api = (sid, path, init = {}) => fetch(B + path, { ...init, headers: { "Content-Type": "application/json", cookie: sid, ...(init.headers ?? {}) } });
async function mcp(token) {
  const c = new Client({ name: "e2e", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(B + "/api/mcp"), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  return c;
}
const call = async (c, name, args = {}) => { const r = await c.callTool({ name, arguments: args }); return { err: !!r.isError, t: r.content[0].text }; };
const H = (tok) => ({ "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(tok ? { Authorization: `Bearer ${tok}` } : {}) });

const A = await register("mcp-a@example.com"), Bu = await register("mcp-b@example.com");
const created = await (await api(A.sid, "/api/account/tokens", { method: "POST", body: JSON.stringify({ name: "Claude Code" }) })).json();
out("token created (shown once)", `${created.token.slice(0, 8)}… prefix=${created.prefix}`);
out("token list never contains the secret", String(!JSON.stringify(await (await api(A.sid, "/api/account/tokens")).json()).includes(created.token)));
const tokB = (await (await api(Bu.sid, "/api/account/tokens", { method: "POST", body: JSON.stringify({ name: "b" }) })).json()).token;

const c = await mcp(created.token);
out("tools", (await c.listTools()).tools.map(t => t.name).join(", "));
out("list_verified_domains", (await call(c, "list_verified_domains")).t.slice(0, 60));
const s1 = await call(c, "scan_url", { url: "https://example.com" });
const scanId = s1.t.match(/scan_id: ([0-9a-f-]{36})/)?.[1];
out("scan_url example.com", s1.err ? "ERROR " + s1.t : `started ${scanId}`);
out("get_scan_status (no worker running)", (await call(c, "get_scan_status", { scan_id: scanId, wait_seconds: 3 })).t.slice(0, 70));
const ssrf = await call(c, "scan_url", { url: "http://127.0.0.1:5432/" });
out("scan_url to loopback — SSRF guard", (ssrf.err ? "REFUSED: " : "ALLOWED?! ") + ssrf.t.slice(0, 70));

await db.query("update scans set status='complete', completed_at=now() where id=$1", [scanId]);
await db.query(`insert into reports (scan_id, user_id, target_url, tier, data) values ($1,$2,'https://example.com','deep',$3)`, [scanId, A.id, JSON.stringify({
  summary: { grade: "C", riskScore: 54, critical: 0, high: 1, medium: 1, low: 0, info: 0, executiveSummary: "Two issues." },
  vulnerabilities: [
    { id: "1", name: "Missing Content-Security-Policy", severity: "medium", category: "headers", description: "No CSP header.", solution: "Add a CSP.", cweId: "CWE-693" },
    { id: "2", name: "Exposed .env file", severity: "high", category: "files", description: "/.env is readable.", solution: "Block dotfiles.", evidence: "GET /.env -> 200" }],
  aiAnalysis: { topPriorities: ["Remove /.env"], agentFixPrompt: "In your server config, deny requests for dotfiles" },
  compliance: { disclaimer: "Not a compliance verdict." } })]);
const rep = await call(c, "get_report", { scan_id: scanId });
out("get_report: high sorted before medium", String(rep.t.includes("[HIGH]") && rep.t.indexOf("[HIGH]") < rep.t.indexOf("[MEDIUM]")));
out("get_report: carries the editor fix prompt", String(rep.t.includes("deny requests for dotfiles")));
out("get_report: carries compliance disclaimer", String(rep.t.includes("Not a compliance verdict")));
out("get_scan_status on finished scan -> report", String((await call(c, "get_scan_status", { scan_id: scanId, wait_seconds: 5 })).t.startsWith("SecScan report")));
const cb = await mcp(tokB);
out("user B reading A's scan", (await call(cb, "get_report", { scan_id: scanId })).t);
out("malformed scan id", (await call(c, "get_report", { scan_id: "1; drop table scans" })).t);
// Spend whatever is left of the free allowance (3 by default), then expect a
// refusal — counted from get_account rather than assumed, so a change to
// FREE_TRIAL_SCAN_LIMIT does not silently turn the last line into a pass.
const left = Number(/Free scans left: (\d+)/.exec((await call(c, "get_account")).t)?.[1] ?? 0);
for (let i = 1; i <= left; i++) {
  const s = await call(c, "scan_url", { url: `https://example.org/?n=${i}` });
  out(`scan_url — free scan ${i} of ${left} left`, s.err ? "ERROR " + s.t.slice(0, 60) : "started");
}
out("scan_url once free scans are used up", (await call(c, "scan_url", { url: "https://example.net" })).t.slice(0, 115));

const noTok = await fetch(B + "/api/mcp", { method: "POST", headers: H(), body: "{}" });
out("POST /api/mcp without a token", `${noTok.status} ${noTok.headers.get("www-authenticate")}`);
out("forged token", String((await fetch(B + "/api/mcp", { method: "POST", headers: H("ssk_forged000000000000000000000000000000000000000"), body: "{}" })).status));
out("GET /api/mcp", String((await fetch(B + "/api/mcp")).status));
out("token used on a normal site route", `${(await fetch(B + "/api/account/tokens", { headers: { Authorization: `Bearer ${created.token}` } })).status} (must not authenticate)`);
out("token used to DELETE the account", `${(await fetch(B + "/api/account", { method: "DELETE", headers: { Authorization: `Bearer ${created.token}` } })).status} (must not authenticate)`);
await api(A.sid, `/api/account/tokens/${created.id}`, { method: "DELETE" });
out("revoked token", String((await fetch(B + "/api/mcp", { method: "POST", headers: H(created.token), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) })).status));
out("revoke someone else's token id", String((await api(Bu.sid, `/api/account/tokens/${created.id}`, { method: "DELETE" })).status));
await c.close(); await cb.close(); await db.end();

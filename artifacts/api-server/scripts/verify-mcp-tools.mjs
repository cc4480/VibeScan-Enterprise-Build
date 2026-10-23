/**
 * End-to-end check of the MCP 1.1 tools (account, domain verification,
 * monitoring, dismissals) through the official MCP client, against the real
 * routes and a real database.
 *
 * Proves each tool does what the website does — same charges, same refusals,
 * same ownership scoping — because each runs the website's own route.
 *
 * WRITES TEST DATA. Run it only against a local server on a throwaway database
 * (FREE_TRIAL_SCAN_LIMIT unset, so the default 3 applies):
 *
 *   SECSCAN_URL=http://localhost:4300 \
 *   MCP_VERIFY_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5440/mcpverify \
 *     node artifacts/api-server/scripts/verify-mcp-tools.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createRequire } from "node:module";
const pg = createRequire(new URL("../../../lib/db/package.json", import.meta.url))("pg");
const B = process.env.SECSCAN_URL ?? "http://localhost:4300";
const db = new pg.Pool({ connectionString: process.env.MCP_VERIFY_DATABASE_URL });

let pass = 0, fail = 0;
const check = (label, ok, detail = "") => {
  ok ? pass++ : fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? `  — ${String(detail).split("\n")[0].slice(0, 110)}` : ""}`);
};

async function register(email) {
  const r = await fetch(B + "/api/account/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: "CorrectHorse-Battery-9" }) });
  const sid = (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).find((c) => c.startsWith("sid="));
  const me = await (await fetch(B + "/api/auth/user", { headers: { cookie: sid } })).json();
  const tok = await (await fetch(B + "/api/account/tokens", { method: "POST", headers: { "Content-Type": "application/json", cookie: sid }, body: JSON.stringify({ name: "e2e" }) })).json();
  const c = new Client({ name: "e2e", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(B + "/api/mcp"), { requestInit: { headers: { Authorization: `Bearer ${tok.token}` } } }));
  return { id: me.user.id, sid, c };
}
const call = async (c, name, args = {}) => {
  const r = await c.callTool({ name, arguments: args });
  return { err: !!r.isError, t: r.content[0].text };
};
const idIn = (t) => /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.exec(t)?.[0];
const monitorIdIn = (t) => /monitor id ([0-9a-f-]{36})/.exec(t)?.[1];
const stamp = Date.now();

const A = await register(`tools-a-${stamp}@example.com`);
const Bu = await register(`tools-b-${stamp}@example.com`);

// ── the tool list ──
const { tools } = await A.c.listTools();
const names = tools.map((t) => t.name).sort();
check("12 tools listed", names.length === 12, names.join(", "));

// ── get_account ──
let x = await call(A.c, "get_account");
check("get_account: a new account has 3 of 3 free scans", x.t.includes("Free scans left this month: 3 of 3"), x.t);

// ── add_monitor spends a free scan, exactly like the website ──
x = await call(A.c, "add_monitor", { url: "https://example.com" });
const mon = monitorIdIn(x.t);
check("add_monitor: monitors the site and starts a baseline scan", !x.err && !!mon && /Baseline scan started: scan_id/.test(x.t), x.t);
x = await call(A.c, "get_account");
check("add_monitor: the baseline used one free scan", x.t.includes("Free scans left: 2 of 3"), x.t);
let row = (await db.query("select paid_with, origin from scans where user_id=$1 and origin='monitor' order by created_at desc limit 1", [A.id])).rows[0];
check("add_monitor: baseline recorded as paid with a free scan", row?.paid_with === "free", JSON.stringify(row));

x = await call(A.c, "add_monitor", { url: "https://example.com" });
check("add_monitor: the same site twice is refused", x.err && /already have an active monitor/i.test(x.t), x.t);

// ── list_monitors ──
x = await call(A.c, "list_monitors");
check("list_monitors: shows the monitor with its id", x.t.includes("https://example.com") && x.t.includes(mon), x.t);
x = await call(Bu.c, "list_monitors");
check("list_monitors: another user sees none of them", /No sites are being monitored/.test(x.t), x.t);

// ── monitor_scan_now ──
x = await call(A.c, "monitor_scan_now", { monitor_id: mon });
check("monitor_scan_now: starts a scan", !x.err && /Scan started: scan_id/.test(x.t), x.t);
x = await call(A.c, "get_account");
check("monitor_scan_now: used one free scan", x.t.includes("Free scans left: 1 of 3"), x.t);
x = await call(Bu.c, "monitor_scan_now", { monitor_id: mon });
check("monitor_scan_now: another user's monitor is 'not found'", x.err && /No monitor with that id/.test(x.t), x.t);
x = await call(A.c, "monitor_scan_now", { monitor_id: "not-a-uuid" });
check("monitor_scan_now: a malformed id is refused", x.err, x.t);

// ── spend the last free scan, then credits ──
x = await call(A.c, "scan_url", { url: "https://example.org" });
check("scan_url: the last free scan", !x.err && /Paid with: free/.test(x.t), x.t);
x = await call(A.c, "add_monitor", { url: "https://example.net" });
check("add_monitor: refused with no free scans and no credits", x.err && /used this month.s 3 free scans/.test(x.t), x.t);
const monitorsAfterRefusal = Number((await db.query("select count(*) from monitor_subscriptions where user_id=$1", [A.id])).rows[0].count);
check("add_monitor: a refusal creates no monitor", monitorsAfterRefusal === 1, `${monitorsAfterRefusal} monitor(s)`);

await db.query("insert into credits (user_id, balance) values ($1, 2) on conflict (user_id) do update set balance = 2", [A.id]);
x = await call(A.c, "get_account");
check("get_account: shows credits", x.t.includes("Credits: 2") && x.t.includes("Free scans left: 0 of 3"), x.t.replace(/\n/g, " | "));
x = await call(A.c, "add_monitor", { url: "https://example.net" });
check("add_monitor: a credit holder can add a monitor once free scans are gone", !x.err && /Now monitoring https:\/\/example\.net/.test(x.t), x.t);
row = (await db.query("select paid_with from scans where user_id=$1 and target_url='https://example.net' order by created_at desc limit 1", [A.id])).rows[0];
x = await call(A.c, "get_account");
check("add_monitor: the baseline was paid with a credit", row?.paid_with === "credit" && x.t.includes("Credits: 1"), `${row?.paid_with}; ${x.t.split("\n")[1]}`);

// ── domain verification ──
x = await call(A.c, "start_domain_verification", { domain: "https://example.com/some/path" });
check("start_domain_verification: returns the file and the DNS record", !x.err && /not verified yet/.test(x.t) && /File: serve exactly this text at https:\/\/example\.com\//.test(x.t) && /TXT record named/.test(x.t), x.t);
x = await call(A.c, "check_domain_verification", { domain: "example.com" });
check("check_domain_verification: not live yet is reported as not found, with the instructions", x.err && /Not found yet/.test(x.t) && /TXT record named/.test(x.t), x.t);
x = await call(Bu.c, "check_domain_verification", { domain: "example.com" });
check("check_domain_verification: another user has no verification to check", x.err && /No verification started/.test(x.t), x.t);
// Mark it verified the way a successful check does, then confirm every tool agrees.
await db.query("update domain_verifications set verified_at=now(), method='well_known' where user_id=$1 and domain='example.com'", [A.id]);
x = await call(A.c, "check_domain_verification", { domain: "example.com" });
check("check_domain_verification: reports VERIFIED once it is", !x.err && /VERIFIED \(file\)/.test(x.t), x.t);
x = await call(A.c, "list_verified_domains");
check("list_verified_domains: agrees", x.t.includes("example.com"), x.t);
x = await call(A.c, "start_domain_verification", { domain: "example.com" });
check("start_domain_verification: does not revoke an already-verified domain", /VERIFIED/.test(x.t), x.t);

// ── dismiss_finding ──
const scanRow = (await db.query("insert into scans (user_id, user_email, target_url, tier, status, origin, completed_at) values ($1,'a@example.com','https://example.com','deep','complete','user',now()) returning id", [A.id])).rows[0];
await db.query("insert into reports (scan_id, user_id, target_url, tier, data) values ($1,$2,'https://example.com','deep',$3)", [
  scanRow.id, A.id,
  JSON.stringify({ summary: { grade: "C" }, vulnerabilities: [{ name: "Missing Referrer-Policy Header", severity: "low", category: "Security Headers", description: "d", solution: "s", evidence: "none" }] }),
]);
x = await call(A.c, "dismiss_finding", { scan_id: scanRow.id, finding_name: "Something The Scan Never Said" });
check("dismiss_finding: refuses a finding the report does not contain", x.err && /no finding named/.test(x.t), x.t);
x = await call(Bu.c, "dismiss_finding", { scan_id: scanRow.id, finding_name: "Missing Referrer-Policy Header" });
check("dismiss_finding: another user cannot dismiss on this scan", x.err && /No finished scan/.test(x.t), x.t);
x = await call(A.c, "dismiss_finding", { scan_id: scanRow.id, finding_name: "missing referrer-policy header" });
const dis = (await db.query("select finding_name, finding_category, reason from dismissed_findings where user_id=$1", [A.id])).rows;
check("dismiss_finding: dismisses it with the report's own category, as the app does", !x.err && dis.length === 1 && dis[0].finding_category === "Security Headers" && dis[0].reason === "false_positive", `${x.t} | ${JSON.stringify(dis)}`);

// ── the server tells the editor the rules ──
const instr = A.c.getInstructions() ?? "";
check("instructions: dismiss only on the user's confirmation", /never to improve a grade/.test(instr));

await A.c.close();
await Bu.c.close();
await db.end();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

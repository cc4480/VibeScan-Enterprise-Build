/**
 * Proves active probing cannot be steered onto a host the requester did not verify. A local "attacker"
 * site answers 302 to a local "victim" site that records every request. Same scan, run twice:
 *   1. requester verified only the attacker host  -> the victim must see NO attack traffic
 *   2. requester also verified the victim host    -> the victim DOES see it (proves the check can see it)
 * Local only (127.0.0.1 and 127.0.0.2). Run with ALLOW_PRIVATE_SCAN_TARGETS=true and any DATABASE_URL.
 */
import http from "node:http";
import { runScan } from "../src/lib/scanner.js";
import { initBrowser, closeBrowser } from "../src/lib/browser.js";

const ATTACK = /['"<>]|\.\.\/|%27|%3c|union\s|sleep\(|etc\/passwd|<script/i;

function listen(host: string, handler: http.RequestListener): Promise<{ port: number; srv: http.Server }> {
  return new Promise((resolve) => {
    const srv = http.createServer(handler).listen(0, host, () => resolve({ port: (srv.address() as { port: number }).port, srv }));
  });
}

async function run(verifyVictim: boolean) {
  const seen: string[] = [];
  const victim = await listen("127.0.0.2", (req, res) => {
    seen.push(`${req.method} ${decodeURIComponent(req.url ?? "")}`);
    res.writeHead(200, { "content-type": "text/html" }).end('<html><body><a href="/item?id=1">item</a><form action="/s" method="get"><input name="q"></form></body></html>');
  });
  const attacker = await listen("127.0.0.1", (_req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.2:${victim.port}/` }).end();
  });
  const attackerUrl = `http://127.0.0.1:${attacker.port}/`;
  const r = await runScan(attackerUrl, "deep", true, undefined, null, undefined, {
    verifyHost: async (u) => verifyVictim && new URL(u).hostname === "127.0.0.2",
  });
  attacker.srv.close();
  victim.srv.close();
  const attackShaped = seen.filter((l) => !/^(GET|HEAD|OPTIONS) /.test(l) || ATTACK.test(l));
  const withdrawn = r.vulnerabilities.some((v) => /Active security testing was skipped/i.test(v.name) && /redirected to 127\.0\.0\.2/.test(v.evidence ?? ""));
  return { total: seen.length, attackShaped, withdrawn };
}

await initBrowser();
const blocked = await run(false);
const allowed = await run(true);
await closeBrowser();
console.log(`victim NOT verified: ${blocked.total} request(s) received, ${blocked.attackShaped.length} attack-shaped; report says active testing withdrawn: ${blocked.withdrawn}`);
console.log(`victim verified    : ${allowed.total} request(s) received, ${allowed.attackShaped.length} attack-shaped (sample: ${allowed.attackShaped[0] ?? "none"})`);
const ok = blocked.attackShaped.length === 0 && blocked.withdrawn && allowed.attackShaped.length > 0;
console.log(ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);

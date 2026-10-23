/** Regression check: nextjsProbe + jwtAnalysis fire on the planted fixtures. */
process.env["DATABASE_URL"] ??= "postgres://localhost/self-test";
import { runNextjsProbe } from "../../api-server/src/lib/nextjsProbe.js";
import { analyzeJwts } from "../../api-server/src/lib/jwtAnalysis.js";
import {
  NEXT_DATA_PROPS,
  JWT_ALG_NONE,
  JWT_NO_EXPIRY,
  JWT_EXCESSIVE_LIFETIME,
  JWT_SENSITIVE_PAYLOAD,
} from "../src/secrets.js";

const html = `<!doctype html><html><head></head><body>
<div id="__next"></div>
<script id="__NEXT_DATA__" type="application/json">${JSON.stringify(NEXT_DATA_PROPS)}</script>
<p>JWTs: ${JWT_ALG_NONE} ${JWT_NO_EXPIRY} ${JWT_EXCESSIVE_LIFETIME} ${JWT_SENSITIVE_PAYLOAD}</p>
</body></html>`;

const nextFindings = await runNextjsProbe("https://fixture.example/", html);
console.log(`__NEXT_DATA__: ${nextFindings.length} findings`);
for (const f of nextFindings) console.log(`  [hit] ${f.name}`);

const jwtFindings = await analyzeJwts({}, html);
console.log(`\nJWT: ${jwtFindings.length} findings`);
for (const f of jwtFindings) console.log(`  [hit] ${f.name}`);

if (nextFindings.length < 7 || jwtFindings.length < 4) {
  console.log("\nFEWER THAN EXPECTED — inspect above.");
  process.exit(1);
}

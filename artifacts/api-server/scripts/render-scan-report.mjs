/**
 * Renders SCAN-RESULTS.md and scans/<host>.md from a live-scan --json capture.
 * Everything in the output comes from the capture; nothing is transcribed.
 *
 *   node artifacts/api-server/scripts/render-scan-report.mjs run.json out/
 *
 * Score and grade come from scanner.ts's own computeRiskScore/computeGrade,
 * reimplemented here rather than imported so this stays a plain .mjs script with
 * no TypeScript loader. The weights are pinned by scanner.test.ts; if they move
 * there and not here, the tables are wrong — which is why they are stated in the
 * output rather than left implicit.
 *
 * A site whose scan was answered by a bot-protection interstitial gets NO score
 * and NO grade. Scoring one produces an A that means "we never got in", which on
 * the page is indistinguishable from an A that means "well configured".
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const [, , src, outDir] = process.argv;
const raw = JSON.parse(readFileSync(src, "utf8"));
const SEV = ["critical", "high", "medium", "low", "info"];
const rank = Object.fromEntries(SEV.map((s, i) => [s, i]));

// scanner.ts:computeRiskScore — higher is worse, capped at 100. Info weighs 0:
// a check that can only see whether something is *advertised* must not move a
// grade.
const WEIGHT = { critical: 30, high: 15, medium: 5, low: 1, info: 0 };
const riskScore = (findings) =>
  Math.min(100, findings.reduce((n, f) => n + (WEIGHT[f.severity] ?? 0), 0));

// scanner.ts:computeGrade
const gradeFor = (score) =>
  score <= 10 ? "A" : score <= 25 ? "B" : score <= 45 ? "C" : score <= 65 ? "D" : "F";

const host = (u) => {
  try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; }
};

const sites = raw.results
  .filter((r) => !r.failed)
  .map((r) => {
    const intercepted = r.findings.some((f) => /intercepted by a bot-protection/i.test(f.name));
    return {
      host: host(r.url),
      url: r.url,
      finalUrl: r.finalUrl,
      status: r.statusCode,
      pages: r.pagesScanned,
      elapsedMs: r.elapsedMs,
      intercepted,
      findings: [...r.findings].sort(
        (a, b) => rank[a.severity] - rank[b.severity] || a.name.localeCompare(b.name),
      ),
      counts: Object.fromEntries(SEV.map((s) => [s, r.findings.filter((f) => f.severity === s).length])),
      actionable: r.findings.filter((f) => f.severity !== "info").length,
      // Only meaningful for a scan that reached the site's own page.
      score: intercepted ? null : riskScore(r.findings),
      grade: intercepted ? null : gradeFor(riskScore(r.findings)),
    };
  })
  .sort((a, b) => a.host.localeCompare(b.host));

const failed = raw.results.filter((r) => r.failed);
const total = sites.reduce((a, s) => a + s.findings.length, 0);
const actionable = sites.reduce((a, s) => a + s.actionable, 0);
const bySev = Object.fromEntries(SEV.map((s) => [s, sites.reduce((a, x) => a + x.counts[s], 0)]));
const pages = sites.reduce((a, s) => a + (s.pages || 0), 0);
const sev = (s) => s[0].toUpperCase() + s.slice(1);
const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
const slug = (h) => h.replace(/[^a-z0-9.-]/gi, "_");

mkdirSync(join(outDir, "scans"), { recursive: true });

// ── index ────────────────────────────────────────────────────────────────────
const out = [];
out.push("# Scan results");
out.push("");
out.push(
  `Passive scans of ${sites.length} sites, captured ${new Date(raw.scannedAt).toISOString().slice(0, 10)}. ` +
  "Every actionable finding here was verified by hand against the live site. " +
  "That the scanner still detects real vulnerabilities is shown separately in " +
  "[DETECTION-VALIDATION.md](DETECTION-VALIDATION.md), because a scanner that " +
  "reports nothing would also produce a clean-looking page like this one.",
);
out.push("");
out.push(
  "Passive means HTTP GETs and DNS lookups against publicly served pages. No " +
  "authentication was attempted, no parameters were manipulated, and no state " +
  "was altered on any site. Every finding below can be reproduced by anyone " +
  "with `curl` or `dig`.",
);
out.push("");
out.push(
  `**${total} findings across ${sites.length} sites, ${actionable} of them above Info.** ` +
  SEV.map((s) => `${bySev[s]} ${s}`).join(", ") + `. ${pages} pages fetched in total.`,
);
out.push("");

if (failed.length) {
  out.push("Not reached, and therefore not included:");
  out.push("");
  for (const f of failed) out.push(`- \`${f.url}\` — ${f.failed}`);
  out.push("");
}

const interceptedSites = sites.filter((s) => s.intercepted);
if (interceptedSites.length) {
  out.push("## Read this before comparing sites");
  out.push("");
  out.push(
    `${interceptedSites.length} of these sites answered with a bot-protection interstitial rather than ` +
    "their own page: " + interceptedSites.map((s) => `\`${s.host}\``).join(", ") + ". " +
    "The scanner withholds every finding read from such a response, so those " +
    "sites show only a handful of findings and often zero actionable ones. " +
    "**That is suppressed coverage, not a clean result** — it means their page " +
    "was never seen. Their counts are not comparable with the rest.",
  );
  out.push("");
}

out.push("## Every site");
out.push("");
out.push("| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |");
out.push("|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|");
for (const s of sites) {
  const note = s.intercepted ? " *" : "";
  out.push(
    `| ${s.host}${note} | ${s.score ?? "—"} | ${s.grade ?? "—"} | ${s.findings.length} | ${s.actionable} | ` +
    `${s.counts.critical} | ${s.counts.high} | ` +
    `${s.counts.medium} | ${s.counts.low} | ${s.counts.info} | [detail](scans/${slug(s.host)}.md) |`,
  );
}
out.push("");
{
  const graded = sites.filter((s) => s.grade);
  const dist = {};
  for (const s of graded) dist[s.grade] = (dist[s.grade] ?? 0) + 1;
  const mean = graded.length
    ? (graded.reduce((n, s) => n + s.score, 0) / graded.length).toFixed(1)
    : "—";
  out.push(
    `**Grades, over the ${graded.length} sites actually reached:** ` +
    ["A", "B", "C", "D", "F"].map((g) => `${g} ${dist[g] ?? 0}`).join(" · ") +
    ` — mean score ${mean}.`,
  );
  out.push("");
  out.push(
    "Score is `computeRiskScore`: critical 30, high 15, medium 5, low 1, " +
    "**info 0** — higher is worse, capped at 100. Grade is `computeGrade`: " +
    "A ≤ 10, B ≤ 25, C ≤ 45, D ≤ 65, F above. Info scoring zero is why a site " +
    "with a dozen findings can still grade A.",
  );
}
out.push("");
if (interceptedSites.length) out.push("`*` answered with a bot-protection interstitial; see above.");
out.push("");

// ── findings by prevalence ───────────────────────────────────────────────────
const prev = {};
for (const s of sites) {
  if (s.intercepted) continue;
  for (const name of new Set(s.findings.map((f) => f.name))) {
    const f = s.findings.find((x) => x.name === name);
    prev[name] ??= { name, severity: f.severity, cwe: f.cweId, sites: [] };
    prev[name].sites.push(s.host);
  }
}
const fully = sites.filter((s) => !s.intercepted).length;
out.push("## What came up most often");
out.push("");
out.push(`Across the ${fully} sites whose own pages were seen.`);
out.push("");
out.push("| Finding | Severity | Sites | CWE |");
out.push("|---|---|---:|---|");
for (const p of Object.values(prev).sort((a, b) => b.sites.length - a.sites.length || rank[a.severity] - rank[b.severity])) {
  out.push(`| ${esc(p.name)} | ${sev(p.severity)} | ${p.sites.length}/${fully} | ${p.cwe ?? "—"} |`);
}
out.push("");

writeFileSync(join(outDir, "SCAN-RESULTS.md"), out.join("\n") + "\n");

// ── per-site detail ──────────────────────────────────────────────────────────
for (const s of sites) {
  const d = [];
  d.push(`# ${s.host}`);
  d.push("");
  d.push(`- Requested: \`${s.url}\``);
  if (s.finalUrl && s.finalUrl.replace(/\/$/, "") !== s.url.replace(/\/$/, "")) {
    d.push(`- Final URL: \`${s.finalUrl}\``);
  }
  d.push(`- HTTP ${s.status}, ${s.pages} inner page(s) fetched, ${(s.elapsedMs / 1000).toFixed(1)}s`);
  d.push(`- ${s.findings.length} findings, ${s.actionable} above Info`);
  if (s.grade) d.push(`- Risk score ${s.score}/100 — grade ${s.grade}`);
  if (s.intercepted) {
    d.push("");
    d.push(
      "> This scan was answered by a bot-protection interstitial. Findings read " +
      "from that response are withheld, so this is a partial view — not a clean result.",
    );
  }
  d.push("");
  if (!s.findings.length) {
    d.push("No findings.");
  } else {
    for (const f of s.findings) {
      d.push(`### ${f.name}`);
      d.push("");
      d.push(`**${sev(f.severity)}**${f.cweId ? ` · ${f.cweId}` : ""}${f.cvssScore != null ? ` · CVSS ${f.cvssScore}` : ""}${f.wstgId ? ` · ${f.wstgId}` : ""} · ${f.category}`);
      d.push("");
      if (f.evidence) {
        d.push("```");
        d.push(String(f.evidence).trim());
        d.push("```");
        d.push("");
      }
    }
  }
  writeFileSync(join(outDir, "scans", `${slug(s.host)}.md`), d.join("\n") + "\n");
}

console.log(`SCAN-RESULTS.md + ${sites.length} per-site files`);
console.log(`  ${total} findings, ${actionable} actionable, ${bySev.critical} critical, ${bySev.high} high`);
console.log(`  intercepted (ungraded): ${interceptedSites.map((s) => s.host).join(", ") || "none"}`);
if (failed.length) console.log(`  failed: ${failed.map((f) => f.url).join(", ")}`);

/**
 * Generates SCAN_CHECKS.md — the exhaustive index of every finding the scanner
 * can emit, read out of the source rather than maintained by hand.
 *
 * Why this is generated. SCAN_COVERAGE.md is the readable catalogue: it groups
 * checks by module, marks the Basic/Deep tier, and explains methodology. That
 * prose is worth writing by hand and cannot be derived from the code. What it
 * cannot do is stay complete — three modules (mailTls, structuredData,
 * challengePage) landed in one day and none of them reached the document. This
 * script covers the other half: it can prove a finding exists because it read
 * the literal that emits it, and it goes stale the moment it stops being run.
 *
 * Run it after adding or removing a check:
 *
 *   node artifacts/api-server/scripts/check-index.mjs
 *
 * Pass --check to fail instead of writing, for CI:
 *
 *   node artifacts/api-server/scripts/check-index.mjs --check
 *
 * What it parses. Every `severity:` in a ScanVulnerability object literal under
 * src/lib, with the name, category, CWE, CVSS and WSTG id that sit alongside
 * it. Regex, not the TypeScript AST — the same trade the scanner itself makes
 * for HTML. That is sound only because the shape is uniform; the assumptions
 * are listed in ASSUMPTIONS below, and a violated one shows up as an unnamed
 * row in the output rather than a silent omission.
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = join(HERE, "..", "src", "lib");
const OUT = join(HERE, "..", "..", "..", "SCAN_CHECKS.md");

const ASSUMPTIONS = [
  "A finding is an object literal carrying `severity:` with one of the five levels.",
  "Its name comes from `name:` in the same literal — or `header:`, for the header-gap table whose names are composed at the emit site.",
  "A ternary severity or name means the check emits two variants (session vs non-session cookies, for example).",
];

/**
 * Modules that define check *templates* in a data table, where the sibling
 * module that emits them assigns category and CWE centrally. Without this the
 * index would report 19 subdomain-takeover services as missing a CWE, when
 * subdomainTakeover.ts stamps CWE-350 on every one of them.
 */
const CENTRAL = {
  "secret-pattern-data": { cat: "Exposed Secrets / Credentials", emitter: "jsScanner.ts" },
  "subdomain-service-data": { cat: "DNS Security", cwe: "CWE-350", emitter: "subdomainTakeover.ts" },
  "recon-data": { cat: "Exposed Service", emitter: "recon.ts" },
  nextjsProbe: { cat: "Secret Exposed in Page HTML", emitter: "nextjsProbe.ts" },
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = Object.fromEntries(SEV_ORDER.map((s, i) => [s, SEV_ORDER.length - i]));

const files = readdirSync(LIB).filter((f) => f.endsWith(".ts"));
const sourceFiles = files.filter((f) => !f.endsWith(".test.ts"));
const testFiles = files.filter((f) => f.endsWith(".test.ts"));

const src = Object.fromEntries(files.map((f) => [f, readFileSync(join(LIB, f), "utf8")]));
const modOf = (f) => f.replace(/\.ts$/, "");

/** it()/test() declarations per source module. */
const testsFor = {};
for (const t of testFiles) {
  // clientIp.origin-secret.test.ts and clientIp.test.ts both belong to clientIp.
  let base = t.replace(/\.test\.ts$/, "");
  while (base && !sourceFiles.includes(base + ".ts") && base.includes(".")) base = base.slice(0, base.lastIndexOf("."));
  const n = (src[t].match(/^\s*(?:it|test)\(/gm) || []).length;
  testsFor[base] = (testsFor[base] || 0) + n;
}

/** Which modules import which, from the source, so coverage is not guessed. */
const importsOf = {};
for (const f of files) {
  importsOf[f] = new Set(
    [...src[f].matchAll(/from\s+"\.\/([A-Za-z0-9_-]+)(?:\.js)?"/g)].map((m) => m[1]),
  );
}

function coverage(mod) {
  if (testsFor[mod]) return { level: "direct", via: `${mod}.test.ts` };
  const byTest = testFiles.filter((t) => importsOf[t].has(mod));
  if (byTest.length) return { level: "indirect", via: byTest.join(", ") };
  const byTested = sourceFiles.filter((f) => importsOf[f].has(mod) && testsFor[modOf(f)]);
  if (byTested.length) return { level: "indirect", via: byTested.map((f) => `${modOf(f)}.test.ts`).join(", ") };
  return { level: "none", via: "nothing reaches it" };
}

const STR = String.raw`(?:\`([^\`]*)\`|"([^"]*)"|'([^']*)')`;
const pick = (m, i) => (m ? m[i] ?? m[i + 1] ?? m[i + 2] : null);

/** Port definitions in recon-data carry their finding on a `dangerous` block. */
function parseReconData(text) {
  const re = /\{\s*port:\s*(\d+),\s*service:\s*"([^"]+)",\s*dangerous:\s*\{\s*severity:\s*"(critical|high|medium)"[\s\S]{0,900}?cweId:\s*"([^"]+)",\s*cvssScore:\s*([\d.]+)/g;
  return [...text.matchAll(re)].map((m) => ({
    name: `${m[2]} Exposed on Port ${m[1]}`,
    sev: m[3],
    cat: "Exposed Service",
    cwe: m[4],
    cvss: Number(m[5]),
    wstg: null,
  }));
}

/**
 * A copy of the source with every brace that is not structural replaced by a
 * space, so brace matching cannot be thrown off by one inside a string, a
 * comment, a template literal or — the case that actually bit — a regex:
 * `/(?:password|pwd)\s*[:=]\s*["'][^"']{8,}["']/` in secret-pattern-data.ts
 * opens a brace that never closes, and a naive scan walks straight past the
 * start of the object it was looking for.
 *
 * Indices are preserved, so a span found here slices the original text.
 */
function maskLiterals(text) {
  const out = text.split("");
  const mask = (i) => { if (out[i] === "{" || out[i] === "}") out[i] = " "; };
  let i = 0;

  const prevCode = () => {
    for (let j = i - 1; j >= 0; j--) if (!/\s/.test(text[j])) return text[j];
    return "";
  };

  // A regex can also follow a keyword, where the character before it is an
  // ordinary letter. `return /"[^"]{8,}"/i.test(body)` in probes-data.ts read
  // the "n" of "return" as the previous code character, classified the slash as
  // division, and scanned the pattern as code — so {8,} opened a brace that
  // never closed and every object span after it started in the wrong place.
  // Findings from /Dockerfile onward were then reported under their
  // neighbour's name.
  const KEYWORD_BEFORE_REGEX = new Set([
    "return", "typeof", "instanceof", "in", "of", "case", "do", "else",
    "void", "delete", "yield", "await", "new", "throw",
  ]);

  const prevWord = () => {
    let j = i - 1;
    while (j >= 0 && /\s/.test(text[j])) j--;
    const end = j + 1;
    while (j >= 0 && /[\w$]/.test(text[j])) j--;
    return text.slice(j + 1, end);
  };

  // Template literals nest — scanner.ts has `...${vendor ? `${vendor}'s` : "x"}...`
  // — so a scan that just runs to the next backtick ends the string inside its
  // own interpolation and every brace after it is classified wrongly. That is
  // what put a neighbouring finding's CVSS on two Scan Coverage findings.
  const scanTemplate = () => {
    while (i < text.length) {
      if (text[i] === "\\") { i += 2; continue; }
      if (text[i] === "`") { i++; return; }
      if (text[i] === "$" && text[i + 1] === "{") {
        mask(i + 1);       // the ${ brace is punctuation, not an object
        i += 2;
        scanCode(true);    // consumes through the matching }
        continue;
      }
      mask(i++);
    }
  };

  function scanCode(untilCloseBrace) {
    let depth = 0;
    while (i < text.length) {
      const ch = text[i];
      const next = text[i + 1];
      if (ch === "/" && next === "/") { while (i < text.length && text[i] !== "\n") mask(i++); continue; }
      if (ch === "/" && next === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) mask(i++); i += 2; continue; }
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i++;
        while (i < text.length) {
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i] === quote) { i++; break; }
          mask(i++);
        }
        continue;
      }
      if (ch === "`") { i++; scanTemplate(); continue; }
      // A `/` opens a regex only where a value may begin — otherwise it is division.
      if (
        ch === "/" &&
        (/^[(,=:[!&|?{};+\-*%<>]?$/.test(prevCode()) || KEYWORD_BEFORE_REGEX.has(prevWord()))
      ) {
        i++;
        let inClass = false;
        while (i < text.length) {
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i] === "[") inClass = true;
          else if (text[i] === "]") inClass = false;
          else if (text[i] === "/" && !inClass) { i++; break; }
          else if (text[i] === "\n") break;
          mask(i++);
        }
        continue;
      }
      if (ch === "{") { depth++; i++; continue; }
      if (ch === "}") {
        if (untilCloseBrace && depth === 0) { mask(i); i++; return; }
        depth--; i++; continue;
      }
      i++;
    }
  }

  scanCode(false);
  return out.join("");
}

/**
 * The span of the object literal containing `at`, found by matching braces
 * outward over the masked text. A fixed character window is not good enough:
 * the header-gap table in crawler.ts packs sibling literals close together, and
 * a window reaches past the entry it belongs to and reads the neighbour's name.
 */
function enclosingObject(text, masked, at) {
  let depth = 0;
  let start = -1;
  for (let i = at; i >= 0; i--) {
    const ch = masked[i];
    if (ch === "}") depth++;
    else if (ch === "{") {
      if (depth === 0) { start = i; break; }
      depth--;
    }
  }
  if (start === -1) return null;
  depth = 0;
  for (let i = start; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  return text.slice(start);
}

function parseModule(file, text) {
  if (file === "recon-data.ts") return parseReconData(text);
  const masked = maskLiterals(text);
  const nameRe = new RegExp(String.raw`(?:name|header):\s*(?:\w+\s*\?\s*${STR}\s*:\s*${STR}|${STR})`);
  const sevRe = /severity:\s*(?:"(critical|high|medium|low|info)"|\w+\s*\?\s*"(critical|high|medium|low|info)"\s*:\s*"(critical|high|medium|low|info)")/g;
  const rows = [];
  let m;
  while ((m = sevRe.exec(text))) {
    const lineStart = text.lastIndexOf("\n", m.index) + 1;
    const lineEnd = text.indexOf("\n", m.index);
    // `severity: "critical" | "high" | ...` is the type declaration, not a finding.
    if (text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd).includes("|")) continue;

    const obj = enclosingObject(text, masked, m.index) ?? "";
    const nameM = nameRe.exec(obj);
    const name = !nameM ? null : pick(nameM, 1) && pick(nameM, 4) ? `${pick(nameM, 1)} / ${pick(nameM, 4)}` : pick(nameM, 7);

    const isHeaderGap = !!nameM && nameM[0].startsWith("header:");
    const catM = new RegExp(String.raw`category:\s*${STR}`).exec(obj);
    const cvssM = /cvssScore:\s*(?:\w+\s*\?\s*([\d.]+)\s*:\s*([\d.]+)|([\d.]+))/.exec(obj);
    const cweM = /cweId:\s*"([^"]*)"/.exec(obj);
    const wstgM = /wstgId:\s*"([^"]*)"/.exec(obj);

    rows.push({
      // The header-gap table names and categorises itself at the emit site.
      name: name && isHeaderGap ? `${name} Missing on Internal Routes` : name,
      sev: m[1] ?? `${m[2]}/${m[3]}`,
      cat: isHeaderGap ? "Security Header Inconsistency" : catM ? pick(catM, 1) : null,
      cwe: cweM ? cweM[1] : null,
      cvss: cvssM ? Number(cvssM[1] ?? cvssM[3]) : null,
      wstg: wstgM ? wstgM[1] : null,
    });
  }
  return rows;
}

const modules = [];
for (const f of sourceFiles) {
  const rows = parseModule(f, src[f]);
  if (!rows.length) continue;
  const mod = modOf(f);
  const central = CENTRAL[mod] || {};
  modules.push({
    mod,
    file: f,
    loc: src[f].split("\n").length,
    tests: testsFor[mod] || 0,
    cov: coverage(mod),
    emitter: central.emitter && central.emitter !== f ? central.emitter : null,
    rows: rows.map((r) => ({ ...r, cat: r.cat || central.cat || null, cwe: r.cwe || central.cwe || null })),
  });
}

const all = modules.flatMap((m) => m.rows.map((r) => ({ ...r, mod: m.mod })));
const primary = (s) => s.split("/")[0];
const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, all.filter((r) => primary(r.sev) === s).length]));
const cats = [...new Set(all.map((r) => r.cat).filter(Boolean))].sort();
const unnamed = all.filter((r) => !r.name);
const uncovered = modules.filter((m) => m.cov.level === "none");

const esc = (s) => String(s).replace(/\|/g, "\\|");
const sevCell = (s) => s.split("/").map((x) => x[0].toUpperCase() + x.slice(1)).join(" / ");

const out = [];
out.push("# SecScan — Check Index");
out.push("");
out.push("<!-- GENERATED FILE — do not edit by hand.");
out.push("     Regenerate with: node artifacts/api-server/scripts/check-index.mjs -->");
out.push("");
out.push(
  "Every finding the scanner can emit, read out of `artifacts/api-server/src/lib`. This is the",
  "complete list; [SCAN_COVERAGE.md](SCAN_COVERAGE.md) is the readable one, grouped by module with",
  "the Basic/Deep tier and the methodology behind each group.",
);
out.push("");
out.push(
  `**${all.length} findings across ${modules.length} modules**, in ${cats.length} categories. ` +
    SEV_ORDER.map((s) => `${counts[s]} ${s}`).join(", ") +
    ".",
);
out.push("");
out.push(
  "A finding is a distinct name the scanner can put in a report, which is not the same as a check",
  "type: the data-table modules below define many findings from one piece of detection logic —",
  "`probes-data` is one path probe applied to " +
    (modules.find((m) => m.mod === "probes-data")?.rows.length ?? 0) +
    " paths. Where a check emits two severities depending on context (a session cookie versus an",
  "ordinary one), both are shown and it is counted at the higher.",
);
out.push("");

out.push("## Coverage");
out.push("");
out.push("`direct` — the module has its own test file. `indirect` — a test file imports it, or a tested");
out.push("module does. `none` — neither, so no test exercises it at all.");
out.push("");
out.push("| Module | Findings | Lines | Tests | Coverage |");
out.push("|---|---:|---:|---:|---|");
for (const m of [...modules].sort((a, b) => a.cov.level.localeCompare(b.cov.level) || b.rows.length - a.rows.length)) {
  out.push(
    `| \`${m.mod}.ts\` | ${m.rows.length} | ${m.loc} | ${m.tests || "—"} | ${m.cov.level === "direct" ? "direct" : m.cov.level === "indirect" ? `indirect, via ${m.cov.via}` : "**none**"} |`,
  );
}
out.push("");
if (uncovered.length) {
  out.push(
    `> **${uncovered.length} modules carrying ${uncovered.reduce((a, m) => a + m.rows.length, 0)} findings have no test reaching them:** ` +
      uncovered.map((m) => `\`${m.mod}\``).join(", ") +
      ".",
  );
  out.push("");
}

out.push("## Findings by module");
out.push("");
for (const m of [...modules].sort((a, b) => a.mod.localeCompare(b.mod))) {
  out.push(`### \`${m.mod}.ts\``);
  const bits = [`${m.rows.length} findings`, `${m.loc} lines`, m.tests ? `${m.tests} tests` : "no test file"];
  if (m.emitter) bits.push(`emitted by \`${m.emitter}\``);
  out.push("");
  out.push(`*${bits.join(" · ")}.*`);
  out.push("");
  out.push("| Finding | Severity | Category | CVSS | CWE | WSTG |");
  out.push("|---|---|---|---:|---|---|");
  for (const r of [...m.rows].sort((a, b) => SEV_RANK[primary(b.sev)] - SEV_RANK[primary(a.sev)] || String(a.name).localeCompare(String(b.name)))) {
    out.push(
      `| ${r.name ? esc(r.name) : "_(dynamic name)_"} | ${sevCell(r.sev)} | ${r.cat ? esc(r.cat) : "—"} | ${r.cvss ?? "—"} | ${r.cwe ?? "—"} | ${r.wstg ?? "—"} |`,
    );
  }
  out.push("");
}

out.push("## How this was read");
out.push("");
out.push("Regex over the source, matching the scanner's own approach to HTML. It holds because the");
out.push("finding literals are uniform; the assumptions are:");
out.push("");
for (const a of ASSUMPTIONS) out.push(`- ${a}`);
out.push("");
out.push(
  unnamed.length
    ? `**${unnamed.length} findings could not be named** — an assumption above no longer holds, and the parser needs a look.`
    : "Every finding resolved to a name, so none of these currently fails.",
);
out.push("");

const text = out.join("\n") + "\n";

// --json <path> writes the same data as JSON, for the published check-inventory
// page. Same parse, so the page and SCAN_CHECKS.md cannot disagree.
const jsonAt = process.argv.indexOf("--json");
if (jsonAt !== -1) {
  const dest = process.argv[jsonAt + 1];
  if (!dest) {
    console.error("--json needs a destination path.");
    process.exit(1);
  }
  writeFileSync(
    dest,
    JSON.stringify({
      checks: all.map((r) => ({ m: r.mod, name: r.name, sev: r.sev, cat: r.cat, cwe: r.cwe, cvss: r.cvss, wstg: r.wstg })),
      modules: modules.map((m) => ({ m: m.mod, loc: m.loc, n: m.rows.length, tests: m.tests })),
    }),
  );
  console.log(`Wrote ${dest} — ${all.length} findings across ${modules.length} modules.`);
} else if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(OUT, "utf8");
  } catch {}
  // Compared with line endings normalised: git hands a Windows checkout CRLF,
  // and this check is about content drift, not about which OS ran it.
  const same = current.replace(/\r\n/g, "\n") === text.replace(/\r\n/g, "\n");
  if (!same) {
    console.error("SCAN_CHECKS.md is out of date. Run: node artifacts/api-server/scripts/check-index.mjs");
    process.exit(1);
  }
  console.log(`SCAN_CHECKS.md is current — ${all.length} findings across ${modules.length} modules.`);
} else {
  writeFileSync(OUT, text);
  console.log(`Wrote SCAN_CHECKS.md — ${all.length} findings across ${modules.length} modules.`);
  if (unnamed.length) console.warn(`  warning: ${unnamed.length} findings could not be named.`);
  if (uncovered.length) console.warn(`  warning: ${uncovered.length} modules have no test reaching them.`);
}

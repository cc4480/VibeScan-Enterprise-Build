// What the finding index knows about the codebase: assumptions, central emitters, non-scanner modules,
// how split parts are matched to their module.

export const ASSUMPTIONS = [
  "A finding is an object literal carrying `severity:` with one of the five levels.",
  "Its name comes from `name:` in the same literal, or in a constant it spreads (`...NOTE`) — or `header:`, for the header-gap table whose names are composed at the emit site.",
  "A ternary severity or name means the check emits two variants (session vs non-session cookies, for example).",
];

/**
 * Modules that define check *templates* in a data table, where the sibling
 * module that emits them assigns category and CWE centrally. Without this the
 * index would report 19 subdomain-takeover services as missing a CWE, when
 * subdomainTakeover.ts stamps CWE-350 on every one of them.
 */
export const CENTRAL = {
  "secret-pattern-data": { cat: "Exposed Secrets / Credentials", emitter: "jsScanner.ts" },
  "secret-pattern-vendors": { cat: "Exposed Secrets / Credentials", emitter: "jsScanner.ts" },
  "secret-pattern-generic": { cat: "Exposed Secrets / Credentials", emitter: "jsScanner.ts" },
  "subdomain-service-data": { cat: "DNS Security", cwe: "CWE-350", emitter: "subdomainTakeover.ts" },
  "recon-data": { cat: "Exposed Service", emitter: "recon.ts" },
  nextjsProbe: { cat: "Secret Exposed in Page HTML", emitter: "nextjsProbe.ts" },
};

/**
 * A module and the parts split out of it for size (foo.ts, fooBar.ts, foo-bar.ts) count as one:
 * the exclusions and central-emitter entries below are named for the module, not for each part.
 */
export const isPartOf = (f, modules) =>
  [...modules].some((m) => {
    const base = m.replace(/\.ts$/, "");
    return f === m || (f.startsWith(base) && /^[A-Z-]/.test(f.slice(base.length)) && !f.endsWith(".test.ts"));
  });
export const file = (mod) => `${mod}.ts`;

/**
 * Modules that carry `severity:` for something that is NOT a scan finding.
 *
 * The rule this script works by — "an object literal with severity: is a
 * finding" — is a good heuristic for probe modules and wrong for anything else
 * that happens to rank things by severity. monitorPulse.ts classifies
 * notification alerts (a removed header, an HSTS downgrade); those never appear
 * in a report, and counting them inflated the published total from 284 to 288.
 *
 * The number in this file's header is a claim on secscan.info about what the
 * scanner detects, so a module belongs here the moment its severities describe
 * alerts, preferences or scheduling rather than findings in a report.
 */
export const NOT_A_SCANNER = new Set([
  "monitorPulse.ts",
]);

export const PART_ALIASES = {
  "secret-pattern-vendors": "secret-pattern-data",
  "secret-pattern-generic": "secret-pattern-data",
  "secret-pattern-filters": "secret-pattern-data",
};

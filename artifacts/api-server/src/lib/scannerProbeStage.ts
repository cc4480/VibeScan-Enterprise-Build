import { vuln, type ScanVulnerability } from "./scannerTypes";
import { withoutRepeatedServiceRole } from "./supabase-probes-report";
import { runAllProbes } from "./probes";
import { TestLedger, NOT_VERIFIED, foundNames, type ProbeOutcome } from "./testLedger";
import { checkDnsSecurity } from "./dnsChecks";
import { scanJavaScriptForSecrets, collectFirstPartyJavaScript } from "./jsScanner";
import { parseGithubRepoRef, githubProbeOutcome } from "./githubSourceProbe";
import { scanRepository } from "./repoScan";
import { progressRecord } from "./repoProgress";
import { publicGithubSource, githubInstallationSource } from "./repoSource";
import { crawlAndCheck } from "./crawler";
import { checkForKnownVulnerabilities } from "./cveCheck";
import { analyzeJwts } from "./jwtAnalysis";
import { checkSubdomainTakeover } from "./subdomainTakeover";
import { checkPathTraversal } from "./pathTraversal";
import { runInjectionProbes } from "./injectionProbe";
import { priceTamperingFindings } from "./priceTamperingProbe";
import { checkSourceMaps } from "./sourceMaps";
import { checkVibeStackSecurity } from "./vibeStackProbes";
import { runBaasProbes } from "./baasProbes";
import { runGraphqlProbe } from "./graphqlProbe";
import { runApiDocsProbe } from "./apiDocsProbe";
import { runHealthEndpointProbe } from "./healthEndpointProbe";
import { runNextjsProbe } from "./nextjsProbe";
import { runStorageProbe } from "./storageProbe";

/** Everything the passive probe families and the crawl need from the first response. */
export interface ProbeStageInput {
  finalUrl: string;
  html: string;
  rawHeaders: Record<string, string>;
  setCookies: string[];
  status: number;
  tier: string;
  allowActiveProbes: boolean;
  /** The scan has a signed-in test account. Checkout and order flows are normally behind sign-in, so business-logic probes need it. */
  signedIn?: boolean;
  githubRepoUrl?: string;
  /**
   * A GitHub App installation token for the repository, when the owner connected it (githubApp.ts). Held in memory for
   * this scan only; with none, only a public repository can be read.
   */
  githubAccessToken?: string;
  ledger: TestLedger;
  crawlPageBudget: number;
  /** What the user asked to scan, before any redirect. */
  requestedUrl?: string;
  /**
   * The first response exactly as the server sent it, before any browser rendering. The checks about
   * assets the site owner controls (subresource integrity, source maps) read this: the rendered page
   * also lists scripts injected at run time by tag loaders, and the source maps of the third-party
   * code they pull in, neither of which the owner wrote or can fix. Defaults to `html`.
   */
  authoredHtml?: string;
}

/**
 * Runs the site crawl and every named probe family concurrently, and reports
 * which of them could not complete (see the notes on unrunFamilies below).
 */
export async function runProbeStage({
  finalUrl, html, rawHeaders, setCookies, status, tier, allowActiveProbes, signedIn, githubRepoUrl, githubAccessToken, ledger, crawlPageBudget, requestedUrl,
  authoredHtml,
}: ProbeStageInput) {
  const vulnerabilities: ScanVulnerability[] = [];
  const crawlStarted = Date.now();

  // Run crawl separately to capture pagesVisited alongside findings
  const crawlPromise = crawlAndCheck(
    finalUrl, html, rawHeaders, setCookies, crawlPageBudget,
  )
    .then((r) => {
      ledger.records.push({
        group: "crawl", name: `site crawl (${r.pagesVisited.length} inner pages)`, status: "ran",
        findings: r.vulnerabilities.length, durationMs: Date.now() - crawlStarted,
        ...(r.vulnerabilities.length > 0 ? { found: foundNames(r.vulnerabilities) } : {}),
      });
      return { ...r, failed: false };
    })
    .catch((err: unknown) => {
      ledger.records.push({
        group: "crawl", name: "site crawl", status: "failed", findings: 0, durationMs: Date.now() - crawlStarted,
        reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
      });
      // Same reasoning as the probe families below: a crawl that died is not a
      // site without inner pages, and the report has to be able to tell them
      // apart.
      console.error("[scan] site crawl failed", err);
      return { vulnerabilities: [], pagesVisited: [], probedNotFound: [], failed: true };
    });

  // Each family is named, and its failure is NOT swallowed here.
  //
  // Every entry used to carry its own `.catch(() => [])`, which meant
  // Promise.allSettled never saw a rejection: a probe family that crashed
  // returned an empty array and was indistinguishable, in the report and in the
  // grade, from one that ran and found nothing. Seventeen families, seventeen
  // ways for a scan to look clean because it broke.
  //
  // Failures are collected and reported once, below, as a Scan Coverage finding.
  // That is deliberately not a vulnerability finding: a probe that could not run
  // is not evidence of a weakness, and inventing one would be the false positive
  // this exists to avoid. It says only "this was not checked", which is the one
  // thing the old behaviour could never say.
  // runAllProbes bundles thirteen checks behind one promise and filters its own
  // rejections, so a single failed check inside it would not surface as a
  // failure of the family. It reports them individually through this callback.
  const innerProbeFailures: string[] = [];

  // A probe that can tell "nothing here to test" from "tested, found nothing" says which, so the
  // report shows "not tested: <why>" instead of "ran, 0 findings" for a check that had no subject.
  const outcome = (family: string, group: "passive" | "active", start: (notTested: (reason: string) => void) => Promise<ScanVulnerability[]>) => {
    let reason: string | undefined;
    const run: Promise<ProbeOutcome> = start((r) => { reason = r; }).then((findings) => ({ findings, ...(reason ? { notTested: reason } : {}) }));
    return { family, tracked: true, run: ledger.trackOutcome(group, family, run) };
  };

  // The site's own JavaScript, fetched once and shared. The checks that look for a backend (Supabase,
  // Firebase, PocketBase, Appwrite, cloud buckets) need its address, keys and bucket names, and a
  // production build keeps those in the bundle, not in the page: an app shipped as an empty shell and one
  // script has nothing for them to read in the HTML. Only the active checks use it, so a passive scan
  // does not fetch anything extra; the secret scanner below reads the same scripts through the shared
  // per-scan cache.
  const siteCode: Promise<string> = allowActiveProbes
    ? collectFirstPartyJavaScript(html, finalUrl).catch(() => "")
    : Promise.resolve("");
  const withSiteCode = async () => `${html}\n${await siteCode}`;
  // Started here, not where it is listed below, because the Supabase check reads its result to avoid reporting
  // a leaked service_role key a second time.
  const secretScan = scanJavaScriptForSecrets(html, finalUrl);

  const namedProbes: Array<{ family: string; run: Promise<ScanVulnerability[]>; tracked?: boolean }> = [
    {
      family: "HTTP probes (headers, files, methods, CORS)",
      run: runAllProbes(finalUrl, html, allowActiveProbes, (checkName, reason) => {
        innerProbeFailures.push(checkName);
        console.error(`[scan] check failed: ${checkName}`, reason);
      }, ledger, requestedUrl, authoredHtml, siteCode),
    },
    { family: "DNS and email authentication", run: checkDnsSecurity(finalUrl) },
    // Mail transport security: does the domain's MX actually offer STARTTLS,
    // and is its certificate valid. Invisible from the web tier — a site can
    // score perfectly on HTTPS while password-reset mail is relayed in
    // cleartext. SPF/DMARC say who MAY send; they say nothing about encryption.
    {
      family: "mail transport security (STARTTLS, MX certificate)",
      run: (async () => {
        const { hostname } = new URL(finalUrl);
        const { inspectMailTls, mailTlsFindings } = await import("./mailTls.js");
        return mailTlsFindings(await inspectMailTls(hostname));
      })(),
    },
    // Structured data, social preview metadata and indexability. No network
    // calls — it reads the document already fetched. Presentation findings are
    // INFO (weight 0) so they cannot move the security grade; only genuine
    // exposure (internal hosts, http assets, foreign canonical) carries weight.
    {
      family: "structured data and social metadata",
      run: (async () => {
        const { structuredDataFindings } = await import("./structuredData.js");
        return structuredDataFindings(finalUrl, html, { status: status, headers: rawHeaders });
      })(),
    },
    { family: "known-CVE and end-of-life versions", run: checkForKnownVulnerabilities(html, rawHeaders) },
    // Passive JWT analysis — no extra HTTP requests
    outcome("JWT analysis", "passive", (nt) => analyzeJwts(rawHeaders, html, nt)),
    // Subdomain takeover — 1-2 DNS + HTTP checks
    { family: "subdomain takeover", run: checkSubdomainTakeover(finalUrl) },
    // Source map exposure — checks JS bundles for .map files
    outcome("source map exposure", "passive", (nt) => checkSourceMaps(authoredHtml ?? html, finalUrl, nt)),
    // Exposed API docs: Swagger/OpenAPI/ReDoc — fetching published doc paths
    { family: "exposed API documentation", run: runApiDocsProbe(finalUrl) },
    { family: "health endpoint disclosure", run: runHealthEndpointProbe(finalUrl) },
    // Next.js __NEXT_DATA__ prop leaks — read from the page already fetched
    outcome("Next.js __NEXT_DATA__ secrets", "passive", (nt) => runNextjsProbe(finalUrl, html, nt)),
  ];

  // Everything below reads data out of a backend the target owns, or fuzzes an
  // endpoint to see what it admits to. That is testing, not visiting.
  const activeFamilies = [
    "Supabase RLS and Firebase rules",
    "BaaS open data (PocketBase, Appwrite)",
    "GraphQL introspection",
    "public cloud storage buckets",
    "dependency CVEs from an exposed manifest",
    "path traversal",
    "injection (XSS, SQLi)",
    "business logic: checkout price",
  ];
  if (!allowActiveProbes) {
    for (const family of activeFamilies) ledger.skip("active", family, NOT_VERIFIED);
  }
  if (allowActiveProbes) {
    namedProbes.push(
      // Vibe-stack database security — Supabase RLS + Firebase rules (both tiers)
      outcome("Supabase RLS and Firebase rules", "active", async (nt) => {
        const found = await checkVibeStackSecurity(await withSiteCode(), finalUrl, tier, nt);
        return withoutRepeatedServiceRole(found, await secretScan.catch(() => []));
      }),
      // BaaS open-data checks not covered above: PocketBase, Appwrite
      outcome("BaaS open data (PocketBase, Appwrite)", "active", async (nt) => runBaasProbes(finalUrl, await withSiteCode(), nt)),
      // GraphQL introspection + field suggestions
      { family: "GraphQL introspection", run: runGraphqlProbe(finalUrl, html) },
      // Public cloud storage listing: S3, GCS, Azure Blob
      outcome("public cloud storage buckets", "active", async (nt) => runStorageProbe(finalUrl, await withSiteCode(), nt)),
      // Real SCA, when the target publishes its own manifest. The path probe
      // already reports that /package.json is exposed; this reads the
      // dependency tree inside it and matches it against OSV, which is the
      // thing that finding tells the customer an attacker would do.
      outcome("dependency CVEs from an exposed manifest", "active", async (nt) => {
        const { scaFromExposedManifest } = await import("./manifestSca.js");
        return scaFromExposedManifest(new URL(finalUrl).origin, nt);
      }),
    );
  }

  namedProbes.push({ family: "JavaScript secret scanning", run: secretScan });

  // Optional source-code scan of a public GitHub repository the user
  // supplied for this scan — see githubSourceProbe.ts. Independent of
  // allowActiveProbes: this never sends a request to the scan target at all,
  // only to GitHub's own public API, so it carries none of the risk that
  // gate exists to control.
  if (githubRepoUrl) {
    const repoRef = parseGithubRepoRef(githubRepoUrl);
    if (repoRef) {
      namedProbes.push({
        family: "GitHub source code secrets",
        // Recorded here, through trackOutcome, so a private or missing repository reads as "not
        // tested" (see githubProbeOutcome) while a GitHub outage or rate limit still throws and is
        // recorded as failed, instead of either reading as a clean "nothing found".
        tracked: true,
        run: ledger.trackOutcome("passive", "GitHub source code secrets", scanRepository(githubAccessToken ? githubInstallationSource(repoRef, githubAccessToken) : publicGithubSource(repoRef), repoRef, { onProgress: (e) => ledger.progress(progressRecord(e)) }).then((o) => githubProbeOutcome(o, repoRef))),
      });
    } else {
      ledger.skip("passive", "GitHub source code secrets", "the supplied value was not a recognisable GitHub repository");
    }
  } else {
    ledger.skip("passive", "GitHub source code secrets", "no repository was supplied for this scan");
  }

  if (allowActiveProbes) {
    namedProbes.push(
      // Active path traversal probing — multiple HTTP requests
      { family: "path traversal", run: checkPathTraversal(finalUrl, html) },
      // A03 Injection — reflected XSS + error-based SQLi active probing
      { family: "injection (XSS, SQLi)", run: runInjectionProbes(finalUrl, html) },
    );
    // Business logic: a checkout that bills the client's price. The checkout sits behind sign-in, so it needs the test account.
    if (signedIn) {
      namedProbes.push({ family: "business logic: checkout price", run: priceTamperingFindings(new URL(finalUrl).origin) });
    } else {
      ledger.skip("active", "business logic: checkout price", "no signed-in test account was supplied for this scan");
    }
  }

  const [crawlResult, ...probeResults] = await Promise.all([
    crawlPromise,
    Promise.allSettled(
      namedProbes.map((p) =>
        // The HTTP probes bundle records its thirteen checks one by one inside
        // runAllProbes; recording the bundle too would count them twice.
        p.family.startsWith("HTTP probes") || p.tracked
          ? p.run
          : ledger.track(activeFamilies.includes(p.family) ? "active" : "passive", p.family, p.run),
      ),
    ),
  ]);

  vulnerabilities.push(...crawlResult.vulnerabilities);

  // Families that threw rather than answering. Named, so the coverage note
  // below can say which — "something failed" is not useful to anyone.
  const unrunFamilies: string[] = [];
  const settledProbes = probeResults[0] as PromiseSettledResult<ScanVulnerability[]>[];
  settledProbes.forEach((result, i) => {
    if (result.status === "fulfilled") {
      vulnerabilities.push(...result.value);
      return;
    }
    const family = namedProbes[i]?.family ?? `probe #${i}`;
    unrunFamilies.push(family);
    console.error(`[scan] probe family failed: ${family}`, result.reason);
  });

  if (crawlResult.failed) unrunFamilies.push("site crawl (inner pages)");
  // Individual checks from inside runAllProbes, already logged as they failed.
  unrunFamilies.push(...innerProbeFailures);

  return { crawlResult, vulnerabilities, unrunFamilies };
}

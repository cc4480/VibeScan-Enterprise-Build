/**
 * Data module: subdomain takeover fingerprints for known cloud services.
 * Extracted from subdomainTakeover.ts to reduce that file's line count.
 */

import type { ScanVulnerability } from "./scanner";

export interface ServiceFingerprint {
  name: string;
  cnamePattern: RegExp;
  /**
   * Patterns in the HTTP body that confirm the resource is unclaimed. Each must be
   * the provider's own unclaimed-resource message: a generic "404", a bare product
   * name or marketing-style copy also appears on live, claimed sites. The check
   * additionally requires an error status (>= 400) and a small page.
   */
  bodyFingerprints: RegExp[];
  /**
   * True when the provider's unclaimed page is indistinguishable from a claimed
   * site's own default 404 (Netlify's "Not Found - Request ID", Fly's bare
   * "404 Not Found"). Reported as an unverified, low-confidence candidate.
   */
  ambiguous?: boolean;
  severity: ScanVulnerability["severity"];
  cvssScore: number;
}

export const SERVICES: ServiceFingerprint[] = [
  {
    name: "AWS S3",
    cnamePattern: /\.s3(?:-website(?:-[a-z0-9-]+)?)?\.amazonaws\.com$/i,
    bodyFingerprints: [/NoSuchBucket|The specified bucket does not exist/i],
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Heroku",
    cnamePattern: /\.herokuapp\.com$|\.herokudns\.com$/i,
    bodyFingerprints: [/No such app|there is no app configured at that hostname/i],
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "GitHub Pages",
    cnamePattern: /\.github\.io$/i,
    bodyFingerprints: [/There isn.t a GitHub Pages site here|404 There is no GitHub Pages site/i],
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Netlify",
    cnamePattern: /\.netlify\.app$|\.netlify\.com$/i,
    bodyFingerprints: [/^\s*Not Found - Request ID: [\w-]+\s*$/i],
    ambiguous: true,
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Vercel",
    cnamePattern: /\.vercel\.app$/i,
    bodyFingerprints: [/The deployment could not be found on Vercel|DEPLOYMENT_NOT_FOUND/i],
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Azure App Service",
    cnamePattern: /\.azurewebsites\.net$|\.cloudapp\.azure\.com$|\.cloudapp\.net$/i,
    bodyFingerprints: [/404 Web Site not found/i],
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Fastly",
    cnamePattern: /\.fastly\.net$/i,
    bodyFingerprints: [/Fastly error: unknown domain|Please check that this domain has been added/i],
    // can-i-take-over-xyz lists Fastly as "Not vulnerable" (a service must prove
    // it owns the domain), so this page alone is a candidate, not a takeover.
    ambiguous: true,
    severity: "critical",
    cvssScore: 9.1,
  },
  {
    name: "Shopify",
    cnamePattern: /\.myshopify\.com$|shops\.myshopify\.com$/i,
    bodyFingerprints: [/Sorry, this shop is currently unavailable/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Ghost Pro",
    cnamePattern: /\.ghost\.io$/i,
    bodyFingerprints: [/The thing you were looking for is no longer here, or never was|Site unavailable\.|Failed to resolve DNS path for this host/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Surge.sh",
    cnamePattern: /\.surge\.sh$/i,
    bodyFingerprints: [/project not found/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Cargo",
    cnamePattern: /\.cargocollective\.com$/i,
    bodyFingerprints: [/If you.re moving your domain away from Cargo/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Readme.io",
    cnamePattern: /\.readme\.io$|\.readmessl\.com$/i,
    bodyFingerprints: [/Project doesnt exist|The creators of this project are still working on making everything perfect/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Pantheon",
    cnamePattern: /\.pantheonsite\.io$/i,
    bodyFingerprints: [/404 error unknown site|The gods are wise/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Squarespace",
    cnamePattern: /\.squarespace\.com$/i,
    bodyFingerprints: [/No Such Account|you may have followed a broken link/i],
    // Listed "Not vulnerable" in can-i-take-over-xyz.
    ambiguous: true,
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Tumblr",
    cnamePattern: /\.tumblr\.com$/i,
    bodyFingerprints: [/Whatever you were looking for doesn.t currently exist at this address/i],
    severity: "medium",
    cvssScore: 6.5,
  },
  {
    name: "WP Engine",
    cnamePattern: /\.wpengine\.com$/i,
    bodyFingerprints: [/The site you were looking for couldn.t be found/i],
    // Listed "Not vulnerable" in can-i-take-over-xyz.
    ambiguous: true,
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Fly.io",
    cnamePattern: /\.fly\.dev$/i,
    bodyFingerprints: [/^\s*404 Not Found\s*$/i],
    ambiguous: true,
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Render",
    cnamePattern: /\.onrender\.com$/i,
    bodyFingerprints: [/There is no site here|Did you mean to access/i],
    severity: "high",
    cvssScore: 8.1,
  },
  {
    name: "Railway",
    cnamePattern: /\.up\.railway\.app$/i,
    bodyFingerprints: [/Application not found|No deployment found/i],
    severity: "high",
    cvssScore: 8.1,
  },
];

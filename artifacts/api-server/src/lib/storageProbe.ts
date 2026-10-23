/**
 * Public object storage listing probe.
 *
 * Detects S3, GCS, and Azure Blob references in page HTML/JS, then performs
 * read-only list requests to check for public bucket listing.
 *
 * Publicly listable buckets expose the full contents of a storage container —
 * a classic data exposure vector, especially common in AI-scaffolded infra.
 *
 * Design: read-only GET requests to known storage listing endpoints only.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";
import { storageProbeOrigin } from "./baasEndpoints";
import { bucketLooksOwned, judgeBucket, listedKeys } from "./storageOwnership";
import { extractS3Buckets, extractGcsBuckets, type AzureBlob, extractAzureBlobs } from "./storageProbeExtract";

const TIMEOUT_MS = 8_000;
/** Enough keys to tell an asset bucket from one with a dump in it. */
const SAMPLE_KEYS = 100;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(url: string): Promise<{ status: number; body: string; ct: string } | null> {
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS });
  if (!res) return null;
  return { status: res.status, body: res.body, ct: res.headers["content-type"] ?? "" };
}

// ─────────────────────────────────────────────────────────────────────────────
// LISTING CHECKS
// ─────────────────────────────────────────────────────────────────────────────

function isS3ListingResponse(body: string): boolean {
  return (
    body.includes("<ListBucketResult") ||
    body.includes("<Contents>") ||
    body.includes("<CommonPrefixes>")
  );
}

function isGcsListingResponse(body: string, ct: string): boolean {
  if (ct.includes("application/json")) {
    return /"kind"\s*:\s*"storage#objects"/.test(body) || /"items"\s*:/.test(body);
  }
  return body.includes("<ListBucketResult") || body.includes("<Contents>");
}

function isAzureListingResponse(body: string): boolean {
  return (
    body.includes("<EnumerationResults") ||
    body.includes("<Blobs>") ||
    body.includes("<Blob>")
  );
}

function countItems(body: string): number {
  // S3/GCS XML
  const contentsMatches = body.match(/<Contents>/g);
  if (contentsMatches) return contentsMatches.length;
  // GCS JSON
  try {
    const j = JSON.parse(body) as { items?: unknown[] };
    if (Array.isArray(j.items)) return j.items.length;
  } catch { /* skip */ }
  // Azure XML
  const blobMatches = body.match(/<Blob>/g);
  if (blobMatches) return blobMatches.length;
  return 0;
}

/**
 * One finding builder for all three providers. A referenced bucket is only
 * filed against the customer at HIGH when its name ties it to the site; a
 * bucket holding only static assets is INFO whoever owns it, and a public
 * bucket with no tie to the site is a hedged LOW.
 */
function bucketFinding(
  provider: string,
  label: string,
  ownerKey: string,
  targetHost: string,
  body: string,
  base: { evidence: string; solution: string },
): ScanVulnerability {
  const keys = listedKeys(body);
  const count = keys.length || countItems(body);
  const verdict = judgeBucket(keys, bucketLooksOwned(ownerKey, targetHost));
  const sample = `${count} object(s) in the first listing page`;
  const common = {
    category: "Cloud Storage Misconfiguration",
    cweId: "CWE-552",
    evidence: `${base.evidence}\n${sample}`,
    solution: base.solution,
  };
  if (verdict === "static-assets") {
    return vuln({
      ...common,
      name: `Public ${provider} Listing of Static Assets — '${label}'`,
      severity: "info",
      cweId: null,
      description:
        `The ${provider} bucket '${label}' referenced by this page is publicly listable, but the ` +
        `listed objects (${sample}) are all static web assets (images, stylesheets, scripts, fonts, media), ` +
        `which is the normal shape of a public asset bucket. Listing still reveals file names; ` +
        `check that nothing else is stored here and that listing is not needed.`,
      cvssScore: 0,
      confidence: 60,
    });
  }
  if (verdict === "unowned") {
    return vuln({
      ...common,
      name: `Public ${provider} Bucket Referenced by This Page — '${label}'`,
      severity: "low",
      description:
        `A publicly listable ${provider} bucket '${label}' is referenced by this page (${sample}). Its name ` +
        `does not tie it to this site, so it may belong to a third party (a vendor, a public dataset) rather ` +
        `than to you. Verify who owns it; if it is yours, treat it as an exposed bucket and lock down listing.`,
      cvssScore: 3.7,
      confidence: 50,
    });
  }
  const ownedDescription =
    `The ${provider} bucket/container '${label}', whose name matches this site, is publicly listable — anyone can enumerate its ` +
    `contents without authentication (${sample}). Listing reveals every file name and exposes ` +
    `the data inventory even where individual objects need auth.`;
  // Three literal names, one per provider: the check index and the catalog read the names from source.
  // Listing observed; ownership inferred from the name.
  if (provider === "S3") {
    return vuln({ ...common, name: `Public S3 Bucket Listing — '${label}'`, severity: "high", description: ownedDescription, cvssScore: 7.5, confidence: 90 });
  }
  if (provider === "GCS") {
    return vuln({ ...common, name: `Public GCS Bucket Listing — '${label}'`, severity: "high", description: ownedDescription, cvssScore: 7.5, confidence: 90 });
  }
  return vuln({ ...common, name: `Public Azure Blob Container Listing — '${label}'`, severity: "high", description: ownedDescription, cvssScore: 7.5, confidence: 90 });
}

async function checkS3Bucket(bucket: string, host: string): Promise<ScanVulnerability | null> {
  // Try virtual-hosted style (current AWS recommendation)
  const via = storageProbeOrigin();
  const urls = via
    ? [`${via}/s3/${bucket}/?list-type=2&max-keys=${SAMPLE_KEYS}`]
    : [
        `https://${bucket}.s3.amazonaws.com/?list-type=2&max-keys=${SAMPLE_KEYS}`,
        `https://s3.amazonaws.com/${bucket}/?list-type=2&max-keys=${SAMPLE_KEYS}`,
      ];

  for (const url of urls) {
    const r = await safeGet(url);
    if (!r || r.status !== 200) continue;
    if (!isS3ListingResponse(r.body)) continue;

    return bucketFinding("S3", bucket, bucket, host, r.body, {
      evidence: `GET ${url}\nHTTP 200 — S3 ListBucketResult returned`,
      solution:
        "In the AWS S3 Console: select the bucket → Permissions → Block Public Access → " +
        "enable all four 'Block public access' settings. Also review the Bucket Policy and " +
        "ACL to remove any `Principal: \"*\"` with `s3:ListBucket` or `s3:GetObject` actions. " +
        "Use pre-signed URLs or CloudFront with OAC for serving public assets.",
    });
  }
  return null;
}

async function checkGcsBucket(bucket: string, host: string): Promise<ScanVulnerability | null> {
  const via = storageProbeOrigin();
  const urls = via
    ? [`${via}/gcs/${bucket}?maxResults=${SAMPLE_KEYS}`]
    : [
        `https://storage.googleapis.com/${bucket}?maxResults=${SAMPLE_KEYS}`,
        `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=${SAMPLE_KEYS}`,
      ];

  for (const url of urls) {
    const r = await safeGet(url);
    if (!r || r.status !== 200) continue;
    if (!isGcsListingResponse(r.body, r.ct)) continue;

    return bucketFinding("GCS", bucket, bucket, host, r.body, {
      evidence: `GET ${url}\nHTTP 200 — GCS listing confirmed`,
      solution:
        "In the GCS Console: select the bucket → Permissions → remove the 'allUsers' and " +
        "'allAuthenticatedUsers' principal entries. Enable 'Uniform bucket-level access' and " +
        "use IAM policies instead of per-object ACLs. For public assets, use a CDN or Cloud " +
        "Storage with signed URLs.",
    });
  }
  return null;
}

async function checkAzureBlob(blob: AzureBlob, host: string): Promise<ScanVulnerability | null> {
  // Azure requires ?restype=container&comp=list for listing
  const via = storageProbeOrigin();
  const base = via ? `${via}/azure/${blob.account}` : `https://${blob.account}.blob.core.windows.net`;
  const url = `${base}/${blob.container}?restype=container&comp=list&maxresults=${SAMPLE_KEYS}`;
  const r = await safeGet(url);
  if (!r || r.status !== 200) return null;
  if (!isAzureListingResponse(r.body)) return null;

  return bucketFinding(
    "Azure Blob",
    `${blob.account}/${blob.container}`,
    blob.account,
    host,
    r.body,
    {
      evidence: `GET ${url}\nHTTP 200 — Azure EnumerationResults confirmed`,
      solution:
        "In the Azure Portal: Storage Account → Containers → select the container → Change " +
        "access level from 'Container (anonymous read access for containers and blobs)' to " +
        "'Private (no anonymous access)'. Also review the storage account's 'Allow Blob public " +
        "access' setting and disable it at the account level.",
    },
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runStorageProbe(
  targetUrl: string,
  html: string,
  /** Told why, when there was nothing here to test (recorded as "not tested", not "ran"). */
  notTested?: (reason: string) => void,
): Promise<ScanVulnerability[]> {
  let host: string;
  try { host = new URL(targetUrl).hostname; } catch { return []; }
  // Build search corpus: HTML + inline scripts
  const inlineRx = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const parts: string[] = [html];
  let m: RegExpExecArray | null;
  while ((m = inlineRx.exec(html)) !== null) {
    if (!/\bsrc\s*=/i.test(m[0])) parts.push(m[1] ?? "");
  }
  const content = parts.join("\n");

  const s3Buckets = extractS3Buckets(content);
  const gcsBuckets = extractGcsBuckets(content);
  const azureBlobs = extractAzureBlobs(content);

  if (s3Buckets.length === 0 && gcsBuckets.length === 0 && azureBlobs.length === 0) {
    notTested?.("no S3, Google Cloud Storage or Azure Blob bucket is referenced in the page or its JavaScript");
    return [];
  }

  const tasks: Promise<ScanVulnerability | null>[] = [
    ...s3Buckets.map((b) => checkS3Bucket(b, host).catch(() => null)),
    ...gcsBuckets.map((b) => checkGcsBucket(b, host).catch(() => null)),
    ...azureBlobs.map((b) => checkAzureBlob(b, host).catch(() => null)),
  ];

  const settled = await Promise.allSettled(tasks);
  return settled
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => v !== null);
}
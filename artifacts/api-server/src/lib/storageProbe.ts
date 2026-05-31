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

const TIMEOUT_MS = 8_000;
const MAX_BUCKETS_PER_PROVIDER = 5;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(url: string): Promise<{ status: number; body: string; ct: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 Seclayer Security Scanner" },
    });
    const body = await res.text().catch(() => "");
    const ct = res.headers.get("content-type") ?? "";
    return { status: res.status, body, ct };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

function extractS3Buckets(content: string): string[] {
  const buckets = new Set<string>();

  // Path-style: https://s3.amazonaws.com/<bucket>
  const pathStyle = /https?:\/\/s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9\-_.]{2,62})/gi;
  let m: RegExpExecArray | null;
  while ((m = pathStyle.exec(content)) !== null) buckets.add(m[1]);

  // Virtual-hosted: https://<bucket>.s3.amazonaws.com or <bucket>.s3.<region>.amazonaws.com
  const vHosted = /https?:\/\/([a-z0-9][a-z0-9\-_.]{2,62})\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/gi;
  while ((m = vHosted.exec(content)) !== null) buckets.add(m[1]);

  return [...buckets].slice(0, MAX_BUCKETS_PER_PROVIDER);
}

function extractGcsBuckets(content: string): string[] {
  const buckets = new Set<string>();

  // storage.googleapis.com/<bucket>
  const pathGcs = /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])/gi;
  let m: RegExpExecArray | null;
  while ((m = pathGcs.exec(content)) !== null) buckets.add(m[1]);

  // <bucket>.storage.googleapis.com
  const vGcs = /https?:\/\/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.storage\.googleapis\.com/gi;
  while ((m = vGcs.exec(content)) !== null) buckets.add(m[1]);

  return [...buckets].slice(0, MAX_BUCKETS_PER_PROVIDER);
}

interface AzureBlob {
  account: string;
  container: string;
}

function extractAzureBlobs(content: string): AzureBlob[] {
  const found = new Map<string, AzureBlob>();

  const rx = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9][a-z0-9\-]{1,62})/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(content)) !== null) {
    const key = `${m[1]}/${m[2]}`;
    found.set(key, { account: m[1], container: m[2] });
  }

  return [...found.values()].slice(0, MAX_BUCKETS_PER_PROVIDER);
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

async function checkS3Bucket(bucket: string): Promise<ScanVulnerability | null> {
  // Try virtual-hosted style (current AWS recommendation)
  const urls = [
    `https://${bucket}.s3.amazonaws.com/?list-type=2&max-keys=5`,
    `https://s3.amazonaws.com/${bucket}/?list-type=2&max-keys=5`,
  ];

  for (const url of urls) {
    const r = await safeGet(url);
    if (!r || r.status !== 200) continue;
    if (!isS3ListingResponse(r.body)) continue;

    const count = countItems(r.body);
    return vuln({
      name: `Public S3 Bucket Listing — '${bucket}'`,
      severity: "high",
      category: "Cloud Storage Misconfiguration",
      description:
        `The Amazon S3 bucket '${bucket}' is publicly listable — anyone can enumerate its ` +
        `full contents without authentication. ` +
        (count > 0
          ? `${count} object(s) were listed in this probe.`
          : "The bucket directory listing was confirmed.") +
        " Even if objects have individual auth, listing reveals all filenames and exposes " +
        "the full data inventory to attackers.",
      evidence: `GET ${url}\nHTTP 200 — S3 ListBucketResult returned${count > 0 ? ` (${count} items)` : ""}`,
      solution:
        "In the AWS S3 Console: select the bucket → Permissions → Block Public Access → " +
        "enable all four 'Block public access' settings. Also review the Bucket Policy and " +
        "ACL to remove any `Principal: \"*\"` with `s3:ListBucket` or `s3:GetObject` actions. " +
        "Use pre-signed URLs or CloudFront with OAC for serving public assets.",
      cweId: "CWE-552",
      cvssScore: 7.5,
      confidence: 95,
    });
  }
  return null;
}

async function checkGcsBucket(bucket: string): Promise<ScanVulnerability | null> {
  const urls = [
    `https://storage.googleapis.com/${bucket}?maxResults=5`,
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=5`,
  ];

  for (const url of urls) {
    const r = await safeGet(url);
    if (!r || r.status !== 200) continue;
    if (!isGcsListingResponse(r.body, r.ct)) continue;

    const count = countItems(r.body);
    return vuln({
      name: `Public GCS Bucket Listing — '${bucket}'`,
      severity: "high",
      category: "Cloud Storage Misconfiguration",
      description:
        `The Google Cloud Storage bucket '${bucket}' is publicly listable. Anyone can ` +
        `enumerate all objects in the bucket without credentials. ` +
        (count > 0 ? `${count} object(s) were listed.` : ""),
      evidence: `GET ${url}\nHTTP 200 — GCS listing confirmed${count > 0 ? ` (${count} items)` : ""}`,
      solution:
        "In the GCS Console: select the bucket → Permissions → remove the 'allUsers' and " +
        "'allAuthenticatedUsers' principal entries. Enable 'Uniform bucket-level access' and " +
        "use IAM policies instead of per-object ACLs. For public assets, use a CDN or Cloud " +
        "Storage with signed URLs.",
      cweId: "CWE-552",
      cvssScore: 7.5,
      confidence: 95,
    });
  }
  return null;
}

async function checkAzureBlob(blob: AzureBlob): Promise<ScanVulnerability | null> {
  // Azure requires ?restype=container&comp=list for listing
  const url = `https://${blob.account}.blob.core.windows.net/${blob.container}?restype=container&comp=list&maxresults=5`;
  const r = await safeGet(url);
  if (!r || r.status !== 200) return null;
  if (!isAzureListingResponse(r.body)) return null;

  const count = countItems(r.body);
  return vuln({
    name: `Public Azure Blob Container Listing — '${blob.account}/${blob.container}'`,
    severity: "high",
    category: "Cloud Storage Misconfiguration",
    description:
      `The Azure Blob Storage container '${blob.container}' in account '${blob.account}' ` +
      `is publicly listable. Unauthenticated list requests reveal all blob names. ` +
      (count > 0 ? `${count} blob(s) were listed.` : ""),
    evidence: `GET ${url}\nHTTP 200 — Azure EnumerationResults confirmed${count > 0 ? ` (${count} blobs)` : ""}`,
    solution:
      "In the Azure Portal: Storage Account → Containers → select the container → Change " +
      "access level from 'Container (anonymous read access for containers and blobs)' to " +
      "'Private (no anonymous access)'. Also review the storage account's 'Allow Blob public " +
      "access' setting and disable it at the account level.",
    cweId: "CWE-552",
    cvssScore: 7.5,
    confidence: 95,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runStorageProbe(
  _targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
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
    return [];
  }

  const tasks: Promise<ScanVulnerability | null>[] = [
    ...s3Buckets.map((b) => checkS3Bucket(b).catch(() => null)),
    ...gcsBuckets.map((b) => checkGcsBucket(b).catch(() => null)),
    ...azureBlobs.map((b) => checkAzureBlob(b).catch(() => null)),
  ];

  const settled = await Promise.allSettled(tasks);
  return settled
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => v !== null);
}

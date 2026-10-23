/** Finding S3, GCS and Azure storage names in page content. */
export const MAX_BUCKETS_PER_PROVIDER = 5;

// ─────────────────────────────────────────────────────────────────────────────
// URL EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

export function extractS3Buckets(content: string): string[] {
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

export function extractGcsBuckets(content: string): string[] {
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

export interface AzureBlob {
  account: string;
  container: string;
}

export function extractAzureBlobs(content: string): AzureBlob[] {
  const found = new Map<string, AzureBlob>();

  const rx = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9][a-z0-9\-]{1,62})/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(content)) !== null) {
    const key = `${m[1]}/${m[2]}`;
    found.set(key, { account: m[1], container: m[2] });
  }

  return [...found.values()].slice(0, MAX_BUCKETS_PER_PROVIDER);
}

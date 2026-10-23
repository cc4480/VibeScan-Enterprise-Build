/**
 * Ownership and content judgement for a publicly listable storage bucket that a
 * page merely REFERENCES. A bucket URL in a page is not evidence the site owns
 * the bucket: it may be a third party's public dataset or a vendor's asset
 * host, and a bucket holding only images/css/js is public by design.
 */

export type BucketVerdict = "owned-sensitive" | "unowned" | "static-assets";

const STATIC_EXT = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|css|js|mjs|map|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav)$/i;

/** Site brand label: "example" for www.example.co.uk / shop.example.com. */
function brandOf(host: string): string {
  const labels = host.toLowerCase().replace(/^www\./, "").split(".");
  const cc = labels.length >= 3 && labels[labels.length - 1]!.length === 2 &&
    ["co", "com", "org", "net", "gov", "ac", "edu"].includes(labels[labels.length - 2]!);
  return (labels[labels.length - (cc ? 3 : 2)] ?? "").replace(/[^a-z0-9]/g, "");
}

/**
 * Evidence the bucket belongs to the scanned site: its name is the site's host
 * or contains the site's brand label (length >= 4, so "app"/"web" never match).
 * Weak by design; when in doubt the finding is hedged, not asserted.
 */
export function bucketLooksOwned(bucketOrAccount: string, targetHost: string): boolean {
  const name = bucketOrAccount.toLowerCase();
  const host = targetHost.toLowerCase().replace(/^www\./, "");
  if (name === host || name === `www.${host}`) return true;
  const brand = brandOf(targetHost);
  return brand.length >= 4 && name.replace(/[^a-z0-9]/g, "").includes(brand);
}

/** Object keys out of an S3/GCS/Azure listing body (XML or GCS JSON). */
export function listedKeys(body: string): string[] {
  const keys: string[] = [];
  for (const m of body.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(m[1]!);
  for (const m of body.matchAll(/<Blob>\s*<Name>([^<]*)<\/Name>/g)) keys.push(m[1]!);
  if (keys.length === 0) {
    try {
      const j = JSON.parse(body) as { items?: Array<{ name?: unknown }> };
      for (const i of j.items ?? []) if (typeof i.name === "string") keys.push(i.name);
    } catch { /* not JSON */ }
  }
  return keys;
}

export function judgeBucket(keys: string[], owned: boolean): BucketVerdict {
  // Folder placeholders ("img/") say nothing about content.
  const files = keys.filter((k) => !k.endsWith("/"));
  if (files.length > 0 && files.every((k) => STATIC_EXT.test(k))) return "static-assets";
  return owned ? "owned-sensitive" : "unowned";
}

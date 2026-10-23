/**
 * Deeper Supabase and Firebase checks, beyond "are the tables or collections open":
 *
 *  - Supabase Auth: are email confirmations switched off?
 *  - Supabase Storage: can the anon key list the files inside a bucket?
 *  - Firebase Storage: can anyone list the files in the project's bucket?
 *
 * All three are read-only requests using what the page already ships (the public anon
 * key, the public Firebase config). Each finding is raised only on a response that
 * proves it: a setting the server states, or file names the server returned. An empty
 * bucket, a 401 or 403, or a body that does not parse is "nothing to report", never a
 * finding, because an unproven claim about someone's storage is the costly kind of
 * false positive.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { readBodyBounded } from "./httpBody";
import { firebaseStorageApi } from "./baasEndpoints";

const TIMEOUT_MS = 8_000;
const MAX_BUCKETS = 5;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function getJson(url: string, init: RequestInit = {}): Promise<{ status: number; json: unknown } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const text = await readBodyBounded(res);
    let json: unknown = null;
    try { json = JSON.parse(text); } catch { /* not JSON: treated as nothing */ }
    return { status: res.status, json };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

// ── Supabase Auth ────────────────────────────────────────────────────────────

export async function probeSupabaseAuth(baseUrl: string, anonKey: string, findings: ScanVulnerability[]): Promise<void> {
  const res = await getJson(`${baseUrl}/auth/v1/settings`, { headers: { apikey: anonKey, Accept: "application/json" } });
  if (!res || res.status !== 200 || !isRecord(res.json)) return;
  const s = res.json;
  // Only when signup is open AND the server says confirmation is off. With signup
  // disabled nobody can register, so an unconfirmed address cannot matter.
  if (s["mailer_autoconfirm"] !== true || s["disable_signup"] === true) return;
  findings.push(vuln({
    name: "Supabase Email Confirmation Disabled",
    severity: "low",
    category: "Authentication",
    description:
      "Supabase Auth accepts a sign-up for any email address without confirming that the person owns it. " +
      "Anyone can register as someone else's address, which lets them squat on it, bypass features gated on a " +
      "verified email, and fill the user table with unverified accounts. Some apps turn confirmation off on purpose " +
      "while developing; if this is a live app it should be on.",
    evidence: `GET ${baseUrl}/auth/v1/settings → mailer_autoconfirm: true, disable_signup: false`,
    solution:
      "In the Supabase dashboard: Authentication → Providers → Email → turn on \"Confirm email\". " +
      "If sign-ups are not meant to be open, also turn on \"Disable sign-ups\" or restrict them to invited users.",
    cweId: null,
    cvssScore: 3.7,
    wstgId: "WSTG-IDNT-02",
  }));
}

// ── Supabase Storage contents ────────────────────────────────────────────────

export async function probeSupabaseStorageContents(
  baseUrl: string,
  anonKey: string,
  findings: ScanVulnerability[],
  /**
   * Bucket names the app's own code opens (`supabase.storage.from("avatars")`). The bucket list answers
   * the anon key with an empty list unless a policy allows it, so a bucket whose files can be listed
   * is usually only found by name.
   */
  bucketHints: string[] = [],
): Promise<void> {
  const headers = { apikey: anonKey, Authorization: `Bearer ${anonKey}`, Accept: "application/json" };
  const list = await getJson(`${baseUrl}/storage/v1/bucket`, { headers });
  const listed = list && list.status === 200 && Array.isArray(list.json)
    ? list.json.filter(isRecord).map((b) => b["name"]).filter((n): n is string => typeof n === "string")
    : [];
  const names = [...new Set([...bucketHints, ...listed])].slice(0, MAX_BUCKETS);

  const exposed: Array<{ bucket: string; count: number; sample: string }> = [];
  for (const bucket of names) {
    const objects = await getJson(`${baseUrl}/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ prefix: "", limit: 5, offset: 0 }),
    });
    if (!objects || objects.status !== 200 || !Array.isArray(objects.json)) continue;
    const files = objects.json.filter(isRecord).map((o) => o["name"]).filter((n): n is string => typeof n === "string");
    if (files.length > 0) exposed.push({ bucket, count: files.length, sample: files[0]! });
  }
  if (exposed.length === 0) return;

  findings.push(vuln({
    name: "Supabase Storage Files Listable Without Authentication",
    severity: "medium",
    category: "Information Disclosure",
    description:
      "The public anon key is enough to list the files stored in " +
      `${exposed.length === 1 ? "a storage bucket" : "several storage buckets"}. Anyone can see what was uploaded and ` +
      "fetch it by name. A bucket meant to serve public images can still be listed like this, so check that nothing " +
      "private (invoices, ID documents, exports) is in the buckets named here.",
    evidence: exposed.map((e) => `POST ${baseUrl}/storage/v1/object/list/${e.bucket} → ${e.count}+ objects (e.g. ${e.sample})`).join("\n"),
    solution:
      "In the Supabase dashboard: Storage → Policies. Remove any policy that lets the anon role SELECT on storage.objects " +
      "for these buckets, and give authenticated users access to only their own folder. Public buckets serve files by URL " +
      "without needing a list policy.",
    cweId: "CWE-200",
    cvssScore: 5.3,
    wstgId: "WSTG-CONF-04",
  }));
}

// ── Firebase Storage ─────────────────────────────────────────────────────────

export function extractStorageBucket(content: string): string | null {
  const m = /storageBucket\s*:\s*["']([a-z0-9][a-z0-9._-]{2,220})["']/.exec(content);
  return m?.[1] ?? null;
}

export async function probeFirebaseStorage(content: string, findings: ScanVulnerability[]): Promise<void> {
  const bucket = extractStorageBucket(content);
  if (!bucket) return;
  const url = `${firebaseStorageApi()}/v0/b/${encodeURIComponent(bucket)}/o?maxResults=5`;
  const res = await getJson(url, { headers: { Accept: "application/json" } });
  if (!res || res.status !== 200 || !isRecord(res.json)) return;
  const items = Array.isArray(res.json["items"]) ? res.json["items"].filter(isRecord) : [];
  const first = items.map((i) => i["name"]).find((n): n is string => typeof n === "string");
  if (!first) return;

  findings.push(vuln({
    name: "Firebase Storage Files Listable Without Authentication",
    severity: "high",
    category: "Broken Access Control",
    description:
      "The project's Cloud Storage bucket lets anyone list its files without signing in. The bucket name is part of the " +
      "public Firebase config, so anyone who opens the page can see and download what has been uploaded. " +
      "This means the storage security rules allow public reads (or the development default is still in place).",
    evidence: `GET ${url} → HTTP 200, ${items.length}+ objects (e.g. ${first})`,
    solution:
      "Update the Storage security rules to require authentication and scope access by owner:\n\n" +
      "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n" +
      "    match /users/{uid}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}\n\n" +
      "Files meant to be public should be served through their download URLs, not through an open list rule.",
    cweId: "CWE-284",
    cvssScore: 7.5,
    wstgId: "WSTG-ATHZ-01",
  }));
}

/**
 * Where the backend-as-a-service hosts the scanner checks are. Each has the public service's address as its default;
 * each can be pointed elsewhere by a relay or proxy an operator runs, or by a test that needs the real probes to talk to a
 * server it controls. Read on every call, so a process (or a test) can change them without re-importing anything.
 *
 * Unset (as in production) these change nothing: the requests go to the real services.
 */
const set = (name: string): string => (process.env[name] ?? "").trim();
const noSlash = (v: string) => v.replace(/\/+$/, "");

/**
 * A Supabase project's origin. Default `https://{ref}.supabase.co`. SUPABASE_PROJECT_ORIGIN_TEMPLATE replaces it, with
 * `{ref}` standing for the project reference, e.g. `http://127.0.0.1:8080/{ref}`.
 */
export function supabaseProjectOrigin(ref: string): string {
  const template = set("SUPABASE_PROJECT_ORIGIN_TEMPLATE") || "https://{ref}.supabase.co";
  return noSlash(template.replace("{ref}", ref));
}

/**
 * A Firebase Realtime Database origin, given the `https://<name>.firebaseio.com` address the page declared. With
 * FIREBASE_DATABASE_ORIGIN_TEMPLATE set (`{name}` stands for the database name) that address is replaced.
 */
export function firebaseDatabaseOrigin(declared: string): string {
  const template = set("FIREBASE_DATABASE_ORIGIN_TEMPLATE");
  if (!template) return declared;
  const name = /^https?:\/\/([a-z0-9-]+)\./i.exec(declared)?.[1];
  return name ? noSlash(template.replace("{name}", name)) : declared;
}

/** Cloud Firestore's REST API. */
export const firestoreApi = (): string => noSlash(set("FIRESTORE_API_URL")) || "https://firestore.googleapis.com";

/** Firebase Storage's REST API. */
export const firebaseStorageApi = (): string => noSlash(set("FIREBASE_STORAGE_API_URL")) || "https://firebasestorage.googleapis.com";

/**
 * Where cloud-storage listings are requested. Unset, a bucket is asked at its provider (`{bucket}.s3.amazonaws.com`,
 * `storage.googleapis.com`, `{account}.blob.core.windows.net`). STORAGE_PROBE_ORIGIN replaces all three with one server,
 * which gets `/s3/{bucket}`, `/gcs/{bucket}` or `/azure/{account}/{container}`; null means "use the provider".
 */
export const storageProbeOrigin = (): string | null => noSlash(set("STORAGE_PROBE_ORIGIN")) || null;

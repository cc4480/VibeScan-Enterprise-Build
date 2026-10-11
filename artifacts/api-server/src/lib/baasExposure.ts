/**
 * Public-by-design vs sensitive judgement for rows a BaaS returned to an
 * unauthenticated request (Supabase tables, Firestore collections, PocketBase
 * and Appwrite collections).
 *
 * "Anonymous read returned rows" is a directly observed fact; whether that is a
 * vulnerability depends on what the rows are. A `products` or `posts` table that
 * the storefront renders for every visitor is meant to be world-readable, so
 * filing it as CRITICAL trains users to ignore the findings that matter. The
 * name alone is not trusted either way: a sensitive-looking column in the
 * returned rows overrides a public-looking table name.
 *
 * Three answers, because "I cannot tell" is a different answer from "sensitive":
 *   sensitive    — the name or the rows say personal, secret or per-user data
 *   public       — the name says published content
 *   unclassified — nothing in the name or the sampled rows says either way
 * The callers report sensitive at full severity, public as information, and unclassified as
 * information too, worded as a question for the owner. It used to be reported like sensitive,
 * so a table that is public by design but not named like a catalogue (an `announcements` table of
 * title, body and date) was rated CRITICAL, on the clean twin of a test app as well.
 */

export type ExposureClass = "sensitive" | "public" | "unclassified";

const SENSITIVE_TOKENS = new Set([
  "user", "users", "profile", "profiles", "account", "accounts", "order", "orders",
  "payment", "payments", "email", "emails", "token", "tokens", "message", "messages",
  "secret", "secrets", "customer", "customers", "member", "members", "invoice", "invoices",
  "subscriber", "subscribers", "session", "sessions", "credential", "credentials",
  "contact", "contacts", "address", "addresses", "chat", "chats", "booking", "bookings",
  "transaction", "transactions", "password", "passwords", "admin", "admins", "key", "keys",
  "lead", "leads", "patient", "patients", "student", "students", "employee", "employees",
  "device", "devices", "wallet", "wallets", "card", "cards", "auth", "invite", "invites",
  "ticket", "tickets", "submission", "submissions", "log", "logs", "audit", "private",
]);

const PUBLIC_TOKENS = new Set([
  "product", "products", "post", "posts", "category", "categories", "article", "articles",
  "faq", "faqs", "pricing", "price", "prices", "plan", "plans", "event", "events",
  "blog", "blogs", "page", "pages", "tag", "tags", "testimonial", "testimonials",
  "review", "reviews", "feature", "features", "service", "services", "team", "news",
  "menu", "menus", "gallery", "banner", "banners", "collection", "collections",
  "config", "settings", "content", "item", "items", "course", "courses", "recipe", "recipes",
  "announcement", "announcements", "notice", "notices", "changelog", "changelogs", "release", "releases",
]);

/**
 * Columns that say whose a row is: the foreign key an RLS policy compares with auth.uid(). A table
 * whose rows carry one holds per-user data, and anyone being able to read it is the very gap row
 * level security closes. `created_by` and the like count; `author_id` and `updated_by` do not, because a
 * public blog post has an author.
 */
const OWNER_COLUMN =
  /^(?:user|owner|customer|member|account|tenant|org|organi[sz]ation|workspace|device|session|client|sender|recipient|assignee|uploader)[_-]?(?:id|uuid)$|^(?:uid|userid|ownerid)$|^(?:created|owned|uploaded)[_-]by$/i;

/** Column names (or nested field names) that make a row personal or secret. */
const SENSITIVE_FIELD =
  /(^|[_-])(e-?mail|phone|mobile|password|passwd|pwd|token|secret|ssn|dob|birth\w*|address|api_?key|private_?key|access_?key|refresh_?token|salary|iban|card_?number|cvv)($|[_-])|email|apikey|password|secret|token/i;

const EMAIL_VALUE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[a-z]{2,}$/i;
const SECRET_VALUE = /^(sk_(live|test)_|sb_secret_|AKIA[0-9A-Z]{16}|ghp_|eyJ[\w-]{20,}\.)/;

function tokens(name: string): string[] {
  return name
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True when any returned row carries a personal/secret-looking field or value. */
export function rowsLookSensitive(rows: unknown[]): boolean {
  const visit = (node: unknown, depth: number): boolean => {
    if (depth > 4 || node === null) return false;
    if (typeof node === "string") return EMAIL_VALUE.test(node) || SECRET_VALUE.test(node);
    if (Array.isArray(node)) return node.slice(0, 5).some((n) => visit(n, depth + 1));
    if (typeof node === "object") {
      return Object.entries(node as Record<string, unknown>).some(
        ([k, v]) => SENSITIVE_FIELD.test(k) || visit(v, depth + 1),
      );
    }
    return false;
  };
  return rows.slice(0, 5).some((r) => visit(r, 0));
}

/** True when the returned rows carry a column that says whose they are (see OWNER_COLUMN). */
export function rowsAreOwned(rows: unknown[]): boolean {
  return rows.slice(0, 5).some(
    (r) => r !== null && typeof r === "object" && !Array.isArray(r) && Object.keys(r as Record<string, unknown>).some((k) => OWNER_COLUMN.test(k)),
  );
}

export function classifyExposure(name: string, rows: unknown[]): ExposureClass {
  const t = tokens(name);
  if (t.some((x) => SENSITIVE_TOKENS.has(x)) || rowsLookSensitive(rows)) return "sensitive";
  if (t.length > 0 && t.every((x) => PUBLIC_TOKENS.has(x))) return "public";
  // The name settles nothing. Rows that carry an owner column are per-user data; rows that carry
  // none of the signals above are not shown to be anything.
  if (rowsAreOwned(rows)) return "sensitive";
  return "unclassified";
}

/** Top-level column names of the first returned row, for evidence lines. */
export function rowColumns(rows: unknown[]): string {
  const first = rows[0];
  if (first && typeof first === "object" && !Array.isArray(first)) {
    return Object.keys(first as Record<string, unknown>).slice(0, 12).join(", ");
  }
  return "";
}

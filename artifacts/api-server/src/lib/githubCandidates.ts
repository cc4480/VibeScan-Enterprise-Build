/**
 * Which files of a public repository the GitHub source scan reads, and in what order.
 *
 * The scan reads at most MAX_FILES files, so both the list and the order decide what it can find.
 * The first version's list missed .env.production.local, .envrc, docker-compose.prod.yml,
 * compose.yaml, .npmrc, .netrc, terraform.tfvars, config/master.key, firebase-adminsdk-*.json and
 * local_settings.py, and over-matched `config/*.{js,ts}` at any depth (src/config/index.ts,
 * config/webpack.config.js), node_modules, vendor and test fixtures, plus an unanchored
 * `supabase/migrations` (notsupabase/migrations/x.sql). Then it took the first 25 in Git's
 * alphabetical tree order, so thirty apps/NAME/config/settings.json files sorted ahead of
 * services/api/.env and web/.env and the run finished "scanned", files read, clean, without ever
 * opening either.
 */

/** Directories whose contents are somebody else's code or a test's, not the project's own configuration. */
const EXCLUDED_DIR = /(?:^|\/)(?:node_modules|vendor|third_party|dist|build|out|coverage|\.git|tests?|__tests__|__mocks__|__fixtures__|fixtures?|testdata|spec)\//i;

const CANDIDATE = new RegExp(
  [
    String.raw`(?:^|/)\.env(?:\.[\w.-]+)?$`, // .env, .env.production.local, .env.example
    String.raw`(?:^|/)\.(?:envrc|npmrc|netrc|pypirc)$`,
    String.raw`(?:^|/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$`, // docker-compose.prod.yml, compose.yaml
    String.raw`(?:^|/)\.aws/credentials$`,
    String.raw`(?:^|/)wp-config\.php$`,
    String.raw`(?:^|/)(?:local_)?settings\.py$`,
    String.raw`(?:^|/)appsettings(?:\.[\w-]+)?\.json$`,
    String.raw`(?:^|/)config/master\.key$`,
    String.raw`(?:^|/)serviceAccountKey\.json$`,
    String.raw`(?:^|/)[\w.-]*firebase-adminsdk[\w.-]*\.json$`,
    String.raw`(?:^|/)[\w.-]+\.tfvars$`,
    // A config directory at the root or one level down: data files, or code named for what it holds.
    String.raw`^(?:[\w.-]+/)?config/[\w.-]+\.(?:json|ya?ml)$`,
    String.raw`^(?:[\w.-]+/)?config/(?:secrets?|credentials?|production|prod|local)[\w.-]*\.(?:js|ts)$`,
    String.raw`(?:^|/)supabase/migrations/[\w.-]+\.sql$`,
  ].join("|"),
  "i",
);

/** Files read per repository. The cap is spent in the order prioritise() gives. */
export const MAX_FILES = 25;

export function isCandidatePath(path: string): boolean {
  return !EXCLUDED_DIR.test(path) && CANDIDATE.test(path);
}

/**
 * Lower reads first. A real .env outranks an example one, credentials outrank general config, and
 * within a class a file nearer the root outranks a deeper one. Migrations, which the secret patterns
 * were never written for, go last.
 */
function rank(path: string): number {
  const depth = path.split("/").length - 1;
  const base = path.split("/").pop() ?? "";
  let cls = 3;
  if (/^\.env(?:\.|$)/i.test(base) && !/\.(?:example|sample|template|dist|tmpl)$/i.test(base)) cls = 0;
  else if (/^\.env|credentials|serviceAccountKey|firebase-adminsdk|master\.key|\.tfvars$|wp-config|^\.(?:npmrc|netrc|pypirc)$/i.test(path.slice(path.lastIndexOf("/") + 1))) cls = 1;
  else if (/compose|appsettings|settings\.py$/i.test(base)) cls = 2;
  else if (/\.sql$/i.test(base)) cls = 4;
  return cls * 100 + depth;
}

/** Candidate entries, most worth reading first, ties broken by path so the order is deterministic. */
export function prioritise<T extends { path: string }>(entries: T[]): T[] {
  return [...entries].sort((a, b) => rank(a.path) - rank(b.path) || a.path.localeCompare(b.path));
}

/**
 * Where GitHub is. github.com's three hosts by default; each can be pointed elsewhere for a GitHub Enterprise Server
 * install, or by a test that needs the real code to talk to a server it controls.
 *
 * Read on every call, not once at load, so a process (or a test) can change them without re-importing anything.
 */
const trim = (v: string) => v.trim().replace(/\/+$/, "");
const fromEnv = (name: string, fallback: string) => trim(process.env[name] ?? "") || fallback;

/** The REST API: repositories, trees, installations and their tokens. */
export const githubApi = (): string => fromEnv("GITHUB_API_URL", "https://api.github.com");

/** The website: the OAuth sign-in and the App installation page. */
export const githubWeb = (): string => fromEnv("GITHUB_WEB_URL", "https://github.com");

/** Raw file contents. */
export const githubRaw = (): string => fromEnv("GITHUB_RAW_URL", "https://raw.githubusercontent.com");

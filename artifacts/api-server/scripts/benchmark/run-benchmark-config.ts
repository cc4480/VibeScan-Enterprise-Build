/** Command-line arguments and the paths and targets derived from them. */
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ── Arguments ─────────────────────────────────────────────────────────────────

export const argv = process.argv.slice(2);

export const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};

export const has = (name: string) => argv.includes(`--${name}`);

export const OUT_DIR = resolve(flag("out", "benchmark-out"));

export const TOOLS = flag("tools", "zap,nuclei,secscan").split(",").map((t) => t.trim());

export const ZAP_MODE = flag("zap-mode", "full");

export const SCORE_ONLY = has("score-only");

/** The fixture as the host sees it, and as a container sees it. */
export const HOST_TARGET = flag("target", "http://127.0.0.1:4100");

export const DOCKER_TARGET = HOST_TARGET.replace(/127\.0\.0\.1|localhost/, "host.docker.internal");

// ESM: no __dirname. import.meta.url is the module's own location.
export const HERE = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(HERE, "..", "..", "..", "..");

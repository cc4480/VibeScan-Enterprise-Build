/**
 * Infrastructure files: Firebase security rules, Dockerfile and docker-compose hygiene, and third-party GitHub Actions.
 *
 * The shapes are ones that are a flaw by themselves and are spelled out in the finding: `allow write: if true` (anyone on
 * the internet writes to the database), `privileged: true`, a database port published to every network interface, a
 * download piped into a shell. Judgement calls (a container with no USER line, an action on a tag) are reported at low
 * confidence, which the report lists under "needs verification" instead of presenting as proven.
 */
import { repoFinding, type RepoFile, type RepoRef } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

export const isComposePath = (p: string) => /(?:^|\/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i.test(p);
export const isFirebaseRulesPath = (p: string) => /(?:^|\/)(?:firestore\.rules|storage\.rules|database\.rules\.json)$/i.test(p);
export const isInfraPath = (p: string) => isComposePath(p) || isFirebaseRulesPath(p);

const withoutSlashComments = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'])\/\/[^\n]*/g, "$1");

// ── Firebase rules ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The path pattern of the innermost `match` block that opens before `index`. */
function enclosingMatch(text: string, index: number): string {
  const before = text.slice(0, index);
  // The path itself holds braces (/{document=**}), so it is read as one run of non-space characters.
  const all = [...before.matchAll(/\bmatch\s+(\S+)\s*\{/g)];
  return all.length ? all[all.length - 1]![1]! : "";
}

function firestoreRulesFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const text = withoutSlashComments(f.content);
  const isStorage = /storage\.rules$/i.test(f.path);
  const what = isStorage ? "Cloud Storage" : "Firestore";
  const writes: string[] = [];
  const reads: string[] = [];
  let wildcardRead = false;

  for (const m of text.matchAll(/\ballow\s+([a-z][a-z,\s]*?)\s*:\s*if\s+(true|request\.time\s*<\s*timestamp\.date\([^)]*\))\s*;/gi)) {
    const methods = m[1]!.toLowerCase();
    const open = m[2]!.toLowerCase() === "true" ? "if true" : "if request.time < timestamp.date(...) (the 30-day test mode)";
    const line = `allow ${methods.replace(/\s+/g, " ")}: ${open}`;
    if (/\b(?:write|create|update|delete)\b/.test(methods)) writes.push(line);
    if (/\b(?:read|get|list)\b/.test(methods)) {
      reads.push(line);
      if (/\*\*/.test(enclosingMatch(text, m.index!))) wildcardRead = true;
    }
  }

  if (writes.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: `${what} Rules Let Anyone Write`,
      severity: "critical", category: "Access Control", cweId: "CWE-284", cvssScore: 9.1, confidence: 90,
      description: `${what} security rules allow writes to anyone: the condition is "true" (or the starter test mode that opens everything until a date). Firebase's client keys are public by design, so the rules are the only protection: anyone on the internet can create, change and delete this data with a few lines of code.`,
      detail: writes.slice(0, 4).map((l) => `Rule: ${l}`).join("\n"),
      solution: "Require a signed-in user and check ownership (request.auth != null && request.auth.uid == resource.data.userId), and allow only the operations each collection needs. Replace the test-mode rule before launch: it expires, and until it does it is open to everyone.",
    }));
  }
  if (reads.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: `${what} Rules Let Anyone Read`,
      severity: wildcardRead ? "high" : "medium", category: "Access Control", cweId: "CWE-284", cvssScore: wildcardRead ? 7.5 : 5.3, confidence: wildcardRead ? 85 : 65,
      description: `${what} security rules allow reads to anyone (the condition is "true" or the test mode)${wildcardRead ? ", and on a wildcard path that covers every document" : ""}. Anyone who finds the project's public key can download the data.`,
      detail: reads.slice(0, 4).map((l) => `Rule: ${l}`).join("\n"),
      solution: "Allow reads only to the users who need them (request.auth != null, then ownership or role). Leave public only what is meant to be public, such as a catalogue, and say so in a comment beside the rule.",
    }));
  }
  return out;
}

const OPEN_RTDB = (v: unknown): boolean => v === true || (typeof v === "string" && /^\s*(?:true|now\s*<\s*\d+)\s*$/.test(v));

function realtimeRulesFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  let doc: unknown;
  try { doc = JSON.parse(withoutSlashComments(f.content)); } catch { return []; }
  const root = (doc as { rules?: Record<string, unknown> } | null)?.rules;
  if (!root || typeof root !== "object") return [];
  const open: string[] = [];
  let writeOpen = false;
  const walk = (node: Record<string, unknown>, path: string) => {
    for (const [k, v] of Object.entries(node)) {
      if (k === ".read" || k === ".write") {
        if (OPEN_RTDB(v)) { open.push(`${path || "/"} ${k}: ${JSON.stringify(v)}`); if (k === ".write") writeOpen = true; }
      } else if (v && typeof v === "object" && !k.startsWith(".")) walk(v as Record<string, unknown>, `${path}/${k}`);
    }
  };
  walk(root, "");
  if (open.length === 0) return [];
  return [repoFinding({
    ref, path: f.path, name: writeOpen ? "Realtime Database Rules Let Anyone Write" : "Realtime Database Rules Let Anyone Read",
    severity: writeOpen ? "critical" : "high", category: "Access Control", cweId: "CWE-284", cvssScore: writeOpen ? 9.1 : 7.5, confidence: 85,
    description: `The Realtime Database rules set ".${writeOpen ? "write" : "read"}" to true (or to the starter test mode, "now < <date>"). Firebase's client keys are public by design, so anyone can ${writeOpen ? "change and delete" : "download"} the data at that path.`,
    detail: open.slice(0, 4).map((l) => `Rule: ${l}`).join("\n"),
    solution: "Rules cascade downward, so set \".read\" and \".write\" to a condition such as \"auth != null && auth.uid === $uid\" on each path, and remove any rule that is just true. Replace the test-mode rule before launch.",
  })];
}

// ── Docker and compose ──────────────────────────────────────────────────────────────────────────────────────────────

export function dockerHygieneFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const text = f.content;

  const pipe = /^\s*RUN\b[^\n]*\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b[^\n]*/im.exec(text);
  if (pipe) {
    out.push(repoFinding({
      ref, path: f.path, name: "Dockerfile Pipes a Download Into a Shell",
      severity: "medium", category: "Supply Chain Security", cweId: "CWE-494", cvssScore: 5.9, confidence: 70,
      description: "A RUN step downloads a script and hands it straight to a shell. Whatever the server returns when the image is built is run as root with no check, so a compromised or changed URL runs its code inside your image.",
      detail: `Line: ${pipe[0].trim().slice(0, 140)}`,
      solution: "Download to a file, verify a checksum or signature you pinned in the Dockerfile, then run it. Or install from the distribution's package manager at a pinned version.",
    }));
  }

  const stages = text.split(/^\s*FROM\b/im).slice(1);
  const final = stages[stages.length - 1] ?? "";
  const image = /^\s*(?:--platform=\S+\s+)?(\S+)/.exec(final)?.[1] ?? "";
  if (stages.length > 0 && !/\bscratch\b|distroless|nonroot/i.test(image) && !/^\s*USER\s+(?!root\b)\S+/im.test(final)) {
    out.push(repoFinding({
      ref, path: f.path, name: "Container Runs as Root",
      severity: "low", category: "Security Misconfiguration", cweId: "CWE-250", cvssScore: 4.4, confidence: 55,
      description: "The last stage of the Dockerfile never switches to a non-root user, so the application runs as root inside the container. A flaw in the app then gives the attacker root there, which makes escaping the container much easier.",
      solution: "Create an unprivileged user and add a USER line before the final CMD (many base images ship one, such as node's `node` user). Some images must start as root to bind a low port or drop privileges themselves: if so, say so in a comment.",
    }));
  }

  const unpinned = [...text.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s$]+)/gim)]
    .map((m) => m[1]!)
    .filter((img) => img.toLowerCase() !== "scratch" && (/:latest$/i.test(img) || !/[:@]/.test(img)))
    // A name defined by an earlier "FROM ... AS name" is a build stage, not a registry image.
    .filter((img) => !new RegExp(`\\bAS\\s+${img.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(text));
  if (unpinned.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: "Dockerfile Base Image Is Not Pinned",
      severity: "low", category: "Supply Chain Security", cweId: "CWE-1104", cvssScore: 3.7, confidence: 60,
      description: "A base image is used without a version tag (or with :latest), so each build can pull a different image, including one that changed after you last tested it.",
      detail: `Image: ${unpinned.slice(0, 4).join(", ")}`,
      solution: "Pin to a specific version tag (node:22.11-alpine), or to a digest (image@sha256:...) for builds that must be reproducible, and update it on purpose.",
    }));
  }
  return out;
}

const DB_PORTS = new Set(["5432", "3306", "6379", "27017", "9200", "11211", "1433", "5984"]);

function composeFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const text = withoutSlashComments(f.content.replace(/^\s*#.*$/gm, ""));
  if (/^\s*privileged\s*:\s*true\b/im.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "Compose Service Runs Privileged",
      severity: "high", category: "Security Misconfiguration", cweId: "CWE-250", cvssScore: 7.5, confidence: 85,
      description: "A service is started with privileged: true, which gives the container nearly all the host's capabilities and access to its devices. A flaw in that service is then a flaw in the host.",
      solution: "Remove privileged and add only the specific capability the service needs (cap_add), or the specific device (devices).",
    }));
  }
  const socket = /^\s*-\s*["']?\/var\/run\/docker\.sock\S*/im.exec(text);
  if (socket) {
    // A reverse proxy such as Traefik mounts it read-only on purpose; read-only still exposes the container list, so
    // it is rated lower, not dropped.
    const readOnly = /:ro\b/.test(socket[0]);
    out.push(repoFinding({
      ref, path: f.path, name: "Compose Service Mounts the Docker Socket",
      severity: readOnly ? "low" : "medium", category: "Security Misconfiguration", cweId: "CWE-250", cvssScore: readOnly ? 3.7 : 6.5, confidence: readOnly ? 55 : 80,
      description: "A service mounts /var/run/docker.sock. Whoever controls that service controls Docker on the host, which is the same as root on it.",
      solution: "Avoid mounting the socket. If a tool must talk to Docker, mount it read-only through a socket proxy that allows only the calls it needs.",
    }));
  }
  const exposed = [...text.matchAll(/^\s*-\s*["']?(?:0\.0\.0\.0:)?(\d{2,5}):(\d{2,5})(?:\/\w+)?["']?\s*$/gm)].filter((m) => DB_PORTS.has(m[2]!)).map((m) => `${m[1]}:${m[2]}`);
  if (exposed.length > 0) {
    // An override or dev compose file publishes the database to the developer's own machine on purpose. So does one whose
    // database password defaults to a development value (${DB_PASSWORD:-localdev123}): that is the local stack, not a server.
    const devDbDefault = /\$\{\w*PASS\w*:-(?:local|dev|test|example|changeme|password|postgres)[^}]*\}/i.test(text);
    const devOnly = /(?:override|dev|local|test)/i.test(f.path.slice(f.path.lastIndexOf("/") + 1)) || devDbDefault;
    out.push(repoFinding({
      ref, path: f.path, name: "Compose Publishes a Database Port to Every Network Interface",
      severity: devOnly ? "info" : "medium", category: "Security Misconfiguration", cweId: "CWE-668", cvssScore: devOnly ? 0 : 6.5, confidence: devOnly ? 45 : 70,
      description: "A database or cache port is published without a host address, so it listens on every interface of the machine. On a server with a public address, that makes the database reachable from the internet, where it is attacked within hours.",
      detail: `Ports: ${[...new Set(exposed)].slice(0, 4).join(", ")}`,
      solution: "Bind it to the loopback address (\"127.0.0.1:5432:5432\") or drop the ports entry, since services on the same compose network reach each other by name.",
    }));
  }
  return out;
}

// ── GitHub Actions ──────────────────────────────────────────────────────────────────────────────────────────────────

export function actionsHygieneFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const mutable = [...f.content.matchAll(/^\s*-?\s*uses\s*:\s*([\w.-]+)\/([\w./-]+)@([^\s#]+)/gim)]
    .filter((m) => !["actions", "github"].includes(m[1]!.toLowerCase()) && !/^[0-9a-f]{40}$/i.test(m[3]!))
    .map((m) => `${m[1]}/${m[2]}@${m[3]}`);
  if (mutable.length > 0) {
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Uses Third-Party Actions Pinned to a Mutable Tag",
      severity: "low", category: "CI/CD Security", cweId: "CWE-829", cvssScore: 4.3, confidence: 65,
      description: "A workflow uses actions from outside GitHub by a tag or branch. Tags can be moved: if the action's repository is compromised, the next run executes the attacker's code with the workflow's token and secrets (this is how the tj-actions/changed-files compromise reached thousands of repositories).",
      detail: `Actions: ${[...new Set(mutable)].slice(0, 6).join(", ")}${new Set(mutable).size > 6 ? ` and ${new Set(mutable).size - 6} more` : ""}`,
      solution: "Pin each third-party action to the full 40-character commit SHA (keep the version in a comment), and let Dependabot or Renovate propose updates.",
    }));
  }
  if (/^\s*secrets\s*:\s*inherit\b/im.test(f.content)) {
    out.push(repoFinding({
      ref, path: f.path, name: "GitHub Actions Passes Every Secret to a Called Workflow",
      severity: "info", category: "CI/CD Security", cweId: "CWE-250", cvssScore: 0, confidence: 60,
      description: "A job calls a reusable workflow with `secrets: inherit`, which hands it every secret of the repository or organisation, not just the ones it needs.",
      solution: "Name the secrets the called workflow uses instead of inheriting all of them.",
    }));
  }
  return out;
}

export function infraFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  if (/(?:firestore|storage)\.rules$/i.test(f.path)) return firestoreRulesFindings(f, ref);
  if (/database\.rules\.json$/i.test(f.path)) return realtimeRulesFindings(f, ref);
  if (isComposePath(f.path)) return composeFindings(f, ref);
  return [];
}

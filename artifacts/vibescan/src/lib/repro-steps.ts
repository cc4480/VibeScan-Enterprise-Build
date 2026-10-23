/**
 * "How to see it yourself": a curl command for a finding whose evidence records the
 * exact request the scanner made.
 *
 * The rule is strict: a command is produced only when the evidence's first line is a
 * plain GET, HEAD or OPTIONS of an http(s) URL, optionally followed by
 * "Request header: Name: value" lines. It is a replay of what the scanner sent, not a
 * reconstruction. Anything else (a POST, a payload in a body, an out-of-band callback,
 * a DNS record, free text) returns null and the report shows no steps, because a
 * guessed command that does not reproduce the finding is worse than none.
 */

export interface ReproSteps {
  command: string;
  /** What the evidence says the response contained, to look for in the output. */
  expect: string[];
}

const REQUEST_LINE = /^(GET|HEAD|OPTIONS)\s+(https?:\/\/\S+)(?:\s+(?:→|->)\s+(.*))?$/;
const HEADER_LINE = /^Request header:\s*([A-Za-z0-9-]+):\s*(.+)$/;
const RESPONSE_LINE = /^Response:\s*(.+)$/;

/** Single-quote for a POSIX shell; refuse anything that cannot be quoted safely. */
function quote(value: string): string | null {
  if (/['\r\n\0]/.test(value)) return null;
  return `'${value}'`;
}

function safeUrl(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username || u.password) return null;
  return raw;
}

export function reproSteps(evidence: string | null | undefined): ReproSteps | null {
  if (!evidence) return null;
  const lines = evidence.split(/\r?\n/).map((l) => l.trim());
  const first = REQUEST_LINE.exec(lines[0] ?? "");
  if (!first) return null;
  const [, method, rawUrl, outcome] = first;
  const url = safeUrl(rawUrl!);
  const quotedUrl = url && quote(url);
  if (!quotedUrl) return null;

  const args = ["curl", "-i"];
  if (method === "OPTIONS") args.push("-X", "OPTIONS");
  else if (method === "HEAD") args.push("-I");
  const expect: string[] = [];
  if (outcome) expect.push(outcome.trim());

  for (const line of lines.slice(1)) {
    const header = HEADER_LINE.exec(line);
    if (header) {
      const q = quote(`${header[1]}: ${header[2]!.trim()}`);
      if (!q) return null;
      args.push("-H", q);
      continue;
    }
    const response = RESPONSE_LINE.exec(line);
    if (response) expect.push(response[1]!.trim());
  }
  args.push(quotedUrl);
  return { command: args.join(" "), expect };
}

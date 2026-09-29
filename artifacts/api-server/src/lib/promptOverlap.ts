/**
 * How much of a known text a reply reproduces. Pure and linear.
 *
 * promptInjectionProbe.ts asks one yes/no question: does this endpoint's reply contain a long,
 * verbatim chunk of a system prompt we already hold from the site's own JavaScript? Three things
 * about the first version of that comparison were wrong, and all three live here:
 *
 *   1. It was cubic. Every start position was compared at every length, re-slicing each time, and
 *      it did the most work exactly when the reply DID reproduce the prompt. Measured: 1,000
 *      characters 0.2 s, 4,000 characters 12 s, 8,000 characters 99 s, on the event loop, which
 *      starves every timer including the scan's own timeout. Now it is one pass over a hash set.
 *
 *   2. It read the reply as one string. The prompt was compared as its raw SOURCE literal (with \n
 *      and \' still escaped) against the raw body, so a fully leaked prompt scored 130 of 182 in a
 *      JSON reply, 49 in a plain one and 0 in a streamed one. Most production chat endpoints
 *      stream. Replies are now read as JSON, as server-sent events, as newline-delimited JSON and
 *      as the Vercel AI data stream, and the best reading wins.
 *
 *   3. Its only measure was an absolute 40 characters. A model that declines and restates its own
 *      role sentence ("I'm a helpful assistant that answers questions about Acme's products...")
 *      reproduces 85 characters of a 163-character prompt and was reported as an extraction. The
 *      measure is now the longest run AND the share of the prompt reproduced anywhere.
 */

/** Shingle length. Long enough that a coincidental match is negligible, short enough to survive edits. */
const K = 24;
const MAX_PROMPT = 20_000;
const MAX_REPLY = 200_000;

export interface Overlap {
  /** Length of the longest verbatim run of the prompt found in the reply. */
  longest: number;
  /** Share of the prompt's characters that sit in any such run, 0 to 1. */
  coverage: number;
  /** The longest run itself, so a report can show what matched. */
  excerpt: string;
}

const NONE: Overlap = { longest: 0, coverage: 0, excerpt: "" };

/** Whitespace collapsed and typographic punctuation flattened, so a model's curly quotes do not hide a match. */
function normalise(s: string): string {
  return s
    .replace(/[‘’‛]/g, "'")
    .replace(/[“”‟]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/ /g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function measureOverlap(promptText: string, replyText: string): Overlap {
  const prompt = normalise(promptText).slice(0, MAX_PROMPT);
  const reply = normalise(replyText).slice(0, MAX_REPLY);
  if (prompt.length < K || reply.length < K) return NONE;

  const shingles = new Set<string>();
  for (let i = 0; i + K <= reply.length; i++) shingles.add(reply.slice(i, i + K));

  let coveredChars = 0;
  let coveredUntil = 0; // exclusive end of what has been counted
  let run = 0;
  let bestRun = 0;
  let bestStart = 0;
  for (let i = 0; i + K <= prompt.length; i++) {
    if (shingles.has(prompt.slice(i, i + K))) {
      coveredChars += i + K - Math.max(i, coveredUntil);
      coveredUntil = i + K;
      run++;
      if (run > bestRun) {
        bestRun = run;
        bestStart = i - run + 1;
      }
    } else {
      run = 0;
    }
  }
  if (bestRun === 0) return NONE;
  const longest = bestRun + K - 1;
  return { longest, coverage: coveredChars / prompt.length, excerpt: prompt.slice(bestStart, bestStart + longest) };
}

/** The characters an escaped JS string literal stands for: \n, \', \\, \uXXXX, \xNN, \u{...}, line continuations. */
export function unescapeJsLiteral(raw: string): string {
  return raw.replace(/\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([\s\S]))/g, (whole, braced, u4, x2, ch) => {
    try {
      if (braced) return String.fromCodePoint(parseInt(braced, 16));
      if (u4) return String.fromCharCode(parseInt(u4, 16));
      if (x2) return String.fromCharCode(parseInt(x2, 16));
    } catch {
      return whole;
    }
    switch (ch) {
      case "n": return "\n";
      case "r": return "\r";
      case "t": return "\t";
      case "b": return "\b";
      case "f": return "\f";
      case "v": return "\v";
      case "0": return "\0";
      case "\n": return ""; // line continuation
      default: return ch;
    }
  });
}

const TOKEN_KEYS = new Set(["content", "text", "delta", "token", "message", "reply", "response", "output", "completion", "answer", "generated_text"]);

/** Keys whose string values are stream metadata, not reply text, even when they sit under "delta" or "message". */
const METADATA_KEYS = new Set(["type", "role", "id", "model", "object", "finish_reason", "stop_reason", "name", "index"]);

function tryJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/** String values in a JSON document. With `onlyReplyFields`, only those under a key that carries reply text. */
function stringLeaves(value: unknown, onlyReplyFields: boolean, underReplyKey = false, out: string[] = []): string[] {
  if (typeof value === "string") {
    if (!onlyReplyFields || underReplyKey) out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) stringLeaves(v, onlyReplyFields, underReplyKey, out);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (onlyReplyFields && METADATA_KEYS.has(k.toLowerCase())) continue;
      stringLeaves(v, onlyReplyFields, underReplyKey || TOKEN_KEYS.has(k.toLowerCase()), out);
    }
  }
  return out;
}

/**
 * Every plausible way to read a reply body as text, raw first. A prompt is compared against each
 * and the best reading wins, because the same reply is a JSON document to one endpoint, a stream
 * of one-word events to the next, and plain text to a third.
 */
export function replyTexts(body: string): string[] {
  const out = [body];
  const trimmed = body.trim();
  const whole = tryJson(trimmed);
  if (whole !== undefined && whole !== null && typeof whole === "object") {
    out.push(stringLeaves(whole, false).join(" "), stringLeaves(whole, true).join(""));
    return out;
  }

  // One event or document per line: SSE ("data: {...}"), NDJSON, or Vercel's `0:"token"` frames.
  const tokens: string[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const frame = /^\d+:(".*")$/.exec(line.trim());
    if (frame) {
      const s = tryJson(frame[1]!);
      if (typeof s === "string") tokens.push(s);
      continue;
    }
    const payload = line.replace(/^data:\s*/, "").trim();
    if (!payload || payload === "[DONE]" || /^(event|id|retry):/.test(payload)) continue;
    const parsed = tryJson(payload);
    if (parsed === undefined) {
      if (line.startsWith("data:")) tokens.push(payload);
    } else if (typeof parsed === "string") {
      tokens.push(parsed);
    } else {
      tokens.push(...stringLeaves(parsed, true));
    }
  }
  if (tokens.length > 0) out.push(tokens.join(""), tokens.join(" "));
  return out;
}

/** The best overlap of the prompt with any reading of the reply. */
export function bestOverlap(prompt: string, replyBody: string): Overlap {
  let best = NONE;
  for (const text of replyTexts(replyBody)) {
    const o = measureOverlap(prompt, text);
    if (o.coverage > best.coverage || (o.coverage === best.coverage && o.longest > best.longest)) best = o;
  }
  return best;
}

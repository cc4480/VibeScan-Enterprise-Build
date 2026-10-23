/**
 * Source-text helpers for check-index.mjs: brace matching that survives
 * strings, comments, template literals and regexes, and the lookup that names a
 * finding built by spreading a constant. Split out so check-index.mjs does not
 * grow past the size a script here can hold.
 */

/**
 * A copy of the source with every brace that is not structural replaced by a
 * space, so brace matching cannot be thrown off by one inside a string, a
 * comment, a template literal or — the case that actually bit — a regex:
 * `/(?:password|pwd)\s*[:=]\s*["'][^"']{8,}["']/` in secret-pattern-data.ts
 * opens a brace that never closes, and a naive scan walks straight past the
 * start of the object it was looking for.
 *
 * Indices are preserved, so a span found here slices the original text.
 */
export function maskLiterals(text) {
  const out = text.split("");
  const mask = (i) => { if (out[i] === "{" || out[i] === "}") out[i] = " "; };
  let i = 0;

  const prevCode = () => {
    for (let j = i - 1; j >= 0; j--) if (!/\s/.test(text[j])) return text[j];
    return "";
  };

  // A regex can also follow a keyword, where the character before it is an
  // ordinary letter. `return /"[^"]{8,}"/i.test(body)` in probes-data.ts read
  // the "n" of "return" as the previous code character, classified the slash as
  // division, and scanned the pattern as code — so {8,} opened a brace that
  // never closed and every object span after it started in the wrong place.
  // Findings from /Dockerfile onward were then reported under their
  // neighbour's name.
  const KEYWORD_BEFORE_REGEX = new Set([
    "return", "typeof", "instanceof", "in", "of", "case", "do", "else",
    "void", "delete", "yield", "await", "new", "throw",
  ]);

  const prevWord = () => {
    let j = i - 1;
    while (j >= 0 && /\s/.test(text[j])) j--;
    const end = j + 1;
    while (j >= 0 && /[\w$]/.test(text[j])) j--;
    return text.slice(j + 1, end);
  };

  // Template literals nest — scanner.ts has `...${vendor ? `${vendor}'s` : "x"}...`
  // — so a scan that just runs to the next backtick ends the string inside its
  // own interpolation and every brace after it is classified wrongly. That is
  // what put a neighbouring finding's CVSS on two Scan Coverage findings.
  const scanTemplate = () => {
    while (i < text.length) {
      if (text[i] === "\\") { i += 2; continue; }
      if (text[i] === "`") { i++; return; }
      if (text[i] === "$" && text[i + 1] === "{") {
        mask(i + 1);       // the ${ brace is punctuation, not an object
        i += 2;
        scanCode(true);    // consumes through the matching }
        continue;
      }
      mask(i++);
    }
  };

  function scanCode(untilCloseBrace) {
    let depth = 0;
    while (i < text.length) {
      const ch = text[i];
      const next = text[i + 1];
      if (ch === "/" && next === "/") { while (i < text.length && text[i] !== "\n") mask(i++); continue; }
      if (ch === "/" && next === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) mask(i++); i += 2; continue; }
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i++;
        while (i < text.length) {
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i] === quote) { i++; break; }
          mask(i++);
        }
        continue;
      }
      if (ch === "`") { i++; scanTemplate(); continue; }
      // A `/` opens a regex only where a value may begin — otherwise it is division.
      if (
        ch === "/" &&
        (/^[(,=:[!&|?{};+\-*%<>]?$/.test(prevCode()) || KEYWORD_BEFORE_REGEX.has(prevWord()))
      ) {
        i++;
        let inClass = false;
        while (i < text.length) {
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i] === "[") inClass = true;
          else if (text[i] === "]") inClass = false;
          else if (text[i] === "/" && !inClass) { i++; break; }
          else if (text[i] === "\n") break;
          mask(i++);
        }
        continue;
      }
      if (ch === "{") { depth++; i++; continue; }
      if (ch === "}") {
        if (untilCloseBrace && depth === 0) { mask(i); i++; return; }
        depth--; i++; continue;
      }
      i++;
    }
  }

  scanCode(false);
  return out.join("");
}

/**
 * The span of the object literal containing `at`, found by matching braces
 * outward over the masked text. A fixed character window is not good enough:
 * the header-gap table in crawler.ts packs sibling literals close together, and
 * a window reaches past the entry it belongs to and reads the neighbour's name.
 */
export function enclosingObject(text, masked, at) {
  let depth = 0;
  let start = -1;
  for (let i = at; i >= 0; i--) {
    const ch = masked[i];
    if (ch === "}") depth++;
    else if (ch === "{") {
      if (depth === 0) { start = i; break; }
      depth--;
    }
  }
  if (start === -1) return null;
  depth = 0;
  for (let i = start; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  return text.slice(start);
}

const maskedCache = new Map();
const maskedOf = (file, text) => {
  if (!maskedCache.has(file)) maskedCache.set(file, maskLiterals(text));
  return maskedCache.get(file);
};

/**
 * The source of every constant object literal that `obj` spreads.
 *
 * A finding can be assembled as `{ id, ...AI_OPT_OUT_NOTE, severity, category }`
 * — worker.ts does this for the note it adds when an owner has turned AI
 * analysis off — so the literal that carries `severity:` has no `name:` and the
 * name sits with the rest of the note's text in aiOptOut.ts. The caller runs its
 * own name pattern over what this returns.
 *
 * A spread is looked up in the file that writes it and in the modules that file
 * imports, and only a plain identifier is followed (`...NOTE`, not `...f()` or
 * `...a.b`). One that cannot be resolved contributes nothing, so the finding
 * stays unnamed and the generator's warning still fires.
 *
 * @param {string} obj   the finding's own object literal
 * @param {string} file  the source file it was read from
 * @param {Record<string, string>} src  every source file by name
 */
export function spreadLiterals(obj, file, src) {
  const imported = [...src[file].matchAll(/from\s+"\.\/([A-Za-z0-9_-]+)(?:\.js)?"/g)].map((m) => `${m[1]}.ts`);
  const searched = [file, ...imported].filter((f) => f in src);
  const found = [];
  for (const [, ident] of obj.matchAll(/\.\.\.([A-Za-z_$][\w$]*)(?![\w$.(\[])/g)) {
    const decl = new RegExp(String.raw`\bconst\s+${ident.replace(/\$/g, "\$")}\b[^=;\n]*=\s*\{`, "g");
    for (const f of searched) {
      const masked = maskedOf(f, src[f]);
      // Matched against the raw text, then confirmed as code: inside a comment
      // or a string the same characters would have been masked to spaces.
      const hit = [...src[f].matchAll(decl)].find((m) => masked[m.index + m[0].length - 1] === "{");
      if (!hit) continue;
      found.push(enclosingObject(src[f], masked, hit.index + hit[0].length - 1));
      break;
    }
  }
  return found.join("\n");
}

/** Port definitions in recon-data carry their finding on a `dangerous` block. */
export function parseReconData(text) {
  const re = /\{\s*port:\s*(\d+),\s*service:\s*"([^"]+)",\s*dangerous:\s*\{\s*severity:\s*"(critical|high|medium)"[\s\S]{0,900}?cweId:\s*"([^"]+)",\s*cvssScore:\s*([\d.]+)/g;
  return [...text.matchAll(re)].map((m) => ({
    name: `${m[2]} Exposed on Port ${m[1]}`,
    sev: m[3],
    cat: "Exposed Service",
    cwe: m[4],
    cvss: Number(m[5]),
    wstg: null,
  }));
}

/**
 * Where in an HTML response does a reflected marker land?
 *
 * "<token>" coming back with its angle brackets intact only matters when the
 * browser's parser will treat that `<` as the start of a tag. Inside a
 * `<script>`, `<style>`, `<textarea>`, `<title>`, an HTML comment, or a quoted
 * attribute value the same bytes are inert text, so the reflection is not XSS
 * until the input can also close that context (`</script>`, `-->`, a quote).
 *
 * This is a deliberately small tokenizer, not a full HTML parser: it tracks
 * exactly the states that decide whether a `<` at a given offset opens an
 * element.
 */

export type HtmlState =
  | { kind: "data" }
  | { kind: "comment" }
  | { kind: "tag" }
  | { kind: "raw"; name: string };

/** Elements whose content the parser reads as text until the matching end tag. */
const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "noembed", "noframes"]);

/** The input that would close each inert context, so a probe can test for a break-out. */
export function breakoutFor(state: HtmlState): string | null {
  if (state.kind === "comment") return "-->";
  if (state.kind === "raw") return `</${state.name}>`;
  return null;
}

/** Parser state at `end`: is a `<` at that offset in element-creating data context? */
export function htmlStateAt(body: string, end: number): HtmlState {
  let p = 0;
  while (p < end) {
    const lt = body.indexOf("<", p);
    if (lt < 0 || lt >= end) return { kind: "data" };

    if (body.startsWith("<!--", lt)) {
      const close = body.indexOf("-->", lt + 4);
      if (close < 0 || close + 3 > end) return { kind: "comment" };
      p = close + 3;
      continue;
    }
    if (body[lt + 1] === "!" || body[lt + 1] === "?") {
      const gt = body.indexOf(">", lt);
      if (gt < 0 || gt >= end) return { kind: "comment" };
      p = gt + 1;
      continue;
    }

    const m = /^<(\/?)([a-zA-Z][^\s/>]*)/.exec(body.slice(lt, lt + 64));
    if (!m) {
      p = lt + 1; // a literal "<" in text
      continue;
    }

    // Walk the attributes; a quote only opens a value straight after "=".
    let j = lt + m[0].length;
    let quote = "";
    let lastSig = "";
    while (j < body.length) {
      const c = body[j]!;
      if (quote) {
        if (c === quote) quote = "";
      } else if ((c === '"' || c === "'") && lastSig === "=") {
        quote = c;
      } else if (c === ">") {
        break;
      }
      if (!quote && !/\s/.test(c)) lastSig = c;
      j++;
    }
    if (j >= end) return { kind: "tag" };
    p = j + 1;

    const name = m[2]!.toLowerCase();
    if (m[1] === "" && RAW_TEXT.has(name)) {
      const closeRe = new RegExp(`</${name}(?=[\\s/>])`, "ig");
      closeRe.lastIndex = p;
      const close = closeRe.exec(body);
      if (!close || close.index >= end) return { kind: "raw", name };
      p = close.index;
    }
  }
  return { kind: "data" };
}

/** Parser state at every occurrence of `needle` in `body`. */
export function reflectionStates(body: string, needle: string): HtmlState[] {
  const states: HtmlState[] = [];
  for (let i = body.indexOf(needle); i >= 0 && states.length < 10; i = body.indexOf(needle, i + 1)) {
    states.push(htmlStateAt(body, i));
  }
  return states;
}

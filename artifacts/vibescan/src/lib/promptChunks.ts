/**
 * Splits the AI fix prompt into pieces that each fit comfortably on a PDF page.
 *
 * The prompt is one long piece of text, and the PDF paginates on block boundaries, so a single
 * block would either fit or be sliced through a sentence. Breaking it at blank lines (then at line
 * breaks, then as a last resort mid-line) lets a page end between paragraphs. Nothing is dropped
 * or reworded: joining the pieces gives the original text back.
 */
export function chunkPrompt(text: string, max = 1400): string[] {
  const clean = text.replace(/\r\n/g, "\n").trim();
  if (!clean) return [];

  const units: string[] = [];
  for (const para of clean.split(/\n{2,}/)) {
    if (para.length <= max) {
      units.push(para);
      continue;
    }
    // A paragraph longer than a piece: break it at line boundaries.
    let cur = "";
    for (const line of para.split("\n")) {
      if (line.length > max) {
        if (cur) units.push(cur);
        cur = "";
        // A single line longer than a piece (minified code, a long URL): hard-wrap it.
        for (let i = 0; i < line.length; i += max) units.push(line.slice(i, i + max));
        continue;
      }
      if (cur && cur.length + 1 + line.length > max) {
        units.push(cur);
        cur = line;
      } else {
        cur = cur ? `${cur}\n${line}` : line;
      }
    }
    if (cur) units.push(cur);
  }

  const out: string[] = [];
  let cur = "";
  for (const u of units) {
    if (cur && cur.length + 2 + u.length > max) {
      out.push(cur);
      cur = u;
    } else {
      cur = cur ? `${cur}\n\n${u}` : u;
    }
  }
  if (cur) out.push(cur);
  return out;
}

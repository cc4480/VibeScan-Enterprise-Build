import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { htmlToPlainText } from "./htmlToText";

/**
 * Every email this service sent was HTML-only — no text part at all — which is
 * a long-standing spam heuristic and renders as nothing in text-only clients.
 * These pin the two things that make the fallback worth having: that it keeps
 * the information the email exists to deliver, and that it cannot be bypassed
 * by a sender added later.
 */

describe("htmlToPlainText", () => {
  // The single most important case. Most of these emails exist to deliver ONE
  // link — verify your address, reset your password, read your report. A
  // converter that keeps the label and drops the href produces text that reads
  // fine and is useless.
  it("keeps link URLs, not just their labels", () => {
    const out = htmlToPlainText('<a href="https://secscan.us/verify?token=abc">Confirm email</a>');
    expect(out).toContain("https://secscan.us/verify?token=abc");
    expect(out).toContain("Confirm email");
  });

  it("does not print the URL twice when the label already is the URL", () => {
    const url = "https://secscan.us/r/1";
    const out = htmlToPlainText(`<a href="${url}">${url}</a>`);
    expect(out).toBe(url);
  });

  // A stylesheet's contents landing in the message body looks like obfuscation
  // to a spam filter — actively worse than having no text part.
  it("drops style and script contents entirely", () => {
    const out = htmlToPlainText(
      "<style>.x{color:red}</style><script>alert(1)</script><p>Real content</p>",
    );
    expect(out).toBe("Real content");
    expect(out).not.toContain("color:red");
    expect(out).not.toContain("alert");
  });

  it("turns block boundaries into line breaks instead of running text together", () => {
    const out = htmlToPlainText("<p>First</p><p>Second</p>");
    expect(out).toBe("First\nSecond");
  });

  it("handles <br> and headings", () => {
    expect(htmlToPlainText("<h1>Title</h1>a<br>b")).toBe("Title\na\nb");
  });

  it("decodes the entities these templates actually produce", () => {
    expect(htmlToPlainText("<p>Tom &amp; Jerry &quot;quoted&quot; &#39;x&#39; &mdash; end</p>")).toBe(
      `Tom & Jerry "quoted" 'x' — end`,
    );
    expect(htmlToPlainText("<p>a&nbsp;b</p>")).toBe("a b");
  });

  it("collapses the empty lines that table-based email markup leaves behind", () => {
    const out = htmlToPlainText("<table><tr><td>A</td></tr><tr><td>B</td></tr></table>");
    expect(out).not.toMatch(/\n\n\n/);
    expect(out).toContain("A");
    expect(out).toContain("B");
  });

  it("strips inline markup without eating the words around it", () => {
    expect(htmlToPlainText("You paid <strong>$29.00</strong> for <em>Deep Scan</em>.")).toBe(
      "You paid $29.00 for Deep Scan.",
    );
  });

  it("returns empty string for empty or markup-only input rather than throwing", () => {
    expect(htmlToPlainText("")).toBe("");
    expect(htmlToPlainText("<div></div>")).toBe("");
  });
});

describe("every outgoing email carries a text part", () => {
  // The regression this prevents is a NEW sender, added later, that builds a
  // payload with only `html`. resendBody derives the text part centrally for
  // exactly that reason, so what has to stay true is that senders go through
  // resendBody rather than hand-rolling a fetch body.
  const source = fs.readFileSync(path.join(process.cwd(), "src", "lib", "mailer.ts"), "utf-8");

  it("routes every Resend call through resendBody, which supplies the text part", () => {
    // Count the sends against the payload builders. A `body:` in a Resend fetch
    // that is not resendBody(...) is a sender that can ship HTML-only.
    const bodies = source.match(/body:\s*(\w+)\(/g) ?? [];
    const offenders = bodies.filter((b) => !/resendBody|JSON\.stringify/.test(b));
    expect(offenders).toEqual([]);
  });

  it("resendBody derives text from html when a caller supplies none", () => {
    expect(source).toMatch(/htmlToPlainText\(html\)/);
  });

  it("keeps a hand-written text body on the sign-in code email", () => {
    // The one a user reads when they cannot get into their account, often on a
    // phone with images disabled.
    expect(source).toMatch(/Your SecScan sign-in code is/);
  });
});

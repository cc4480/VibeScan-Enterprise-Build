import { describe, it, expect } from "vitest";
import { analyzeCsp, hasNosniff, findMixedContent } from "./headerAnalysis";

describe("analyzeCsp", () => {
  it("does not count 'unsafe-inline' that a nonce, hash or strict-dynamic neutralises", () => {
    expect(analyzeCsp("script-src 'nonce-abc123' 'unsafe-inline' https:").scriptUnsafeInline).toBe(false);
    expect(analyzeCsp("script-src 'sha256-AAAA=' 'unsafe-inline'").scriptUnsafeInline).toBe(false);
    expect(analyzeCsp("script-src 'strict-dynamic' 'unsafe-inline' https:").scriptUnsafeInline).toBe(false);
  });
  it("does not treat 'wasm-unsafe-eval' as unsafe-eval", () => {
    const v = analyzeCsp("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'");
    expect(v.scriptUnsafeEval).toBe(false);
    expect(v.scriptUnsafeInline).toBe(false);
  });
  it("still detects real weak policies, including via the default-src fallback", () => {
    expect(analyzeCsp("script-src 'self' 'unsafe-inline'").scriptUnsafeInline).toBe(true);
    expect(analyzeCsp("default-src 'self' 'unsafe-inline'").scriptUnsafeInline).toBe(true);
    expect(analyzeCsp("script-src 'self' 'unsafe-eval'").scriptUnsafeEval).toBe(true);
    // a nonce does not make eval safe
    expect(analyzeCsp("script-src 'nonce-x' 'unsafe-eval'").scriptUnsafeEval).toBe(true);
  });
  it("keeps style-only unsafe-inline separate from script", () => {
    const v = analyzeCsp("script-src 'self'; style-src 'self' 'unsafe-inline'");
    expect(v.scriptUnsafeInline).toBe(false);
    expect(v.styleUnsafeInline).toBe(true);
  });
  it("reads upgrade-insecure-requests", () => {
    expect(analyzeCsp("default-src 'self'; upgrade-insecure-requests").upgradeInsecureRequests).toBe(true);
    expect(analyzeCsp("default-src 'self'").upgradeInsecureRequests).toBe(false);
  });
});

describe("hasNosniff", () => {
  it("accepts a duplicated value from CDN plus origin", () => {
    expect(hasNosniff("nosniff, nosniff")).toBe(true);
    expect(hasNosniff("NoSniff")).toBe(true);
  });
  it("rejects absent or other values", () => {
    expect(hasNosniff(undefined)).toBe(false);
    expect(hasNosniff("sniff")).toBe(false);
  });
});

describe("findMixedContent", () => {
  it("finds real subresources", () => {
    const r = findMixedContent(`<script src="http://cdn.example.com/a.js"></script><img src='http://x.example/i.png'>`);
    expect(r.map((x) => [x.tag, x.active])).toEqual([["script", true], ["img", false]]);
  });
  it("ignores data-src, anchors, comments, inline script strings and loopback", () => {
    const html = `<img data-src="http://lazy.example/a.png"><a href="http://example.org/">x</a>
      <!-- <script src="http://old.example/x.js"></script> -->
      <script>var u = '<img src="http://tpl.example/a.png">'; var s = 'src="http://x.example"';</script>
      <link rel="canonical" href="http://example.com/"><script src="http://localhost:3000/dev.js"></script>`;
    expect(findMixedContent(html)).toEqual([]);
  });
  it("counts loading <link> elements", () => {
    expect(findMixedContent(`<link rel="stylesheet" href="http://c.example/s.css">`)).toHaveLength(1);
  });
});

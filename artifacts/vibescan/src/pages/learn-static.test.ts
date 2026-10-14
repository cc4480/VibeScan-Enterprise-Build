import { describe, it, expect } from "vitest";
import { renderLearnStatic } from "./learn-static";
import { learnStaticHtml } from "./learn-static-entry";
import { LEARN_CATEGORIES_A } from "./learn-data-a";
import { LEARN_CATEGORIES_B } from "./learn-data-b";
import { LEARN_CATEGORIES_C } from "./learn-data-c";
import type { Category } from "./learn-types";

const ALL = [...LEARN_CATEGORIES_A, ...LEARN_CATEGORIES_B, ...LEARN_CATEGORIES_C];

describe("renderLearnStatic", () => {
  it("renders every check on the page, with its text", () => {
    for (const cat of ALL) {
      expect(learnStaticHtml).toContain(`<h2>${cat.label.replace(/&/g, "&amp;")}</h2>`);
      for (const c of cat.checks) {
        expect(learnStaticHtml, c.id).toContain(`id="${c.id}"`);
        expect(learnStaticHtml, c.id).toContain("How to fix it");
      }
    }
    expect(learnStaticHtml.match(/<article /g)?.length).toBe(ALL.reduce((n, c) => n + c.checks.length, 0));
  });

  it("escapes markup so a check cannot inject HTML", () => {
    const cat = {
      id: "x", label: "<b>L</b>", description: "d", icon: () => null,
      checks: [{ id: "a", title: "T", shortTitle: "T", severity: "low", what: "<script>1</script>", why: "w", howTested: "h", fix: "f", fixCode: "</code><img src=x>" }],
    } as unknown as Category;
    const html = renderLearnStatic([cat]);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
  });
});

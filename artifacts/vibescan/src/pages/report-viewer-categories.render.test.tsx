import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CategorySection, GROUP_PAGE } from "./report-viewer-categories";

const finding = (i: number, severity = "medium") =>
  ({ id: `v${i}`, name: `Finding number ${i}`, severity, category: "Exposed Secrets / Credentials", description: "d", evidence: `File: f${i}.ts`, solution: "s", confidence: 80 }) as never;

describe("CategorySection", () => {
  it("draws the first page of an open group and offers the rest", () => {
    const html = renderToStaticMarkup(<CategorySection category="Exposed Secrets / Credentials" vulns={Array.from({ length: 60 }, (_, i) => finding(i))} globalIndex={0} />);
    expect(html).toContain("Finding number 0<");
    expect(html).toContain(`Finding number ${GROUP_PAGE - 1}<`);
    expect(html).not.toContain(`Finding number ${GROUP_PAGE}<`);
    expect(html).toContain(`Show ${GROUP_PAGE} more`);
    expect(html).toContain("Show all 60");
  });

  it("draws everything, with no button, when the group is one page or less", () => {
    const html = renderToStaticMarkup(<CategorySection category="Exposed Secrets / Credentials" vulns={Array.from({ length: GROUP_PAGE }, (_, i) => finding(i))} globalIndex={0} />);
    expect(html).toContain(`Finding number ${GROUP_PAGE - 1}<`);
    expect(html).not.toContain("more</button>");
  });
});

import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AgentFixPromptCard } from "./report-viewer-agents";

describe("AgentFixPromptCard with a hostile prompt", () => {
  const prompt = [
    "Please fix the following security findings in my web app (https://example.com).",
    "1. [high] <img src=x onerror=alert(1)>",
    "   How to fix it: [open](javascript:alert(1))",
  ].join("\n");

  it("shows the prompt as escaped text, not as markup", () => {
    const html = renderToStaticMarkup(<AgentFixPromptCard prompt={prompt} />);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toMatch(/href="javascript:/i);
  });

  it("tells the reader to review the prompt before pasting it", () => {
    const html = renderToStaticMarkup(<AgentFixPromptCard prompt={prompt} />);
    expect(html).toContain("Review this prompt before you paste it into an AI tool.");
  });
});

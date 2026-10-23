import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SubscriptionHeader } from "./monitor-card-header";

/** The header contains the pause button, which reads a query client even when only rendered. */
const render = (el: ReactElement) => renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{el}</QueryClientProvider>);

const HOSTILE_IMG = `<img src=x onerror=alert(1)>`;

const card = {
  cancelling: false,
  scanning: false,
  days: 30,
  isActive: true,
  isDown: false,
  handleScanNow: () => {},
  handleCancel: () => {},
  toggleDrawer: () => {},
} as never;

const sub = (targetUrl: string) =>
  ({
    id: "s1",
    targetUrl,
    lastPulseAt: null,
    responseTimeMs: null,
    regressionCount: 0,
    alertCount: 0,
    expiryApplies: false,
    status: "active",
  }) as never;

describe("SubscriptionHeader with hostile target URLs", () => {
  it("renders a javascript: target as text, not as a link", () => {
    const html = render(<SubscriptionHeader sub={sub("javascript:alert(1)")} card={card} />);
    expect(html).toContain("javascript:alert(1)");
    expect(html).not.toMatch(/href="javascript:/i);
    expect(html).not.toContain("<a ");
  });

  it("renders a data: target as text, not as a link", () => {
    const html = render(<SubscriptionHeader sub={sub("data:text/html,<script>alert(1)</script>")} card={card} />);
    expect(html).not.toMatch(/href="data:/i);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<a ");
  });

  it("does not create an img element from markup in the target", () => {
    const html = render(<SubscriptionHeader sub={sub(HOSTILE_IMG)} card={card} />);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("still links a valid https target", () => {
    const html = render(<SubscriptionHeader sub={sub("https://example.com/")} card={card} />);
    expect(html).toMatch(/<a [^>]*href="https:\/\/example\.com\/"/);
  });
});

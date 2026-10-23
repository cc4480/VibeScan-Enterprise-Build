import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { QuietHoursSection } from "./quiet-hours-section";
import { MonitorIntervalSelect } from "./monitor-interval-select";

const render = (el: ReactElement) => renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{el}</QueryClientProvider>);
const noop = () => {};

describe("QuietHoursSection", () => {
  it("is off with no pickers when there is no window, and says what still gets through", () => {
    const html = render(<QuietHoursSection value={null} saving={false} onChange={noop} />);
    expect(html).toContain('aria-checked="false"');
    expect(html).not.toContain("Quiet hours start");
    expect(html).toMatch(/critical finding/);
    expect(html).toMatch(/certificate/);
    expect(html).toMatch(/going down/);
  });

  it("shows the saved window and zone", () => {
    const html = render(<QuietHoursSection value={{ start: 22, end: 7, timezone: "Europe/London" }} saving={false} onChange={noop} />);
    expect(html).toContain('aria-checked="true"');
    expect(html).toMatch(/<option value="22" selected[^>]*>22:00/);
    expect(html).toMatch(/<option value="7" selected[^>]*>07:00/);
    expect(html).toMatch(/<option value="Europe\/London" selected/);
  });

  it("warns when the two hours are the same instead of saving a window that does nothing", () => {
    const html = render(<QuietHoursSection value={{ start: 5, end: 5, timezone: "UTC" }} saving={false} onChange={noop} />);
    expect(html).toContain("Pick two different hours");
  });

  it("locks the controls while saving", () => {
    const html = render(<QuietHoursSection value={{ start: 22, end: 7, timezone: "UTC" }} saving onChange={noop} />);
    expect(html.match(/disabled/g)?.length).toBeGreaterThanOrEqual(4);
  });
});

describe("MonitorIntervalSelect", () => {
  const sub = (scanIntervalDays: number | null) => ({ id: "s1", targetUrl: "https://a.example/", scanIntervalDays }) as never;

  it("defaults to automatic and offers exactly the four intervals", () => {
    const html = render(<MonitorIntervalSelect sub={sub(null)} />);
    expect(html).toMatch(/<option value="auto" selected/);
    for (const d of [3, 7, 14, 30]) expect(html).toContain(`value="${d}"`);
    expect((html.match(/<option/g) ?? []).length).toBe(5);
  });

  it("shows the chosen interval", () => {
    expect(render(<MonitorIntervalSelect sub={sub(14)} />)).toMatch(/<option value="14" selected/);
  });
});

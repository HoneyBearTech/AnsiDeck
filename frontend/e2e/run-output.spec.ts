import { expect, test } from "@playwright/test";

import { resolve } from "../src/test/api-routes";
import { run } from "../src/test/fixtures";
import { baseRoutes } from "../src/test/pages";

// A run's output as the viewer keeps it: in chunks, added once per frame. Every line must show,
// once and in order, across chunk boundaries and however fast lines arrive.
const LINES = 1001;

test("every line of a run's output shows once, in order", async ({ page }) => {
  const table = { ...baseRoutes(), "GET /runs/:id": run({ status: "success" }) };
  await page.addInitScript(() => localStorage.setItem("ansideck.activeProject", "1"));
  await page.routeWebSocket(/\/api\/runs\/\d+\/ws/, (ws) => {
    for (let i = 1; i <= LINES; i++) {
      ws.send(JSON.stringify({ counter: i, stdout: `ok: [host-${i}] => line ${i}` }));
    }
    ws.close({ code: 1000 });
  });
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const resolved = await resolve(table, {
      method: request.method(),
      path: url.pathname.replace(/^\/api/, ""),
      query: url.searchParams,
      body: request.postDataJSON() as unknown,
    });
    await route.fulfill(
      resolved ? { status: resolved.status, json: resolved.body } : { status: 404, json: {} },
    );
  });

  await page.goto("/runs/1");
  const lines = page.locator("div.whitespace-pre-wrap");
  await expect(lines).toHaveCount(LINES);
  const texts = await lines.allTextContents();
  expect(texts.every((text, i) => text === `ok: [host-${i + 1}] => line ${i + 1}`)).toBe(true);
  await expect(page.getByText("This run produced no output.")).toHaveCount(0);
});

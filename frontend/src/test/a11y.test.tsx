import { waitFor } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it } from "vitest";

import { CATALOG, credential, gitSource, inventory, playbook, run, runTemplate, targets, vaultPassword } from "./fixtures";
import { renderApp } from "./render";

// Enough data for every page to render its full content.
const ROUTES = {
  "GET /playbooks": [playbook()],
  "GET /playbooks/:id": playbook(),
  "GET /inventories": [inventory()],
  "GET /inventories/:id": inventory(),
  "GET /inventories/:id/sources": [],
  "GET /inventories/:id/targets": targets(),
  "GET /inventories/:id/snapshot": null,
  "GET /credentials": [credential()],
  "GET /vault-passwords": [vaultPassword()],
  "GET /runs": [run()],
  "GET /runs/:id": run(),
  "GET /run-templates": [runTemplate(), runTemplate({ id: 4, name: "Broken", missing: ["credential"] })],
  "GET /projects": [{ id: 1, name: "Default", description: null, created_at: "2026-10-05T12:00:00Z", my_role: "admin" }],
  "GET /projects/:id/git-sources": [gitSource()],
  "GET /users": [],
  "GET /audit": { items: [], total: 0 },
  "GET /workers": [],
  "GET /secret-store/status": { enabled: false, label: "OpenBao", url: null, ok: null, reachable: null, sealed: null, version: null, token_ttl: null, error_kind: null, error: null, checked_at: null, last_ok_at: null },
  "GET /notifications/catalog": CATALOG,
  "GET /notifications/channels": [],
  "GET /projects/:id/notifications/channels": [],
  "GET /galaxy/requirements": { content: "" },
  "GET /galaxy/installed": { collections: [], roles: [] },
  "GET /galaxy/installs": [],
};

const PAGES: [string, string][] = [
  ["/", "Dashboard"],
  ["/account", "Account"],
  ["/playbooks", "Playbooks"],
  ["/playbooks/1", "Edit Playbook"],
  ["/inventories", "Inventories"],
  ["/inventories/1", "lab"],
  ["/credentials", "Credentials"],
  ["/vault", "Vault"],
  ["/galaxy", "Galaxy"],
  ["/runs", "Runs"],
  ["/runs/new", "New Run"],
  ["/runs/7", "site.yml → lab"],
  ["/templates", "Run templates"],
  ["/users", "Users"],
  ["/audit", "Audit log"],
  ["/workers", "Workers"],
  ["/notifications", "Notifications"],
  ["/projects", "Projects"],
];

async function violations(container: HTMLElement) {
  const result = await axe.run(container, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    // jsdom has no layout or colours; contrast is checked in a real browser instead.
    rules: { "color-contrast": { enabled: false } },
  });
  return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

describe("accessibility (axe)", () => {
  it.each(PAGES)("%s has no violations", async (path, heading) => {
    const { screen } = renderApp(path, { routes: ROUTES });
    await screen.findByRole("heading", { level: 1, name: heading });
    expect(await violations(document.body)).toEqual([]);
  });

  it("the login page has no violations", async () => {
    const { screen } = renderApp("/login", { user: null });
    await screen.findByRole("heading", { level: 1, name: "AnsiDeck" });
    expect(await violations(document.body)).toEqual([]);
  });
});

describe("keyboard", () => {
  it("returns focus to the button that opened a dialog, also without a DialogTrigger", async () => {
    const { user, screen } = renderApp("/notifications", { routes: ROUTES });
    const opener = (await screen.findAllByRole("button", { name: "New channel" }))[0]!;
    opener.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(opener).toHaveFocus());
  });
});

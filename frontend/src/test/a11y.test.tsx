import { waitFor } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it } from "vitest";

import { adminUser, FQCN_FINDING, lintJob } from "./fixtures";
import { PAGE_ROUTES as ROUTES, PAGES } from "./pages";
import { renderApp } from "./render";

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

  it("a playbook with check results has no violations", async () => {
    const { screen, user } = renderApp("/playbooks/1", {
      routes: {
        ...ROUTES,
        "POST /playbooks/lint": lintJob({
          findings: [FQCN_FINDING, { ...FQCN_FINDING, level: "warning", path: "roles/x/tasks/main.yml", in_target: false }],
          total: 2,
        }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Check" }));
    await screen.findByRole("heading", { level: 2, name: "Check results" });
    expect(await violations(document.body)).toEqual([]);
  });

  it("the login page has no violations", async () => {
    const { screen } = renderApp("/login", { user: null });
    await screen.findByRole("heading", { level: 1, name: "AnsiDeck" });
    expect(await violations(document.body)).toEqual([]);
  });

  it("the required two-factor setup has no violations", async () => {
    const { screen } = renderApp("/", { user: adminUser({ two_factor_setup_required: true }), routes: ROUTES });
    await screen.findByRole("heading", { level: 1, name: "Set up two-factor login" });
    await screen.findByText("Work laptop");
    expect(await violations(document.body)).toEqual([]);
  });

  it("the second sign-in step has no violations", async () => {
    const { screen, user } = renderApp("/login", {
      user: null,
      routes: { "POST /auth/login": { mfa_required: true, methods: ["totp", "recovery_code"] } },
    });
    await user.type(await screen.findByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "pw");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByLabelText("Authentication code");
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

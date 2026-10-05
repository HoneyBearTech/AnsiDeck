import { within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser, playbook, run, viewerUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const DASHBOARD = {
  "GET /playbooks": [playbook()],
  "GET /inventories": [],
  "GET /credentials": [],
  "GET /runs": [run(), run({ id: 8 })],
  "GET /run-templates": [],
};

describe("sign-in", () => {
  it("sends a signed-out visitor to the login page and signs them in", async () => {
    const { api, user, screen } = renderApp("/runs", { user: null, routes: DASHBOARD });
    await screen.findByText("Sign in to run playbooks against your infrastructure.");
    api.set({ "POST /auth/login": adminUser(), "GET /auth/me": adminUser() });

    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "s3cret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    // Signing in lands on the dashboard.
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeInTheDocument();
    expect(api.requests("POST /auth/login")[0]?.body).toEqual({ username: "admin", password: "s3cret" });
  });

  it("shows the server's reason when the password is wrong", async () => {
    const { user, screen } = renderApp("/login", {
      user: null,
      routes: { "POST /auth/login": reply(401, { detail: "Invalid username or password" }) },
    });
    await user.type(await screen.findByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "nope");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid username or password")).toBeInTheDocument();
  });

  it("asks for a second factor, and accepts a recovery code instead", async () => {
    const { api, user, screen } = renderApp("/login", {
      user: null,
      routes: { "POST /auth/login": { mfa_required: true }, ...DASHBOARD },
    });
    await user.type(await screen.findByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "s3cret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByText("Two-factor login is on for this account.");
    await user.click(screen.getByRole("button", { name: /recovery code/i }));
    api.set({ "POST /auth/login/mfa": adminUser(), "GET /auth/me": adminUser() });
    await user.type(screen.getByLabelText("Recovery code"), "abcde-12345");
    await user.click(screen.getByRole("button", { name: /verify|sign in|continue/i }));

    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    expect(api.requests("POST /auth/login/mfa")[0]?.body).toEqual({ recovery_code: "abcde-12345" });
  });

  it("offers the configured single sign-on providers and explains SSO errors", async () => {
    const { screen } = renderApp("/login?sso_error=not_linked", {
      user: null,
      routes: {
        "GET /auth/providers": { oidc: { enabled: true, label: "Keycloak" }, github: { enabled: true, label: "GitHub" } },
      },
    });
    expect(await screen.findByRole("button", { name: "Sign in with Keycloak" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in with GitHub" })).toBeInTheDocument();
    expect(screen.getByText(/No AnsiDeck account is linked/)).toBeInTheDocument();
  });
});

describe("dashboard", () => {
  it("shows what's running, recent failures, the latest runs and linked counts", async () => {
    const { api, screen } = renderApp("/", {
      routes: {
        ...DASHBOARD,
        "GET /runs": ({ query }: { query: URLSearchParams }) => {
          const status = query.getAll("status");
          if (status.includes("running")) return [run({ id: 10, status: "running", finished_at: null })];
          if (status.includes("failed")) return [run({ id: 9, status: "failed" })];
          return [run(), run({ id: 8 })];
        },
      },
    });
    const running = await screen.findByRole("region", { name: "Running now" });
    expect(await within(running).findByText("#10")).toBeInTheDocument();
    expect(await within(screen.getByRole("region", { name: "Recent failures" })).findByText("#9")).toBeInTheDocument();
    const latest = screen.getByRole("region", { name: "Latest runs" });
    expect(await within(latest).findByText("#8")).toBeInTheDocument();
    expect(within(latest).getByRole("link", { name: "All runs" })).toHaveAttribute("href", "/runs");
    expect(screen.getByRole("link", { name: /Playbooks\s*1/ })).toHaveAttribute("href", "/playbooks");
    expect(screen.getByRole("link", { name: "New run" })).toHaveAttribute("href", "/runs/new");
    const requests = api.requests("GET /runs").map((r) => r.query.toString());
    expect(requests).toEqual(expect.arrayContaining(["project_id=1&status=failed&status=timed_out&limit=5", "project_id=1&limit=8", "project_id=1&status=queued&status=running&limit=20"]));
  });

  it("says when nothing is running or failed, and when the API is unreachable", async () => {
    const { screen } = renderApp("/", { user: viewerUser(), routes: { ...DASHBOARD, "GET /runs": [] } });
    expect(await screen.findByText("Nothing is running or waiting to run.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "New run" })).not.toBeInTheDocument();
    const broken = renderApp("/", { routes: { ...DASHBOARD, "GET /runs": reply(502) } });
    expect(await broken.screen.findByRole("alert")).toHaveTextContent("couldn't be reached");
  });
});

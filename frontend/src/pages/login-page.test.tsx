import { describe, expect, it } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser, playbook, run } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const DASHBOARD = {
  "GET /playbooks": [playbook()],
  "GET /inventories": [],
  "GET /credentials": [],
  "GET /runs": [run(), run({ id: 8 })],
};

describe("sign-in", () => {
  it("sends a signed-out visitor to the login page and signs them in", async () => {
    const { api, user, screen } = renderApp("/runs", { user: null, routes: DASHBOARD });
    await screen.findByText("Sign in to run playbooks against your infrastructure.");
    api.set({ "POST /auth/login": adminUser(), "GET /auth/me": adminUser() });

    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "s3cret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Runs", { selector: "h3" })).toBeInTheDocument();
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

    await screen.findByText("ok");
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
  it("shows backend health and counts", async () => {
    const { screen } = renderApp("/", { routes: DASHBOARD });
    expect(await screen.findByText("ok")).toBeInTheDocument();
    expect(await screen.findByText("2")).toBeInTheDocument(); // runs
  });

  it("says when the backend is unreachable", async () => {
    const { screen } = renderApp("/", { routes: { ...DASHBOARD, "GET /health": reply(502) } });
    expect(await screen.findByText("Backend unreachable")).toBeInTheDocument();
  });
});

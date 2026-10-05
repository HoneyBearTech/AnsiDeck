import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser, adminUserRow, project, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

const ALICE = adminUserRow({ id: 2, username: "alice", role: "operator", email: "alice@example.com", created_by: "admin", sso_linked: true, sso_provider: "Keycloak", totp_enabled: true });
const BOB = adminUserRow({ id: 3, username: "bob", role: "viewer", is_active: false });
const ROUTES = {
  "GET /users": [adminUserRow(), ALICE, BOB],
  "PATCH /users/:id": ALICE,
  "DELETE /users/:id": reply(204),
  "DELETE /users/:id/sso-link": reply(204),
  "DELETE /users/:id/totp": reply(204),
};

describe("users", () => {
  it("lists users with their state, and keeps your own row safe", async () => {
    const { screen } = renderApp("/users", { routes: ROUTES });
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("you")).toBeInTheDocument();
    expect(screen.getByText("deactivated")).toBeInTheDocument();
    expect(screen.getByText("Keycloak")).toBeInTheDocument();
    expect(screen.getByText(/alice@example.com · Created .* by admin/)).toBeInTheDocument();
    expect(screen.getByLabelText("Role of admin")).toBeDisabled();
    expect(screen.getByRole("link", { name: "Change password" })).toHaveAttribute("href", "/account");
  });

  it("creates a user into the active project, or a global admin", async () => {
    const { api, user, screen } = renderApp("/users", {
      user: adminUser({ projects: [project(), project({ id: 2, name: "Ops" })] }),
      routes: { ...ROUTES, "POST /users": ALICE },
    });
    await user.click(await screen.findByRole("button", { name: "New User" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Username"), "carol");
    await user.type(dialog.getByLabelText("Initial password"), "short");
    expect(dialog.getByRole("button", { name: "Create" })).toBeDisabled();
    await user.type(dialog.getByLabelText("Initial password"), "-but-long-now");
    await user.type(dialog.getByLabelText("Email (optional)"), "carol@example.com");
    await choose(user, dialog.getByLabelText("Role"), "operator");
    expect(dialog.getByText(/Edit playbooks\/inventories and trigger runs/)).toBeInTheDocument();
    await choose(user, dialog.getByLabelText("Add to project"), "Ops");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    await screen.findByText("alice");
    expect(api.requests("POST /users")[0]?.body).toEqual({
      username: "carol",
      password: "short-but-long-now",
      role: "operator",
      project_id: 2,
      email: "carol@example.com",
    });

    api.set({ "POST /users": reply(409, { detail: "Username taken" }) });
    await user.click(screen.getByRole("button", { name: "New User" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Username"), "alice");
    await user.type(dialog.getByLabelText("Initial password"), "a-long-password");
    await choose(user, dialog.getByLabelText("Role"), "admin");
    expect(dialog.queryByLabelText("Add to project")).not.toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("Username taken")).toBeInTheDocument();
    // No project for a global admin, no email: both left out.
    expect(api.requests("POST /users")[1]?.body).toEqual({ username: "alice", password: "a-long-password", role: "admin" });
  });

  it("changes roles, emails and passwords, and shows refusals", async () => {
    const { api, user, screen } = renderApp("/users", { routes: ROUTES });
    await choose(user, await screen.findByLabelText("Role of alice"), "viewer");
    expect(api.requests("PATCH /users/2")[0]?.body).toEqual({ role: "viewer" });

    await user.click(screen.getAllByRole("button", { name: "Email" })[1]!);
    let dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText("Email address")).toHaveValue("alice@example.com");
    await user.clear(dialog.getByLabelText("Email address"));
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByText("alice");
    expect(api.requests("PATCH /users/2")[1]?.body).toEqual({ email: null });

    await user.click(screen.getAllByRole("button", { name: "Reset password" })[0]!);
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("New password"), "another-long-password");
    await user.click(dialog.getByRole("button", { name: "Reset" }));
    await screen.findByText("alice");
    expect(api.requests("PATCH /users/2")[2]?.body).toEqual({ password: "another-long-password" });

    api.set({ "PATCH /users/:id": reply(400, { detail: "Email already used" }) });
    await user.click(screen.getAllByRole("button", { name: "Email" })[2]!);
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Email address"), "alice@example.com");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("Email already used")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await user.click(screen.getAllByRole("button", { name: "Reset password" })[1]!);
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("New password"), "another-long-password");
    await user.click(dialog.getByRole("button", { name: "Reset" }));
    expect(await dialog.findByText("Email already used")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await user.click(screen.getByRole("button", { name: "Activate" }));
    expect(await screen.findByText("Email already used")).toBeInTheDocument();
  });

  it("unlinks SSO, resets 2FA, deactivates and deletes after confirming", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const { api, user, screen } = renderApp("/users", { routes: ROUTES });
    await user.click(await screen.findByRole("button", { name: "Unlink SSO" }));
    await user.click(screen.getByRole("button", { name: "Reset 2FA" }));
    await user.click(screen.getAllByRole("button", { name: "Delete" })[0]!);
    expect(api.calls.filter((c) => c.method === "DELETE")).toHaveLength(0);

    confirm.mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Unlink SSO" }));
    await user.click(screen.getByRole("button", { name: "Reset 2FA" }));
    await user.click(screen.getAllByRole("button", { name: "Delete" })[0]!);
    await user.click(screen.getByRole("button", { name: "Deactivate" }));
    expect(api.requests("DELETE /users/2/sso-link")).toHaveLength(1);
    expect(api.requests("DELETE /users/2/totp")).toHaveLength(1);
    expect(api.requests("DELETE /users/2")).toHaveLength(1);
    expect(api.requests("PATCH /users/2").at(-1)?.body).toEqual({ is_active: false });
  });

  it("is only for user managers", async () => {
    const { screen } = renderApp("/users", { user: viewerUser(), routes: ROUTES });
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
  });
});

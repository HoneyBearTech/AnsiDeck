import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser, project, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

function summary(overrides = {}) {
  return {
    id: 1,
    name: "Default",
    description: "Everything",
    created_at: "2026-10-05T12:00:00Z",
    my_role: "admin",
    ...overrides,
  };
}

function apiKey(overrides = {}) {
  return {
    id: 1,
    name: "ci-deploy",
    preset: "trigger",
    prefix: "1a2b3c4d",
    created_by: "admin",
    created_at: "2026-10-05T12:00:00Z",
    expires_at: "2027-01-03T12:00:00Z",
    last_used_at: null,
    last_used_ip: null,
    revoked_at: null,
    status: "active",
    ...overrides,
  };
}

const MEMBERS = [
  { user_id: 1, username: "admin", is_active: true, role: "admin" },
  { user_id: 2, username: "alice", is_active: false, role: "operator" },
];

describe("projects", () => {
  it("creates, renames and deletes projects as a global admin", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/projects", {
      routes: {
        "GET /projects": [summary()],
        "POST /projects": summary({ id: 2, name: "Ops" }),
        "PATCH /projects/:id": summary({ name: "Main" }),
        "DELETE /projects/:id": reply(409, { detail: "The project still has playbooks" }),
      },
    });
    expect(await screen.findByText("Everything")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "New project" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "Ops");
    await user.type(dialog.getByLabelText("Description"), "Operations");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByText("Everything");
    expect(api.requests("POST /projects")[0]?.body).toEqual({ name: "Ops", description: "Operations" });
    expect(api.requests("GET /auth/me").length).toBeGreaterThan(1);

    await user.click(screen.getByRole("button", { name: "Rename" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.clear(dialog.getByLabelText("Name"));
    await user.type(dialog.getByLabelText("Name"), "Main");
    api.set({ "PATCH /projects/:id": reply(409, { detail: "Name taken" }) });
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("Name taken")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    confirm.mockReturnValueOnce(false);
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(api.requests("DELETE /projects/1")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("The project still has playbooks")).toBeInTheDocument();
  });

  it("manages members", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/projects", {
      routes: {
        "GET /projects": [summary()],
        "GET /projects/:id/members": MEMBERS,
        "POST /projects/:id/members": MEMBERS[1],
        "PUT /projects/:id/members/:uid": MEMBERS[1],
        "DELETE /projects/:id/members/:uid": reply(204),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Members" }));
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("deactivated")).toBeInTheDocument();
    expect(screen.getByLabelText("Role of admin")).toBeEnabled(); // a global admin may change their own

    await choose(user, screen.getByLabelText("Role of alice"), "viewer");
    expect(api.requests("PUT /projects/1/members/2")[0]?.body).toEqual({ role: "viewer" });
    await user.click(screen.getAllByRole("button", { name: "Remove" })[1]!);
    expect(api.requests("DELETE /projects/1/members/2")).toHaveLength(1);

    await user.type(screen.getByLabelText("Add an existing user"), " bob ");
    await choose(user, screen.getByLabelText("Role for the new member"), "operator");
    expect(screen.getByText(/Edits playbooks and inventories, triggers runs/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(api.requests("POST /projects/1/members")[0]?.body).toEqual({ username: "bob", role: "operator" });
    expect(await screen.findByLabelText("Add an existing user")).toHaveValue("");

    api.set({ "POST /projects/:id/members": reply(404, { detail: "No such user" }) });
    await user.type(screen.getByLabelText("Add an existing user"), "nobody");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText("No such user")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Hide members" }));
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
  });

  it("locks a project admin's own membership, and shows member load errors", async () => {
    const projectAdmin = viewerUser({
      username: "admin",
      role: "viewer",
      projects: [project({ role: "admin", permissions: ["content:read", "members:manage"] })],
    });
    const { screen, user } = renderApp("/projects", {
      user: projectAdmin,
      routes: { "GET /projects": [summary()], "GET /projects/:id/members": MEMBERS },
    });
    await user.click(await screen.findByRole("button", { name: "Members" }));
    expect(await screen.findByLabelText("Role of admin")).toBeDisabled();
    expect(screen.getAllByRole("button", { name: "Remove" })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "New project" })).not.toBeInTheDocument();
  });

  it("creates an API key, shows it once, copies it and revokes keys", async () => {
    const { api, user, screen } = renderApp("/projects", {
      routes: {
        "GET /projects": [summary()],
        "GET /projects/:id/api-keys": [
          apiKey(),
          apiKey({ id: 2, name: "old", status: "revoked", last_used_at: "2026-10-01T00:00:00Z" }),
        ],
        "POST /projects/:id/api-keys": {
          ...apiKey({ id: 3, name: "ci-read", preset: "read-only" }),
          token: "ansd_1a2b3c4d_secret",
        },
        "DELETE /projects/:id/api-keys/:kid": reply(204),
      },
    });
    await user.click(await screen.findByRole("button", { name: "API keys" }));
    expect(await screen.findAllByText("ansd_1a2b3c4d_…")).toHaveLength(2); // only the public prefix
    expect(screen.getByText("revoked")).toBeInTheDocument();

    await user.type(screen.getByLabelText("New API key"), "bad name");
    expect(screen.getByRole("button", { name: "Create key" })).toBeDisabled();
    await user.clear(screen.getByLabelText("New API key"));
    await user.type(screen.getByLabelText("New API key"), "ci-read");
    await choose(user, screen.getByLabelText("Key permissions"), "read-only");
    expect(screen.getByText(/Cannot start runs/)).toBeInTheDocument();
    await choose(user, screen.getByLabelText("Key lifetime"), "1 year");
    expect(screen.getByRole("button", { name: "Create key" })).toBeDisabled(); // no password yet
    expect(screen.getByText(/creating one asks for your password/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Current password"), "my-password");
    await user.click(screen.getByRole("button", { name: "Create key" }));

    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByTestId("new-api-key")).toHaveTextContent("ansd_1a2b3c4d_secret");
    expect(dialog.getByText(/can read runs in Default/)).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("ansd_1a2b3c4d_secret");
    expect(dialog.getByRole("button", { name: "Copied" })).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Done" }));
    expect(screen.queryByText("ansd_1a2b3c4d_secret")).not.toBeInTheDocument();
    expect(api.requests("POST /projects/1/api-keys")[0]?.body).toEqual({
      name: "ci-read",
      preset: "read-only",
      expires_in_days: 365,
      current_password: "my-password",
    });
    expect(screen.getByLabelText("Current password")).toHaveValue(""); // not kept around

    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    expect(api.requests("DELETE /projects/1/api-keys/1")).toHaveLength(0);
    confirm.mockReturnValue(true);
    api.set({ "DELETE /projects/:id/api-keys/:kid": reply(404, { detail: "Already revoked" }) });
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    expect(await screen.findByText("Already revoked")).toBeInTheDocument();
  });

  it("shows API key errors and a failed copy", async () => {
    const { api, user, screen } = renderApp("/projects", {
      routes: {
        "GET /projects": [summary({ my_role: null })],
        "GET /projects/:id/api-keys": [],
        "POST /projects/:id/api-keys": reply(400, { detail: "Too many keys" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "API keys" }));
    expect(await screen.findByText("No API keys yet.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("New API key"), "ci");
    await user.type(screen.getByLabelText("Current password"), "pw");
    await user.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByText("Too many keys")).toBeInTheDocument();

    api.set({ "POST /projects/:id/api-keys": { ...apiKey(), token: "ansd_x_y" } });
    await user.click(screen.getByRole("button", { name: "Create key" }));
    const dialog = within(await screen.findByRole("dialog"));
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    await user.click(dialog.getByRole("button", { name: "Copy" }));
    expect(await screen.findByText(/Couldn't copy automatically/)).toBeInTheDocument();
  });
  it("needs no password right after an SSO sign-in", async () => {
    const { api, user, screen } = renderApp("/projects", {
      user: adminUser({ signed_in_with: "sso" }),
      routes: {
        "GET /projects": [summary()],
        "GET /projects/:id/api-keys": [],
        "POST /projects/:id/api-keys": { ...apiKey(), token: "ansd_1a2b3c4d_secret" },
      },
    });
    await user.click(await screen.findByRole("button", { name: "API keys" }));
    expect(await screen.findByText(/Signed in with single sign-on/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("New API key"), "ci");
    await user.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(api.requests("POST /projects/1/api-keys")[0]?.body).toEqual({
      name: "ci",
      preset: "trigger",
      expires_in_days: 90,
    });
  });

  it("shows why a key is suspended and lets admins revoke it", async () => {
    const reason = "creator deactivated";
    const { api, user, screen } = renderApp("/projects", {
      routes: {
        "GET /projects": [summary()],
        "GET /projects/:id/api-keys": [apiKey({ status: "suspended", suspended_because: reason })],
        "DELETE /projects/:id/api-keys/:kid": reply(204),
      },
    });
    await user.click(await screen.findByRole("button", { name: "API keys" }));
    expect(await screen.findByText("suspended")).toBeInTheDocument();
    expect(screen.getByText(`Not working: ${reason}.`)).toBeInTheDocument();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    expect(api.requests("DELETE /projects/1/api-keys/1")).toHaveLength(1);
  });
});

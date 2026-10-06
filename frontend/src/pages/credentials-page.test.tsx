import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { credential, viewerUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const STORE = {
  "GET /secret-store/info": {
    enabled: true,
    label: "OpenBao",
    base_path: "secret/ansideck/1/",
    path_rules: "letters, digits, - and _",
  },
};

describe("credentials", () => {
  it("lists credentials with their kind, variables and secret store location", async () => {
    const { screen } = renderApp("/credentials", {
      routes: {
        ...STORE,
        "GET /credentials": [
          credential({ description: "Deploys the web tier" }),
          credential({ id: 2, name: "netbox", kind: "env", env_names: ["NETBOX_TOKEN", "NETBOX_URL"] }),
          credential({ id: 3, name: "vaulted", store: "external", store_location: "secret/ansideck/1/web" }),
        ],
      },
    });
    expect(await screen.findByText("Deploys the web tier")).toBeInTheDocument();
    expect(screen.getByText("NETBOX_TOKEN · NETBOX_URL")).toBeInTheDocument();
    expect(screen.getByText("secret/ansideck/1/web")).toBeInTheDocument();
    expect(screen.getAllByText("Environment variables")).toHaveLength(1);
  });

  it("creates an SSH key credential, uploading the key from a file", async () => {
    const { api, user, screen } = renderApp("/credentials", {
      routes: { "GET /credentials": [], "POST /credentials": credential() },
    });
    await screen.findByText("No credentials yet.");
    await user.click(screen.getByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "deploy-key");
    await user.type(dialog.getByLabelText("Description"), "web tier");
    const key = new File(["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"], "id_ed25519");
    await user.upload(dialog.getByLabelText("Upload private key file"), key);
    expect(dialog.getByLabelText("Private key (PEM)")).toHaveValue("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n");

    api.set({ "GET /credentials": [credential()] });
    await user.click(dialog.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("deploy-key")).toBeInTheDocument();
    expect(api.requests("POST /credentials")[0]?.body).toMatchObject({
      name: "deploy-key",
      description: "web tier",
      private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
    });
  });

  it("creates an environment-variable credential with several rows", async () => {
    const { api, user, screen } = renderApp("/credentials", {
      routes: { "GET /credentials": [], "POST /credentials": credential({ kind: "env" }) },
    });
    await user.click(await screen.findByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "netbox");
    await user.click(dialog.getByRole("button", { name: "Environment variables" }));
    expect(dialog.getByRole("button", { name: "Environment variables" })).toHaveAttribute("aria-pressed", "true");
    await user.type(dialog.getByLabelText("Variable 1 name"), "netbox_token");
    await user.type(dialog.getByLabelText("Variable 1 value"), "t0ken");
    await user.click(dialog.getByRole("button", { name: "Add variable" }));
    await user.type(dialog.getByLabelText("Variable 2 name"), "EXTRA");
    await user.type(dialog.getByLabelText("Variable 2 value"), "x");
    await user.click(dialog.getByRole("button", { name: "Remove variable 2" }));
    await user.click(dialog.getByRole("button", { name: "Create" }));

    await screen.findByText("No credentials yet.");
    expect(api.requests("POST /credentials")[0]?.body).toMatchObject({
      name: "netbox",
      kind: "env",
      env: { NETBOX_TOKEN: "t0ken" },
    });
  });

  it("references a key in the secret store and tests that it can be read", async () => {
    const { api, user, screen } = renderApp("/credentials", {
      routes: {
        ...STORE,
        "GET /credentials": [],
        "POST /credentials": credential({ store: "external" }),
        "POST /credentials/:id/check": { ok: true, version: 3, error_kind: null, error: null },
      },
    });
    await user.click(await screen.findByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "vaulted");
    await user.click(dialog.getByRole("button", { name: "In OpenBao" }));
    await user.type(dialog.getByLabelText("Path in OpenBao"), "web/ssh");
    await user.clear(dialog.getByLabelText("Key in that secret"));
    await user.type(dialog.getByLabelText("Key in that secret"), "key");
    api.set({
      "GET /credentials": [credential({ id: 4, name: "vaulted", store: "external", store_location: "secret/ansideck/1/web/ssh" })],
    });
    await user.click(dialog.getByRole("button", { name: "Create" }));

    expect(api.requests("POST /credentials")[0]?.body).toMatchObject({ store_path: "web/ssh", store_key: "key" });
    await user.click(await screen.findByRole("button", { name: "Test" }));
    expect(await screen.findByText("Readable (version 3)")).toBeInTheDocument();
  });

  it("shows why a stored secret can't be read, and why a create was refused", async () => {
    const { user, screen } = renderApp("/credentials", {
      routes: {
        ...STORE,
        "GET /credentials": [credential({ store: "external", store_location: "secret/x" })],
        "POST /credentials/:id/check": { ok: false, version: null, error_kind: "missing", error: "No such secret" },
        "POST /credentials": reply(409, { detail: "A credential with that name exists" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Test" }));
    expect(await screen.findByText("No such secret")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "deploy-key");
    await user.type(dialog.getByLabelText("Private key (PEM)"), "key");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("A credential with that name exists")).toBeInTheDocument();
  });

  it("deletes a credential", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/credentials", {
      routes: { "GET /credentials": [credential()], "DELETE /credentials/:id": reply(204) },
    });
    await screen.findByText("deploy-key");
    api.set({ "GET /credentials": [] });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await screen.findByText("No credentials yet.");
    expect(api.requests("DELETE /credentials/1")).toHaveLength(1);
  });

  it("asks before deleting, and shows why a delete was refused", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const { api, user, screen } = renderApp("/credentials", {
      routes: {
        "GET /credentials": [credential()],
        "DELETE /credentials/:id": reply(409, { detail: "Git source 'infra' uses this key as its deploy key" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("deleted for good and can't be recovered"));
    expect(api.requests("DELETE /credentials/1")).toHaveLength(0);

    confirm.mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Git source 'infra' uses this key as its deploy key")).toBeInTheDocument();
    expect(screen.getByText("deploy-key")).toBeInTheDocument();
  });

  it("is hidden from people who can't list secrets", async () => {
    const { screen } = renderApp("/credentials", { user: viewerUser(), routes: { "GET /credentials": [] } });
    expect(await screen.findByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New credential" })).not.toBeInTheDocument();
  });
});

import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { credential, sshCertCredential, sshCertificate, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

const STORE = {
  "GET /secret-store/info": {
    enabled: true,
    label: "OpenBao",
    base_path: "secret/ansideck/1/",
    path_rules: "letters, digits, - and _",
  },
};

const SSH_STORE = {
  "GET /secret-store/info": {
    ...STORE["GET /secret-store/info"],
    ssh_mounts: ["ssh", "ssh-prod"],
    ssh_role_prefix: "ansideck-1-",
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

  it("points a reference elsewhere, and shows why a new one was refused", async () => {
    const vaulted = credential({
      id: 4,
      name: "vaulted",
      store: "external",
      store_path: "web/ssh",
      store_key: "private_key",
      store_location: "secret/ansideck/1/web/ssh#private_key",
    });
    const { api, user, screen } = renderApp("/credentials", {
      routes: {
        ...STORE,
        "GET /credentials": [vaulted, credential({ id: 5, name: "here" })],
        "PATCH /credentials/:id": reply(400, { detail: "OpenBao: no secret at that path" }),
      },
    });
    const buttons = await screen.findAllByRole("button", { name: "Edit reference" });
    expect(buttons).toHaveLength(1); // not for a key stored in AnsiDeck
    await user.click(buttons[0]!);
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByText("secret/ansideck/1/web/ssh#private_key")).toBeInTheDocument();
    expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled(); // nothing changed yet
    await user.clear(dialog.getByLabelText("Path in OpenBao"));
    await user.type(dialog.getByLabelText("Path in OpenBao"), "web/nope");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("OpenBao: no secret at that path")).toBeInTheDocument();

    api.set({
      "PATCH /credentials/:id": { ...vaulted, store_path: "web/ssh2" },
      "GET /credentials": [{ ...vaulted, store_location: "secret/ansideck/1/web/ssh2#pk" }],
    });
    await user.clear(dialog.getByLabelText("Path in OpenBao"));
    await user.type(dialog.getByLabelText("Path in OpenBao"), "web/ssh2");
    await user.clear(dialog.getByLabelText("Key in that secret"));
    await user.type(dialog.getByLabelText("Key in that secret"), "pk");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("secret/ansideck/1/web/ssh2#pk")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(api.requests("PATCH /credentials/4").at(-1)?.body).toEqual({
      store_path: "web/ssh2",
      store_key: "pk",
    });
  });

  it("points an environment-variable credential at another secret, with no key", async () => {
    const env = credential({
      id: 6,
      name: "aws",
      kind: "env",
      env_names: null,
      store: "external",
      store_path: "cloud/aws",
      store_location: "secret/ansideck/1/cloud/aws",
    });
    const { api, user, screen } = renderApp("/credentials", {
      routes: { ...STORE, "GET /credentials": [env], "PATCH /credentials/:id": env },
    });
    await user.click(await screen.findByRole("button", { name: "Edit reference" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.queryByLabelText("Key in that secret")).not.toBeInTheDocument();
    await user.clear(dialog.getByLabelText("Path in OpenBao"));
    await user.type(dialog.getByLabelText("Path in OpenBao"), "cloud/gcp");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await vi.waitFor(() =>
      expect(api.requests("PATCH /credentials/6")[0]?.body).toEqual({ store_path: "cloud/gcp" }),
    );
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

  it("offers SSH certificates only when the secret store has SSH mounts", async () => {
    const { user, screen } = renderApp("/credentials", { routes: { ...STORE, "GET /credentials": [] } });
    await user.click(await screen.findByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByRole("button", { name: "SSH key" })).toBeInTheDocument();
    expect(dialog.queryByRole("button", { name: /SSH certificate/ })).not.toBeInTheDocument();
  });

  it("creates an SSH certificate credential with its role and principals", async () => {
    const { api, user, screen } = renderApp("/credentials", {
      routes: { ...SSH_STORE, "GET /credentials": [], "POST /credentials": sshCertCredential() },
    });
    await user.click(await screen.findByRole("button", { name: "New credential" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "web-cert");
    await user.click(dialog.getByRole("button", { name: "SSH certificate (from OpenBao)" }));
    expect(dialog.queryByLabelText("Private key (PEM)")).not.toBeInTheDocument();
    expect(dialog.getByText("ansideck-1-")).toBeInTheDocument();
    expect(dialog.getByRole("button", { name: "Create" })).toBeDisabled();
    await user.type(dialog.getByLabelText("Role in OpenBao"), "web");
    await user.type(dialog.getByLabelText("Principals"), "deploy, ansible deploy");
    expect(dialog.getByText("ansible")).toBeInTheDocument();
    await choose(user, dialog.getByLabelText("SSH engine mount"), "ssh-prod");
    api.set({ "GET /credentials": [sshCertCredential()] });
    await user.click(dialog.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("web-cert")).toBeInTheDocument();
    expect(api.requests("POST /credentials")[0]?.body).toMatchObject({
      name: "web-cert",
      kind: "ssh_cert",
      ssh_mount: "ssh-prod",
      ssh_role: "web",
      ssh_principals: ["deploy", "ansible"],
    });
  });

  it("shows a certificate credential's role and principals and its test certificate", async () => {
    const { user, screen } = renderApp("/credentials", {
      routes: {
        ...SSH_STORE,
        "GET /credentials": [sshCertCredential()],
        "POST /credentials/:id/check": {
          ok: true,
          version: null,
          certificate: sshCertificate({ serial: "42" }),
          error_kind: null,
          error: null,
        },
      },
    });
    expect(await screen.findByText("SSH certificate")).toBeInTheDocument();
    expect(screen.getByText("ssh/sign/ansideck-1-web")).toBeInTheDocument();
    expect(screen.getByText("deploy · ansible")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(
      await screen.findByText(
        "Signed a test certificate: serial 42, CA SHA256:SnC9xXbMkPaHgX0yJ8k1aKlfAJ3Bk1aY2HhqLr8yFt8",
      ),
    ).toBeInTheDocument();
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

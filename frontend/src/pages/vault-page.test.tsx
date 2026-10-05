import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { vaultPassword } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

describe("vault", () => {
  it("creates a vault password, and one kept in the secret store", async () => {
    const { api, user, screen } = renderApp("/vault", {
      routes: {
        "GET /secret-store/info": { enabled: true, label: "OpenBao", base_path: "secret/ansideck/1/", path_rules: "plain segments" },
        "GET /vault-passwords": [],
        "POST /vault-passwords": vaultPassword(),
        "POST /vault-passwords/:id/check": reply(503, { detail: "OpenBao is unavailable" }),
      },
    });
    expect(await screen.findByText(/No vault passwords yet/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "New Vault Password" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "prod-vault");
    await user.type(dialog.getByLabelText("Description"), "prod secrets");
    await user.type(dialog.getByLabelText("Vault password"), "hunter2");
    api.set({ "GET /vault-passwords": [vaultPassword({ description: "prod secrets" })] });
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await screen.findByText("prod secrets")).toBeInTheDocument();
    expect(api.requests("POST /vault-passwords")[0]?.body).toMatchObject({ name: "prod-vault", password: "hunter2" });

    await user.click(screen.getByRole("button", { name: "New Vault Password" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "bao-vault");
    await user.click(dialog.getByRole("button", { name: "In OpenBao" }));
    await user.type(dialog.getByLabelText("Path in OpenBao"), "vault/prod");
    api.set({
      "GET /vault-passwords": [vaultPassword({ id: 2, name: "bao-vault", store: "external", store_location: "secret/ansideck/1/vault/prod" })],
    });
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await screen.findByText("secret/ansideck/1/vault/prod")).toBeInTheDocument();
    expect(api.requests("POST /vault-passwords")[1]?.body).toMatchObject({ store_path: "vault/prod", store_key: "password" });

    await user.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByText("OpenBao is unavailable")).toBeInTheDocument();
  });

  it("encrypts a value for YAML and extra vars, and copies it", async () => {
    const { api, user, screen } = renderApp("/vault", {
      routes: {
        "GET /vault-passwords": [vaultPassword()],
        "POST /vault/encrypt": { vault_text: "$ANSIBLE_VAULT;1.1;AES256\n6162", yaml_block: "db_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256" },
      },
    });
    await choose(user, await screen.findByLabelText("Vault password", { selector: "#encrypt-vault-password" }), "prod-vault");
    await user.type(screen.getByLabelText("Variable name (optional)"), "db_password");
    await user.type(screen.getByLabelText("Value to encrypt"), "s3cret");
    await user.click(screen.getByRole("button", { name: "Encrypt" }));
    expect(await screen.findByLabelText("For playbook YAML")).toHaveValue("db_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256");
    expect(screen.getByLabelText("For extra-vars JSON")).toHaveValue("$ANSIBLE_VAULT;1.1;AES256\n6162");
    expect(screen.getByLabelText("Value to encrypt")).toHaveValue("");
    expect(api.requests("POST /vault/encrypt")[0]?.body).toEqual({ vault_password_id: 1, plaintext: "s3cret", var_name: "db_password" });

    await user.click(screen.getAllByRole("button", { name: "Copy" })[0]!);
    // user-event provides the clipboard.
    expect(await navigator.clipboard.readText()).toBe("db_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256");
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("decrypts a value and reports a wrong password", async () => {
    const { api, user, screen } = renderApp("/vault", {
      routes: {
        "GET /vault-passwords": [vaultPassword()],
        "POST /vault/decrypt": { plaintext: "s3cret" },
        "POST /vault/encrypt": reply(400, { detail: "Nothing to encrypt" }),
      },
    });
    await choose(user, await screen.findByLabelText("Vault password", { selector: "#decrypt-vault-password" }), "prod-vault");
    await user.type(screen.getByLabelText("Encrypted value"), "$ANSIBLE_VAULT;1.1;AES256");
    await user.click(screen.getByRole("button", { name: "Decrypt" }));
    expect(await screen.findByLabelText("Decrypted value")).toHaveValue("s3cret");

    api.set({ "POST /vault/decrypt": reply(400, { detail: "Decryption failed (wrong password?)" }) });
    await user.click(screen.getByRole("button", { name: "Decrypt" }));
    expect(await screen.findByText("Decryption failed (wrong password?)")).toBeInTheDocument();
    expect(screen.queryByLabelText("Decrypted value")).not.toBeInTheDocument();

    await choose(user, screen.getByLabelText("Vault password", { selector: "#encrypt-vault-password" }), "prod-vault");
    await user.type(screen.getByLabelText("Value to encrypt"), "x");
    await user.click(screen.getByRole("button", { name: "Encrypt" }));
    expect(await screen.findByText("Nothing to encrypt")).toBeInTheDocument();
  });

  it("deletes a vault password and shows refused creates", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/vault", {
      routes: {
        "GET /vault-passwords": [vaultPassword()],
        "DELETE /vault-passwords/:id": reply(204),
        "POST /vault-passwords": reply(409, { detail: "Name taken" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "New Vault Password" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "prod-vault");
    await user.type(dialog.getByLabelText("Vault password"), "x");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("Name taken")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    api.set({ "GET /vault-passwords": [] });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText(/No vault passwords yet/)).toBeInTheDocument();
    expect(api.requests("DELETE /vault-passwords/1")).toHaveLength(1);
  });
});

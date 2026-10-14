import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser, passkey } from "@/test/fixtures";
import { renderApp } from "@/test/render";
import { ASSERTED, CREATED, CREATION_OPTIONS, fakeCredentials, REQUEST_OPTIONS } from "@/test/webauthn";

const CODES = ["aaaaa-11111", "bbbbb-22222"];

describe("account: password", () => {
  it("checks the new password as you type and changes it", async () => {
    const { api, user, screen } = renderApp("/account", {
      routes: { "POST /auth/change-password": { ok: true } },
    });
    expect(await screen.findByText("Default · admin")).toBeInTheDocument();
    expect(screen.getByText("global admin")).toBeInTheDocument();
    const submit = screen.getByRole("button", { name: "Change password" });

    await user.type(screen.getByLabelText("Current password"), "old-password");
    await user.type(screen.getByLabelText("New password"), "short");
    expect(screen.getByText("Use at least 12 characters.")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("New password"));
    await user.type(screen.getByLabelText("New password"), "x".repeat(129));
    expect(screen.getByText("Use at most 128 characters.")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("New password"));
    await user.type(screen.getByLabelText("New password"), "correct horse battery");
    await user.type(screen.getByLabelText("Confirm new password"), "correct horse batterz");
    expect(screen.getByText("The new passwords don't match.")).toBeInTheDocument();
    expect(submit).toBeDisabled();
    await user.clear(screen.getByLabelText("Confirm new password"));
    await user.type(screen.getByLabelText("Confirm new password"), "correct horse battery");
    await user.click(submit);

    expect(await screen.findByText(/Password changed/)).toBeInTheDocument();
    expect(api.requests("POST /auth/change-password")[0]?.body).toEqual({
      current_password: "old-password",
      new_password: "correct horse battery",
    });
    expect(screen.getByLabelText("Current password")).toHaveValue("");
  });

  it("refuses your username and shows a wrong current password", async () => {
    const { user, screen } = renderApp("/account", {
      user: adminUser({ username: "administrator1" }),
      routes: { "POST /auth/change-password": reply(400, { detail: "The current password is wrong" }) },
    });
    await user.type(await screen.findByLabelText("New password"), "ADMINISTRATOR1");
    expect(screen.getByText("Don't use your username.")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("New password"));
    await user.type(screen.getByLabelText("Current password"), "nope");
    await user.type(screen.getByLabelText("New password"), "a-good-long-password");
    await user.type(screen.getByLabelText("Confirm new password"), "a-good-long-password");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("The current password is wrong")).toBeInTheDocument();
  });
});

const TOTP_SETUP = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x", qr: "data:image/svg+xml;base64,PHN2Zy8+" };

function passkeysHere() {
  return { oidc: { enabled: false, label: "SSO" }, github: { enabled: false, label: "GitHub" }, passkeys: { enabled: true, origin: window.location.origin } };
}

describe("account: authenticator app", () => {
  it("sets it up: password, scan, code, then recovery codes", async () => {
    const createObjectURL = vi.fn(() => "blob:codes");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { api, user, screen } = renderApp("/account", {
      routes: {
        "POST /auth/totp/setup": TOTP_SETUP,
        "POST /auth/totp/enable": reply(400, { detail: "That code is not valid." }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Code from the app"), "000000");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("That code is not valid.")).toBeInTheDocument();

    const on = adminUser({ totp_enabled: true, two_factor_enabled: true });
    api.set({ "POST /auth/totp/enable": { recovery_codes: CODES }, "GET /auth/me": on });
    await user.clear(screen.getByLabelText("Code from the app"));
    await user.type(screen.getByLabelText("Code from the app"), "123456");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("aaaaa-11111")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("aaaaa-11111\nbbbbb-22222\n");
    await user.click(screen.getByRole("button", { name: "Download .txt" }));
    expect(click).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:codes");
    // The account (badge, other cards) changes once the codes are saved.
    expect(screen.queryByText("2FA")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "I've saved them" }));
    expect(await screen.findByText("2FA")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Turn off" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New recovery codes" })).toBeInTheDocument();
  });

  it("keeps the codes a passkey came with", async () => {
    const withPasskey = adminUser({ passkey_count: 1, two_factor_enabled: true });
    const { api, user, screen } = renderApp("/account", {
      user: withPasskey,
      routes: { "POST /auth/totp/setup": TOTP_SETUP, "POST /auth/totp/enable": { recovery_codes: null } },
    });
    await user.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    api.set({ "GET /auth/me": { ...withPasskey, totp_enabled: true } });
    await user.type(await screen.findByLabelText("Code from the app"), "123456");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByRole("button", { name: "Turn off" })).toBeInTheDocument();
    expect(screen.queryByText("I've saved them")).not.toBeInTheDocument();
  });

  it("makes new recovery codes and turns it off", async () => {
    const { api, user, screen } = renderApp("/account", {
      user: adminUser({ totp_enabled: true, two_factor_enabled: true }),
      routes: {
        "POST /auth/recovery-codes": { recovery_codes: CODES },
        "POST /auth/totp/disable": { ok: true },
      },
    });
    await user.click(await screen.findByRole("button", { name: "New recovery codes" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#recovery-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Create new codes" }));
    expect(await screen.findByText("bbbbb-22222")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "I've saved them" }));

    await user.click(screen.getByRole("button", { name: "Turn off" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    expect(screen.getByRole("button", { name: "Turn off" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Use a passkey" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Authentication code or recovery code"), "123456");
    api.set({ "GET /auth/me": adminUser() });
    await user.click(screen.getByRole("button", { name: "Turn off" }));
    expect(await screen.findByRole("button", { name: "Set up an authenticator app" })).toBeInTheDocument();
    expect(api.requests("POST /auth/totp/disable")[0]?.body).toEqual({ current_password: "pw", code: "123456" });
    expect(screen.queryByRole("button", { name: "New recovery codes" })).not.toBeInTheDocument();
  });

  it("can be cancelled at each step", async () => {
    const { user, screen } = renderApp("/account", { routes: { "POST /auth/totp/setup": TOTP_SETUP } });
    await user.click(await screen.findByRole("button", { name: "Set up an authenticator app" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Set up an authenticator app" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByLabelText("Code from the app");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Set up an authenticator app" })).toBeInTheDocument();
  });
});

describe("account: passkeys", () => {
  it("adds one: password, name, the browser's prompt, then recovery codes", async () => {
    const { create } = fakeCredentials();
    const { api, user, screen } = renderApp("/account", {
      routes: {
        "GET /auth/providers": passkeysHere(),
        "POST /auth/passkeys/registration/options": { options: CREATION_OPTIONS },
        "POST /auth/passkeys": { passkey: passkey({ name: "Passkey 1" }), recovery_codes: CODES },
      },
    });
    expect(await screen.findByText(/None yet/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add a passkey" }));
    expect(screen.getByLabelText("Name")).toHaveValue("Passkey 1");
    await user.type(screen.getByLabelText("Current password", { selector: "#passkey-password" }), "pw");
    api.set({
      "GET /auth/passkeys": [passkey({ name: "Passkey 1" })],
      "GET /auth/me": adminUser({ passkey_count: 1, two_factor_enabled: true }),
    });
    await user.click(screen.getByRole("button", { name: "Add passkey" }));

    expect(await screen.findByText("aaaaa-11111")).toBeInTheDocument();
    expect(create).toHaveBeenCalledOnce();
    expect(api.requests("POST /auth/passkeys/registration/options")[0]?.body).toEqual({ current_password: "pw" });
    expect(api.requests("POST /auth/passkeys")[0]?.body).toEqual({ name: "Passkey 1", credential: CREATED });
    await user.click(screen.getByRole("button", { name: "I've saved them" }));
    expect(await screen.findByText("2FA")).toBeInTheDocument();
    expect(screen.getByText("Passkey 1")).toBeInTheDocument();
  });

  it("shows what went wrong in the browser or on the server", async () => {
    const { create } = fakeCredentials();
    create.mockRejectedValueOnce(new DOMException("cancelled", "NotAllowedError"));
    const { api, user, screen } = renderApp("/account", {
      routes: {
        "GET /auth/providers": passkeysHere(),
        "POST /auth/passkeys/registration/options": { options: CREATION_OPTIONS },
        "POST /auth/passkeys": reply(409, { detail: "You already have a passkey with that name" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Add a passkey" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#passkey-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Add passkey" }));
    expect(await screen.findByText(/prompt was closed or timed out/)).toBeInTheDocument();
    expect(api.requests("POST /auth/passkeys")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Add passkey" }));
    expect(await screen.findByText("You already have a passkey with that name")).toBeInTheDocument();
  });

  it("says why passkeys can't be added here", async () => {
    const { screen } = renderApp("/account");
    expect(await screen.findByText(/set PUBLIC_URL to its https/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a passkey" })).not.toBeInTheDocument();

    const elsewhere = { ...passkeysHere(), passkeys: { enabled: true, origin: "https://ansideck.example.com" } };
    const other = renderApp("/account", { routes: { "GET /auth/providers": elsewhere } });
    expect(await other.screen.findByText(/work at https:\/\/ansideck.example.com only/)).toBeInTheDocument();
  });

  it("renames one and removes another, confirming with a passkey", async () => {
    const { get } = fakeCredentials();
    const laptop = passkey({ id: 1, name: "Work laptop", last_used_at: "2026-10-14T09:00:00Z" });
    const key = passkey({ id: 2, name: "YubiKey", synced: false });
    const { api, user, screen } = renderApp("/account", {
      user: adminUser({ passkey_count: 2, two_factor_enabled: true }),
      routes: {
        "GET /auth/providers": passkeysHere(),
        "GET /auth/passkeys": [laptop, key],
        "PATCH /auth/passkeys/:id": ({ body }: { body: unknown }) => ({ ...laptop, ...(body as object) }),
        "POST /auth/passkeys/step-up-options": { options: REQUEST_OPTIONS },
        "POST /auth/passkeys/:id/remove": { ok: true },
      },
    });
    await user.click(await screen.findByRole("button", { name: "Rename Work laptop" }));
    await user.clear(screen.getByLabelText("New name"));
    await user.type(screen.getByLabelText("New name"), "Home laptop");
    api.set({ "GET /auth/passkeys": [{ ...laptop, name: "Home laptop" }, key] });
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Home laptop")).toBeInTheDocument();
    expect(api.requests("PATCH /auth/passkeys/1")[0]?.body).toEqual({ name: "Home laptop" });

    await user.click(screen.getByRole("button", { name: "Remove YubiKey" }));
    expect(screen.getByLabelText("Recovery code")).toBeInTheDocument(); // no authenticator app
    await user.type(screen.getByLabelText("Current password", { selector: "#passkey-remove-password" }), "pw");
    api.set({ "GET /auth/passkeys": [{ ...laptop, name: "Home laptop" }] });
    await user.click(screen.getByRole("button", { name: "Use a passkey" }));
    await screen.findByRole("button", { name: "Add a passkey" });
    expect(get).toHaveBeenCalledOnce();
    expect(api.requests("POST /auth/passkeys/2/remove")[0]?.body).toEqual({ current_password: "pw", passkey: ASSERTED });
    expect(screen.queryByText("YubiKey")).not.toBeInTheDocument();
  });
});

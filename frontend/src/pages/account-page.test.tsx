import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { adminUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const CODES = ["aaaaa-11111", "bbbbb-22222"];

describe("account: password", () => {
  it("checks the new password as you type and changes it", async () => {
    const { api, user, screen } = renderApp("/account", {
      routes: { "POST /auth/change-password": { ok: true } },
    });
    expect(await screen.findByText("Default: admin")).toBeInTheDocument();
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

describe("account: two-factor login", () => {
  it("sets it up: password, scan, code, then recovery codes", async () => {
    const createObjectURL = vi.fn(() => "blob:codes");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const { api, user, screen } = renderApp("/account", {
      routes: {
        "POST /auth/totp/setup": { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/x", qr: "data:image/svg+xml;base64,PHN2Zy8+" },
        "POST /auth/totp/enable": reply(400, { detail: "That code is not valid." }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Set up two-factor login" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Code from the app"), "000000");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("That code is not valid.")).toBeInTheDocument();

    api.set({ "POST /auth/totp/enable": { recovery_codes: CODES }, "GET /auth/me": adminUser({ totp_enabled: true }) });
    await user.clear(screen.getByLabelText("Code from the app"));
    await user.type(screen.getByLabelText("Code from the app"), "123456");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText("aaaaa-11111")).toBeInTheDocument();
    expect(screen.getByText("2FA")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("aaaaa-11111\nbbbbb-22222\n");
    await user.click(screen.getByRole("button", { name: "Download .txt" }));
    expect(click).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:codes");
    await user.click(screen.getByRole("button", { name: "I've saved them" }));
    expect(await screen.findByRole("button", { name: "Turn off" })).toBeInTheDocument();
  });

  it("makes new recovery codes and turns it off", async () => {
    const { api, user, screen } = renderApp("/account", {
      user: adminUser({ totp_enabled: true }),
      routes: {
        "POST /auth/totp/recovery-codes": { recovery_codes: CODES },
        "POST /auth/totp/disable": { ok: true },
      },
    });
    await user.click(await screen.findByRole("button", { name: "New recovery codes" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Create new codes" }));
    expect(await screen.findByText("bbbbb-22222")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "I've saved them" }));

    await user.click(screen.getByRole("button", { name: "Turn off" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    expect(screen.getByRole("button", { name: "Turn off" })).toBeDisabled();
    await user.type(screen.getByLabelText("Authentication code or recovery code"), "123456");
    api.set({ "GET /auth/me": adminUser() });
    await user.click(screen.getByRole("button", { name: "Turn off" }));
    expect(await screen.findByRole("button", { name: "Set up two-factor login" })).toBeInTheDocument();
    expect(api.requests("POST /auth/totp/disable")[0]?.body).toEqual({ current_password: "pw", code: "123456" });
  });

  it("can be cancelled at each step", async () => {
    const { user, screen } = renderApp("/account", {
      routes: { "POST /auth/totp/setup": { secret: "ABCD", otpauth_uri: "otpauth://x", qr: "data:image/svg+xml;base64,PHN2Zy8+" } },
    });
    await user.click(await screen.findByRole("button", { name: "Set up two-factor login" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Set up two-factor login" }));
    await user.type(screen.getByLabelText("Current password", { selector: "#totp-password" }), "pw");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByLabelText("Code from the app");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Set up two-factor login" })).toBeInTheDocument();
  });
});

import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { CATALOG, channel, viewerUser, project } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

const GLOBAL = "GET /notifications/channels";
const PROJECT = "GET /projects/:id/notifications/channels";

/** One channel section (global or the project's), found by its heading. */
function section(title: string) {
  const heading = [...document.querySelectorAll("h2")].find((h) => h.textContent === title);
  return within(heading!.closest("section")!);
}

describe("notifications", () => {
  it("shows global and project channels with their last delivery and history", async () => {
    const { user, screen } = renderApp("/notifications", {
      routes: {
        "GET /notifications/catalog": CATALOG,
        [GLOBAL]: [channel()],
        [PROJECT]: [channel({ id: 2, project_id: 1, name: "team-mail", kind: "email", target: "a@example.com", recipients: ["a@example.com"], last_delivery: null, enabled: false })],
        "GET /notifications/channels/:id/deliveries": [
          { id: 1, event: "run.failed", title: "Run #7 failed", status: "failed", attempts: 3, last_status_code: 500, last_error: "HTTP 500", created_at: "2026-10-05T12:00:00Z", next_attempt_at: "2026-10-05T12:05:00Z", sent_at: null },
          { id: 2, event: "run.failed", title: "Run #6 failed", status: "sent", attempts: 1, last_status_code: 204, last_error: null, created_at: "2026-10-05T11:00:00Z", next_attempt_at: null, sent_at: "2026-10-05T11:00:01Z" },
        ],
      },
    });
    await screen.findByText("ops-discord");
    const global = section("Global channels");
    expect(global.getByText("Run failed")).toBeInTheDocument();
    expect(global.getByText("sent")).toBeInTheDocument();
    const team = section("Default channels");
    expect(team.getByText("team-mail")).toBeInTheDocument();
    expect(team.getByText("· nothing sent yet")).toBeInTheDocument();
    expect(team.getByRole("switch", { name: "Turn on" })).not.toBeChecked();

    await user.click(global.getByRole("button", { name: "History" }));
    expect(await global.findByText("Run #7 failed")).toBeInTheDocument();
    expect(global.getByText(/3 attempts · HTTP 500 · next try/)).toBeInTheDocument();
    await user.click(global.getByRole("button", { name: "Hide history" }));
    expect(global.queryByText("Run #7 failed")).not.toBeInTheDocument();
  });

  it("creates a webhook channel with a signing secret and chosen events", async () => {
    const { api, user, screen } = renderApp("/notifications", {
      routes: { "GET /notifications/catalog": CATALOG, [GLOBAL]: [], [PROJECT]: [], "POST /notifications/channels": channel({ kind: "webhook" }) },
    });
    await screen.findAllByText(/^No channels yet/);
    await user.click(section("Global channels").getByRole("button", { name: "New channel" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByText(/A global channel/)).toBeInTheDocument();
    await user.type(dialog.getByLabelText("Name"), "hook");
    await choose(user, dialog.getByLabelText("Send to"), "Webhook");
    await user.type(dialog.getByLabelText("Webhook URL"), " https://example.com/hook ");
    await user.type(dialog.getByLabelText("Signing secret (optional)"), "sig");
    await user.click(dialog.getByRole("checkbox", { name: /Run recovered/ }));
    await user.click(dialog.getByRole("checkbox", { name: /Worker offline/ }));
    api.set({ [GLOBAL]: [channel({ name: "hook", kind: "webhook" })] });
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("hook")).toBeInTheDocument();
    expect(api.requests("POST /notifications/channels")[0]?.body).toEqual({
      name: "hook",
      kind: "webhook",
      events: ["run.failed"],
      url: "https://example.com/hook",
      secret: "sig",
    });
  });

  it("creates email and push channels in a project, which only offers project events", async () => {
    const { api, user, screen } = renderApp("/notifications", {
      routes: { "GET /notifications/catalog": CATALOG, [GLOBAL]: [], [PROJECT]: [], "POST /projects/:id/notifications/channels": channel() },
    });
    await screen.findAllByText(/^No channels yet/);
    const team = section("Default channels");
    await user.click(team.getByRole("button", { name: "New channel" }));
    let dialog = within(await screen.findByRole("dialog"));
    expect(dialog.queryByRole("checkbox", { name: /Worker offline/ })).not.toBeInTheDocument();
    await user.type(dialog.getByLabelText("Name"), "mail");
    await choose(user, dialog.getByLabelText("Send to"), "Email");
    await user.type(dialog.getByLabelText("Recipients (one per line)"), "a@example.com\nb@example.com, ");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findAllByText(/^No channels yet/);
    expect(api.requests("POST /projects/1/notifications/channels")[0]?.body).toEqual({
      name: "mail",
      kind: "email",
      events: ["run.failed", "run.recovered"],
      recipients: ["a@example.com", "b@example.com"],
    });

    await user.click(team.getByRole("button", { name: "New channel" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "phone");
    await choose(user, dialog.getByLabelText("Send to"), "Pushover");
    await user.type(dialog.getByLabelText("Application API token"), " tok ");
    await user.type(dialog.getByLabelText("User or group key"), " usr ");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findAllByText(/^No channels yet/);
    expect(api.requests("POST /projects/1/notifications/channels")[1]?.body).toMatchObject({ kind: "pushover", token: "tok", user_key: "usr" });
  });

  it("edits a channel, removing its signing secret, and changes recipients", async () => {
    const hook = channel({ kind: "webhook", has_secret: true, name: "hook" });
    const mail = channel({ id: 3, kind: "email", name: "mail", recipients: ["a@example.com"], target: "a@example.com" });
    const { api, user, screen } = renderApp("/notifications", {
      routes: {
        "GET /notifications/catalog": { ...CATALOG, email_available: false },
        [GLOBAL]: [hook, mail],
        [PROJECT]: [],
        "PATCH /notifications/channels/:id": hook,
      },
    });
    await screen.findByText("hook");
    await user.click(screen.getAllByRole("button", { name: "Edit" })[0]!);
    let dialog = within(await screen.findByRole("dialog"));
    expect(dialog.queryByLabelText("Send to")).not.toBeInTheDocument();
    expect(dialog.getByLabelText("Webhook URL")).toHaveAttribute("placeholder", "Leave empty to keep the current one");
    await user.click(dialog.getByRole("checkbox", { name: "Remove the signing secret" }));
    expect(dialog.getByLabelText("Signing secret (optional)")).toBeDisabled();
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByText("hook");
    expect(api.requests("PATCH /notifications/channels/1")[0]?.body).toEqual({ name: "hook", events: ["run.failed"], secret: "" });

    await user.click(screen.getAllByRole("button", { name: "Edit" })[1]!);
    dialog = within(await screen.findByRole("dialog"));
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByText("hook");
    expect(api.requests("PATCH /notifications/channels/3")[0]?.body).toEqual({ name: "mail", events: ["run.failed"] });
    await user.click(screen.getAllByRole("button", { name: "Edit" })[1]!);
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Recipients (one per line)"), "\nb@example.com");
    api.set({ "PATCH /notifications/channels/:id": reply(400, { detail: "Not an email address" }) });
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("Not an email address")).toBeInTheDocument();
    expect(api.requests("PATCH /notifications/channels/3")[1]?.body).toMatchObject({ recipients: ["a@example.com", "b@example.com"] });
  });

  it("tests, toggles and deletes channels", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/notifications", {
      routes: {
        "GET /notifications/catalog": CATALOG,
        [GLOBAL]: [channel({ last_delivery: { status: "failed", event: "run.failed", created_at: "2026-10-05T12:00:00Z", error: "HTTP 404" } })],
        [PROJECT]: [],
        "POST /notifications/channels/:id/test": { ok: true, status_code: 204, error: null },
        "PATCH /notifications/channels/:id": channel({ enabled: false }),
        "DELETE /notifications/channels/:id": reply(204),
      },
    });
    expect(await screen.findByText(/\(HTTP 404\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test message sent.")).toBeInTheDocument();
    api.set({ "POST /notifications/channels/:id/test": { ok: false, status_code: 404, error: "HTTP 404" } });
    await user.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test failed: HTTP 404")).toBeInTheDocument();
    api.set({ "POST /notifications/channels/:id/test": reply(429, { detail: "Wait a minute between tests" }) });
    await user.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Wait a minute between tests")).toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "Turn off" }));
    expect(api.requests("PATCH /notifications/channels/1")[0]?.body).toEqual({ enabled: false });

    api.set({ "DELETE /notifications/channels/:id": reply(500, { detail: "Database busy" }) });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Database busy")).toBeInTheDocument();
    expect(confirm).toHaveBeenCalled();
  });

  it("for a project admin, shows only the project's channels", async () => {
    const projectAdmin = viewerUser({ projects: [project({ role: "admin", permissions: ["content:read", "notifications:manage"] })] });
    const { screen } = renderApp("/notifications", {
      user: projectAdmin,
      routes: { "GET /notifications/catalog": CATALOG, [PROJECT]: reply(500, { detail: "Server error" }) },
    });
    expect(await screen.findByText("Server error")).toBeInTheDocument();
    expect(screen.queryByText("Global channels")).not.toBeInTheDocument();
  });

  it("asks a global admin in all-projects mode to pick a project, and shows catalog errors", async () => {
    const { screen } = renderApp("/notifications", {
      activeProject: null,
      routes: { "GET /notifications/catalog": CATALOG, [GLOBAL]: [] },
    });
    expect(await screen.findByText(/Pick a project in the switcher/)).toBeInTheDocument();
  });

  it("shows when the catalog can't load", async () => {
    const { screen } = renderApp("/notifications", { routes: { "GET /notifications/catalog": reply(500, { detail: "Catalog down" }) } });
    expect(await screen.findByText("Catalog down")).toBeInTheDocument();
  });
});

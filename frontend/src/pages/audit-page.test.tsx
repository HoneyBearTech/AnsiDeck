import { describe, expect, it } from "vitest";

import { reply } from "@/test/fake-api";
import { choose, renderApp } from "@/test/render";

function event(id: number, overrides = {}) {
  return {
    id,
    created_at: "2026-10-05T12:00:00Z",
    actor_username: "admin",
    project_id: 1,
    action: "credential.create",
    target_type: "credential",
    target_id: 3,
    target_name: "deploy-key",
    outcome: "success",
    ip: "10.0.0.5",
    detail: { kind: "ssh" },
    ...overrides,
  };
}

describe("audit log", () => {
  it("shows events and filters them by action, actor and outcome", async () => {
    const { api, user, screen } = renderApp("/audit", {
      routes: {
        "GET /audit": (r: { query: URLSearchParams }) =>
          r.query.get("outcome") === "denied"
            ? { items: [event(2, { outcome: "denied", actor_username: null, target_type: null, target_name: null, ip: null, project_id: null, detail: null })], total: 1 }
            : { items: [event(1)], total: 1 },
      },
    });
    expect(await screen.findByText('admin → credential #3 "deploy-key" · 10.0.0.5 · project Default')).toBeInTheDocument();
    expect(screen.getByText("kind")).toBeInTheDocument();
    expect(screen.getByText("ssh")).toBeInTheDocument();
    expect(screen.getByText("1 event · page 1 of 1")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Action starts with"), "auth.");
    await user.type(screen.getByLabelText("Actor"), "bob");
    await choose(user, screen.getByLabelText("Outcome"), "denied");
    expect(await screen.findByText("system")).toBeInTheDocument();
    const last = api.requests("GET /audit").at(-1)!;
    expect(Object.fromEntries(last.query)).toMatchObject({ action: "auth.", actor: "bob", outcome: "denied", offset: "0" });
  });

  it("pages through events and refreshes", async () => {
    const { api, user, screen } = renderApp("/audit", {
      routes: { "GET /audit": (r: { query: URLSearchParams }) => ({ items: [event(Number(r.query.get("offset")) + 1)], total: 60 }) },
    });
    expect(await screen.findByText("60 events · page 1 of 3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("60 events · page 2 of 3")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("60 events · page 3 of 3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("60 events · page 2 of 3");
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(api.requests("GET /audit").at(-1)?.query.get("offset")).toBe("25");
  });

  it("says when nothing matches or the log can't load", async () => {
    const { api, user, screen } = renderApp("/audit", { routes: { "GET /audit": { items: [], total: 0 } } });
    expect(await screen.findByText("No matching events.")).toBeInTheDocument();
    api.set({ "GET /audit": reply(500) });
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Could not load the audit log")).toBeInTheDocument();
  });
});

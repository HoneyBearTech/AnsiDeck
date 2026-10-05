import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { credential, inventory, inventorySource, refresh, targets, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";
import { editorText } from "@/test/editor";

const SNAPSHOT = {
  id: 1,
  created_at: "2026-10-05T12:00:00Z",
  refresh_id: 1,
  host_count: 2,
  group_count: 1,
  warnings: ["host 'bad name' skipped"],
  sources: [{ id: 1, name: "netbox", plugin: "netbox.netbox.nb_inventory" }],
  vars: {},
  groups: [{ name: "site_lab", hosts: 2, children: [], vars: {} }],
};

/** The detail page's routes with no dynamic sources. */
function detail(overrides = {}) {
  return {
    "GET /inventories/:id": inventory(),
    "GET /inventories/:id/sources": [],
    "GET /inventories/:id/targets": targets(),
    "GET /inventories/:id/snapshot": null,
    ...overrides,
  };
}

describe("inventories list", () => {
  it("creates and deletes inventories", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/inventories", {
      routes: {
        "GET /inventories": [],
        "POST /inventories": inventory(),
        "DELETE /inventories/:id": reply(204),
      },
    });
    await screen.findByText("No inventories yet.");
    await user.click(screen.getByRole("button", { name: "New Inventory" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "lab");
    await user.type(dialog.getByLabelText("Description"), "The lab");
    api.set({ "GET /inventories": [inventory()] });
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await screen.findByText("The lab")).toBeInTheDocument();
    expect(api.requests("POST /inventories")[0]?.body).toMatchObject({ name: "lab", description: "The lab" });

    api.set({ "GET /inventories": [] });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await screen.findByText("No inventories yet.");
  });

  it("shows why a create was refused", async () => {
    const { user, screen } = renderApp("/inventories", {
      routes: { "GET /inventories": [], "POST /inventories": reply(409, { detail: "Name taken" }) },
    });
    await user.click(await screen.findByRole("button", { name: "New Inventory" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "lab");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("Name taken")).toBeInTheDocument();
  });
});

describe("inventory detail", () => {
  it("adds groups and hosts, edits and deletes them", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "POST /inventories/:id/groups": { id: 2, name: "db" },
        "POST /inventories/:id/hosts": { id: 2, hostname: "db1", vars: {}, group_ids: [] },
        "PUT /inventories/:id/hosts/:hid": { id: 1, hostname: "web1.example", vars: {}, group_ids: [] },
        "DELETE /inventories/:id/groups/:gid": reply(204),
        "DELETE /inventories/:id/hosts/:hid": reply(204),
      }),
    });
    expect(await screen.findByRole("heading", { name: "lab" })).toBeInTheDocument();
    expect(screen.getByText("web1.example")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Add Group" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "db");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    await screen.findByText("web1.example");
    expect(api.requests("POST /inventories/1/groups")[0]?.body).toEqual({ name: "db" });

    await user.click(screen.getByRole("button", { name: "Add Host" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Hostname"), "db1");
    await user.clear(dialog.getByLabelText("Vars (JSON)"));
    await user.type(dialog.getByLabelText("Vars (JSON)"), "not json");
    await user.click(dialog.getByRole("checkbox", { name: "web" }));
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("Vars must be valid JSON")).toBeInTheDocument();
    await user.clear(dialog.getByLabelText("Vars (JSON)"));
    await user.type(dialog.getByLabelText("Vars (JSON)"), "{{}");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByRole("button", { name: "Add Host" });
    expect(api.requests("POST /inventories/1/hosts")[0]?.body).toEqual({ hostname: "db1", vars: {}, group_ids: [1] });

    await user.click(screen.getByRole("button", { name: "Edit" }));
    dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText("Hostname")).toHaveValue("web1.example");
    await user.click(dialog.getByRole("checkbox", { name: "web" }));
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByRole("button", { name: "Add Host" });
    expect(api.requests("PUT /inventories/1/hosts/1")[0]?.body).toEqual({
      hostname: "web1.example",
      vars: { ansible_user: "deploy" },
      group_ids: [],
    });

    const [deleteGroup, deleteHost] = screen.getAllByRole("button", { name: "Delete" });
    await user.click(deleteGroup!);
    await user.click(deleteHost!);
    expect(api.requests("DELETE /inventories/1/groups/1")).toHaveLength(1);
    expect(api.requests("DELETE /inventories/1/hosts/1")).toHaveLength(1);
  });

  it("shows host and group errors from the server", async () => {
    const { user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id": inventory({ groups: [], hosts: [] }),
        "POST /inventories/:id/groups": reply(400, { detail: "Group names use letters" }),
        "POST /inventories/:id/hosts": reply(400, { detail: "No ports in host names" }),
      }),
    });
    await screen.findByText("No hosts yet.");
    expect(screen.getByText("No groups yet.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add Group" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "a b");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("Group names use letters")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await user.click(screen.getByRole("button", { name: "Add Host" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Hostname"), "db:5432");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("No ports in host names")).toBeInTheDocument();
  });

  it("is read-only for viewers, without an empty sources panel", async () => {
    const { screen } = renderApp("/inventories/1", { user: viewerUser(), routes: detail() });
    await screen.findByText("web1.example");
    expect(screen.queryByRole("button", { name: "Add Host" })).not.toBeInTheDocument();
    expect(screen.queryByText("Dynamic sources")).not.toBeInTheDocument();
  });
});

describe("dynamic inventory sources", () => {
  it("shows sources, the last refresh, warnings, groups and the merged hosts", async () => {
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/sources": [
          inventorySource({ credential_id: 2, credential_name: "netbox-token" }),
          inventorySource({ id: 2, name: "groups", plugin: "constructed", enabled: false }),
        ],
        "GET /inventories/:id/targets": targets({ has_sources: true, snapshot_id: 1, snapshot_at: "2026-10-05T12:00:00Z", last_refresh: refresh() }),
        "GET /inventories/:id/snapshot": SNAPSHOT,
        "GET /inventories/:id/hosts": (r: { query: URLSearchParams }) =>
          r.query.get("q") === "zzz"
            ? { total: 0, hosts: [] }
            : {
                total: 3,
                hosts: [
                  { name: "web1.example", origin: "both", groups: ["web", "site_lab"], vars: { a: 1 }, overridden: ["ansible_user"] },
                  { name: "nb1", origin: "source", groups: ["site_lab"], vars: {}, overridden: [] },
                ],
              },
      }),
    });
    expect(await screen.findByText("credential: netbox-token")).toBeInTheDocument();
    expect(screen.getByText("off")).toBeInTheDocument();
    expect(screen.getByText("refreshed")).toBeInTheDocument();
    expect(screen.getByText(/2 hosts,\s+1 groups/)).toBeInTheDocument();
    expect(screen.getByText("host 'bad name' skipped")).toBeInTheDocument();
    expect(screen.getByText("site_lab · 2")).toBeInTheDocument();
    expect(await screen.findByText("Hosts a run sees (3)")).toBeInTheDocument();
    expect(screen.getByText("source + inventory")).toBeInTheDocument();
    expect(screen.getByText(/replace the source's: ansible_user/)).toBeInTheDocument();
    expect(screen.getByText("Showing 2 of 3: search to narrow down.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Search hosts"), "zzz");
    expect(await screen.findByText("No hosts match.")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/inventories/1/hosts" && c.query.get("q") === "zzz")).toBe(true);
  });

  it("refreshes now, polls until the refresh ends, and sets the schedule", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, user, screen } = renderApp("/inventories/1", {
        routes: detail({
          "GET /inventories/:id/sources": [inventorySource()],
          "GET /inventories/:id/targets": targets({ has_sources: true }),
          "POST /inventories/:id/refresh": refresh({ status: "queued" }),
          "PUT /inventories/:id/refresh-settings": targets({ refresh_interval_seconds: 3600 }),
        }),
      });
      expect(await screen.findByText("not refreshed")).toBeInTheDocument();
      api.set({ "GET /inventories/:id/targets": targets({ has_sources: true, last_refresh: refresh({ status: "running", finished_at: null }) }) });
      await user.click(screen.getByRole("button", { name: "Refresh now" }));
      expect(await screen.findByRole("button", { name: "Refreshing…" })).toBeDisabled();

      api.set({
        "GET /inventories/:id/targets": targets({ has_sources: true, snapshot_id: 1, snapshot_at: "2026-10-05T12:00:00Z", last_refresh: refresh({ status: "failed", error: "netbox: 401 Unauthorized" }) }),
        "GET /inventories/:id/snapshot": { ...SNAPSHOT, warnings: [], groups: [] },
        "GET /inventories/:id/hosts": { total: 0, hosts: [] },
      });
      await vi.advanceTimersByTimeAsync(2500);
      expect(await screen.findByText("netbox: 401 Unauthorized")).toBeInTheDocument();
      expect(screen.getByText("Runs keep using the last good snapshot.")).toBeInTheDocument();

      await choose(user, screen.getByLabelText("Refresh interval"), "Every hour");
      expect(api.requests("PUT /inventories/1/refresh-settings")[0]?.body).toEqual({ refresh_interval_seconds: 3600 });
    } finally {
      vi.useRealTimers();
    }
  });

  it("adds a source from an example with a credential, edits, toggles and deletes it", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /credentials": [credential({ id: 2, name: "netbox-token", kind: "env", env_names: ["NETBOX_TOKEN"] })],
        "POST /inventories/:id/sources": inventorySource(),
        "PATCH /inventories/:id/sources/:sid": inventorySource(),
        "DELETE /inventories/:id/sources/:sid": reply(204),
      }),
    });
    expect(await screen.findByText(/No sources yet/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add source" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "gen");
    await user.click(dialog.getByRole("button", { name: "generator" }));
    expect(editorText(dialog.getByLabelText("Plugin config (YAML)"))).toContain("ansible.builtin.generator");
    await choose(user, dialog.getByRole("combobox", { name: "Credential" }), "netbox-token (NETBOX_TOKEN)");
    api.set({ "GET /inventories/:id/sources": [inventorySource({ name: "gen", credential_id: 2, credential_name: "netbox-token" })] });
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("credential: netbox-token")).toBeInTheDocument();
    expect(api.requests("POST /inventories/1/sources")[0]?.body).toMatchObject({ name: "gen", credential_id: 2, enabled: true });

    await user.click(screen.getAllByRole("button", { name: "Edit" })[0]!); // the source's, above the hosts
    dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText("Name")).toHaveValue("gen");
    await user.click(dialog.getByRole("switch", { name: "Enabled" }));
    api.set({ "PATCH /inventories/:id/sources/:sid": reply(400, { detail: "plugin 'script' is not allowed" }) });
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("plugin 'script' is not allowed")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    api.set({ "PATCH /inventories/:id/sources/:sid": inventorySource({ enabled: false }) });
    await user.click(screen.getByRole("switch", { name: "gen enabled" }));
    expect(api.requests("PATCH /inventories/1/sources/1").at(-1)?.body).toEqual({ enabled: false });

    api.set({ "GET /inventories/:id/sources": [] });
    await user.click(screen.getAllByRole("button", { name: "Delete" })[0]!);
    await screen.findByText(/No sources yet/);
    expect(api.requests("DELETE /inventories/1/sources/1")).toHaveLength(1);
  });

  it("reports a refresh the API refuses", async () => {
    const { user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/sources": [inventorySource()],
        "POST /inventories/:id/refresh": reply(409, { detail: "No worker is online" }),
      }),
    });
    await user.click(await screen.findByRole("button", { name: "Refresh now" }));
    expect(await screen.findByText("No worker is online")).toBeInTheDocument();
  });
});

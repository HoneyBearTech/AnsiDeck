import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import {
  credential,
  egressSettings,
  hostKeys,
  inventory,
  inventorySource,
  refresh,
  targets,
  viewerUser,
} from "@/test/fixtures";
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
    "GET /inventories/:id/host-keys": hostKeys({ keys: [], hosts: [], total: 0 }),
    "GET /inventories/:id/egress": egressSettings({
      hosts: [],
      total: 0,
      summary: { hosts: 0, ok: 0, indirect: 0, local: 0, unknown: 0 },
    }),
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
    await user.click(screen.getByRole("button", { name: "New inventory" }));
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
    await user.click(await screen.findByRole("button", { name: "New inventory" }));
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

    await user.click(screen.getByRole("button", { name: "Add group" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "db");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    await screen.findByText("web1.example");
    expect(api.requests("POST /inventories/1/groups")[0]?.body).toEqual({ name: "db" });

    await user.click(screen.getByRole("button", { name: "Add host" }));
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
    await screen.findByRole("button", { name: "Add host" });
    expect(api.requests("POST /inventories/1/hosts")[0]?.body).toEqual({ hostname: "db1", vars: {}, group_ids: [1] });

    await user.click(screen.getByRole("button", { name: "Edit" }));
    dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText("Hostname")).toHaveValue("web1.example");
    await user.click(dialog.getByRole("checkbox", { name: "web" }));
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByRole("button", { name: "Add host" });
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
    await user.click(screen.getByRole("button", { name: "Add group" }));
    let dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "a b");
    await user.click(dialog.getByRole("button", { name: "Create" }));
    expect(await dialog.findByText("Group names use letters")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    await user.click(screen.getByRole("button", { name: "Add host" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Hostname"), "db:5432");
    await user.click(dialog.getByRole("button", { name: "Save" }));
    expect(await dialog.findByText("No ports in host names")).toBeInTheDocument();
  });

  it("is read-only for viewers, without an empty sources panel", async () => {
    const { screen } = renderApp("/inventories/1", { user: viewerUser(), routes: detail() });
    await screen.findByText("web1.example");
    expect(screen.queryByRole("button", { name: "Add host" })).not.toBeInTheDocument();
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
            : r.query.get("page") === "2"
              ? { total: 102, hosts: [{ name: "zz-last", origin: "source", groups: [], vars: {}, overridden: [] }] }
              : {
                total: 102,
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
    expect(await screen.findByText("Hosts a run sees (102)")).toBeInTheDocument();
    expect(screen.getByText("source + inventory")).toBeInTheDocument();
    expect(screen.getByText(/replace the source's: ansible_user/)).toBeInTheDocument();
    // 102 hosts: pages of 100 (this fake sends 2 on the first)
    const pages = screen.getByRole("navigation", { name: "Host pages" });
    expect(within(pages).getByText("1–2 of 102")).toBeInTheDocument();
    expect(within(pages).getByRole("button", { name: "Previous" })).toBeDisabled();
    await user.click(within(pages).getByRole("button", { name: "Next" }));
    expect(await screen.findByText("zz-last")).toBeInTheDocument();
    expect(within(pages).getByText("101–101 of 102")).toBeInTheDocument();
    expect(within(pages).getByRole("button", { name: "Next" })).toBeDisabled();

    await user.type(screen.getByLabelText("Search hosts"), "zzz");
    expect(await screen.findByText("No hosts match.")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/inventories/1/hosts" && c.query.get("q") === "zzz")).toBe(true);
  });

  it("shows what each source found, and a source that failed keeping its last output", async () => {
    const { screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/sources": [
          inventorySource({ output_refreshed_at: "2026-10-05T12:00:00Z", output_host_count: 12, output_group_count: 3 }),
          inventorySource({
            id: 2,
            name: "aws",
            plugin: "amazon.aws.aws_ec2",
            last_error: "10-src2.aws_ec2.yml: Could not connect to the endpoint URL\nmore",
            last_finished_at: "2026-10-05T13:00:00Z",
            output_refreshed_at: "2026-10-05T12:00:00Z",
            output_host_count: 40,
            output_group_count: 5,
          }),
          inventorySource({ id: 3, name: "groups", plugin: "ansible.builtin.constructed" }),
          inventorySource({ id: 4, name: "new" }),
        ],
        "GET /inventories/:id/targets": targets({
          has_sources: true,
          snapshot_id: 2,
          snapshot_at: "2026-10-05T13:00:00Z",
          last_refresh: refresh({ status: "failed", snapshot_id: 2, error: "source 'aws': 10-src2.aws_ec2.yml: Could not connect" }),
        }),
        "GET /inventories/:id/snapshot": SNAPSHOT,
      }),
    });
    expect(await screen.findByText(/^12 hosts, 3 groups as of/)).toBeInTheDocument();
    expect(screen.getByText(/^Failed .*: 10-src2\.aws_ec2\.yml: Could not connect to the endpoint URL$/)).toBeInTheDocument();
    expect(screen.getByText(/keeps 40 hosts, 5 groups as of/)).toBeInTheDocument();
    expect(screen.getByText("Applied in every refresh")).toBeInTheDocument();
    expect(screen.getByText("Not refreshed yet")).toBeInTheDocument();
    expect(
      screen.getByText("The other sources were updated; a source that failed keeps what it found last."),
    ).toBeInTheDocument();
  });

  it("lets project admins make runs refresh the sources first", async () => {
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/sources": [inventorySource()],
        "GET /inventories/:id/targets": targets({ has_sources: true }),
        "PUT /inventories/:id/refresh-settings": targets({ has_sources: true, refresh_before_run: true }),
      }),
    });
    const toggle = await screen.findByRole("switch", { name: "Refresh before every run" });
    expect(toggle).not.toBeChecked();
    await user.click(toggle);
    expect(api.requests("PUT /inventories/1/refresh-settings")[0]?.body).toEqual({ refresh_before_run: true });
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
        "GET /inventories/:id/targets": targets({ has_sources: true, snapshot_id: 1, snapshot_at: "2026-10-05T12:00:00Z", last_refresh: refresh({ status: "failed", error: "netbox: 401 Unauthorized", snapshot_id: null }) }),
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

    const edits = screen.getAllByRole("button", { name: "Edit" });
    await user.click(edits[edits.length - 1]!); // the source's: sources come after the hosts
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
    const deletes = screen.getAllByRole("button", { name: "Delete" });
    await user.click(deletes[deletes.length - 1]!); // the source's, the last on the page
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

describe("SSH host keys", () => {
  it("shows the mode, the hosts without a trusted key and the keys", async () => {
    const { api, screen } = renderApp("/inventories/1", {
      routes: detail({ "GET /inventories/:id/host-keys": hostKeys() }),
    });
    expect(await screen.findByText("SSH host keys")).toBeInTheDocument();
    expect(screen.getByLabelText("Host key mode")).toHaveTextContent("Learn new hosts");
    expect(screen.getByText("1 learned, unconfirmed")).toBeInTheDocument();
    expect(screen.getByText("1 no key yet")).toBeInTheDocument();
    expect(screen.getByText("db1")).toBeInTheDocument();
    expect(screen.getByText("SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "by run #7" })).toHaveAttribute("href", "/runs/7");
    expect(screen.getByText("unconfirmed")).toBeInTheDocument();
    expect(
      api.calls.some((c) => c.path === "/inventories/1/host-keys" && c.query.get("untrusted") === "true"),
    ).toBe(true);
    expect(screen.queryByText("host keys not checked")).not.toBeInTheDocument();
  });

  it("warns when an inventory doesn't check host keys", async () => {
    const { screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id": inventory({ host_key_checking: "off" }),
        "GET /inventories/:id/host-keys": hostKeys({ mode: "off", keys: [] }),
      }),
    });
    expect(await screen.findByText("host keys not checked")).toBeInTheDocument();
    // The panel loads on its own.
    expect(await screen.findByText("Host keys aren't checked")).toBeInTheDocument();
    expect(screen.getByText(/Learn new hosts is a safe start/)).toBeInTheDocument();
  });

  it("lets project admins change the mode, confirm learned keys, paste and remove keys", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/host-keys": hostKeys(),
        "PUT /inventories/:id/host-keys/mode": { mode: "strict" },
        "POST /inventories/:id/host-keys/confirm": [],
        "DELETE /inventories/:id/host-keys/:key": reply(204),
        "POST /inventories/:id/host-keys/paste": {
          keys: [
            {
              name: "db1",
              key_type: "ssh-ed25519",
              fingerprint: "SHA256:new",
              change: "replace",
              previous: "SHA256:old",
              hosts: ["db1"],
            },
          ],
          warnings: ["line 2: hashed names can't be used (one plain name per key)"],
        },
      }),
    });
    await screen.findByText("SSH host keys");

    await choose(user, screen.getByLabelText("Host key mode"), "Strict: confirmed keys only");
    expect(confirm.mock.calls.at(-1)?.[0]).toMatch(/2 hosts have no confirmed key/);
    expect(api.requests("PUT /inventories/1/host-keys/mode")[0]?.body).toEqual({ mode: "strict" });

    await user.click(screen.getByRole("button", { name: "Confirm learned (1)" }));
    expect(api.requests("POST /inventories/1/host-keys/confirm")[0]?.body).toEqual({ ids: [1] });

    await user.click(screen.getByRole("button", { name: "Paste known_hosts" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("known_hosts"), "db1 ssh-ed25519 AAAA");
    await user.click(dialog.getByRole("button", { name: "Preview" }));
    expect(await dialog.findByText("replaces a key")).toBeInTheDocument();
    expect(dialog.getByText("was SHA256:old")).toBeInTheDocument();
    expect(dialog.getByText(/hashed names can't be used/)).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Trust and replace" }));
    expect(api.requests("POST /inventories/1/host-keys/paste").map((r) => r.body)).toEqual([
      { known_hosts: "db1 ssh-ed25519 AAAA", dry_run: true },
      { known_hosts: "db1 ssh-ed25519 AAAA", dry_run: false },
    ]);

    await user.click(screen.getByRole("button", { name: "Remove" }));
    expect(confirm.mock.calls.at(-1)?.[0]).toMatch(/its next run learns whatever key it is shown/);
    expect(api.requests("DELETE /inventories/1/host-keys/1")).toHaveLength(1);
  });

  it("scans the hosts' keys in a worker and trusts the ones picked", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    try {
      const queued = {
        id: 3,
        status: "queued",
        wait_reason: "Waiting for a worker that can scan host keys…",
        error: null,
        requested_by: "admin",
        queued_at: "2026-10-14T12:00:00Z",
        finished_at: null,
        targets: 3,
        keys: [],
        silent: [],
      };
      const { api, user, screen } = renderApp("/inventories/1", {
        routes: detail({
          "GET /inventories/:id/host-keys": hostKeys(),
          "POST /inventories/:id/host-key-scans": queued,
          "GET /inventories/:id/host-key-scans/:scan": queued,
          "POST /inventories/:id/host-keys/trust": [],
        }),
      });
      await user.click(await screen.findByRole("button", { name: "Scan host keys" }));
      const dialog = within(await screen.findByRole("dialog"));
      await user.type(dialog.getByLabelText("Jump hosts (optional)"), "bastion [[10.0.0.1]:2222");
      await user.click(dialog.getByRole("button", { name: "Scan" }));
      expect(await dialog.findByText("Waiting for a worker that can scan host keys…")).toBeInTheDocument();
      expect(api.requests("POST /inventories/1/host-key-scans")[0]?.body).toEqual({
        extra: ["bastion", "[10.0.0.1]:2222"],
      });

      api.set({
        "GET /inventories/:id/host-key-scans/:scan": {
          ...queued,
          status: "success",
          wait_reason: null,
          finished_at: "2026-10-14T12:00:05Z",
          silent: ["bastion"],
          keys: [
            { name: "[10.0.0.5]:2222", key_type: "ssh-ed25519", fingerprint: "SHA256:aaa", hosts: ["web1.example"],
              state: "learned", previous: null },
            { name: "db1", key_type: "ssh-ed25519", fingerprint: "SHA256:new", hosts: ["db1"], state: "changed",
              previous: "SHA256:old" },
            { name: "db2", key_type: "ssh-rsa", fingerprint: "SHA256:ok", hosts: ["db2"], state: "trusted",
              previous: null },
          ],
        },
      });
      await vi.advanceTimersByTimeAsync(2000);
      expect(await dialog.findByText("differs from the trusted key")).toBeInTheDocument();
      expect(dialog.getByText("trusted now: SHA256:old")).toBeInTheDocument();
      expect(dialog.getByText(/No key from bastion/)).toBeInTheDocument();
      expect(dialog.getByLabelText("Trust the ssh-rsa key of db2")).toBeDisabled();

      await user.click(dialog.getByRole("button", { name: "Select the learned keys that match" }));
      await user.click(dialog.getByLabelText("Trust the ssh-ed25519 key of db1"));
      await user.click(dialog.getByRole("button", { name: "Trust selected (2)" }));
      expect(confirm.mock.calls.at(-1)?.[0]).toMatch(/Replace the trusted key of db1/);
      expect(api.requests("POST /inventories/1/host-keys/trust")[0]?.body).toEqual({
        scan_id: 3,
        keys: [
          { name: "[10.0.0.5]:2222", key_type: "ssh-ed25519" },
          { name: "db1", key_type: "ssh-ed25519" },
        ],
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("is read-only for everyone else", async () => {
    const { screen } = renderApp("/inventories/1", {
      user: viewerUser(),
      routes: detail({ "GET /inventories/:id/host-keys": hostKeys() }),
    });
    expect(await screen.findByText("SSH host keys")).toBeInTheDocument();
    expect(screen.getByText("Learn new hosts")).toBeInTheDocument();
    expect(screen.queryByLabelText("Host key mode")).not.toBeInTheDocument();
    for (const name of ["Scan host keys", "Paste known_hosts", "Confirm learned (1)", "Remove"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });
});

describe("network egress", () => {
  it("shows where each host connects, and lets project admins restrict runs and add entries", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/inventories/1", {
      routes: detail({
        "GET /inventories/:id/egress": egressSettings(),
        "PUT /inventories/:id/egress/mode": { restricted: true },
        "PUT /inventories/:id/egress/extras": reply(400, { detail: "entry 2: ::/0 is every address" }),
      }),
    });
    expect(await screen.findByText("Network")).toBeInTheDocument();
    expect(screen.getByText("via bastion.example:22")).toBeInTheDocument();
    expect(screen.getByText("its address is set by a template")).toBeInTheDocument();
    expect(screen.getByText("1 address unknown")).toBeInTheDocument();

    await choose(user, screen.getByLabelText("Network access"), "Only its hosts");
    expect(confirm.mock.calls.at(-1)?.[0]).toMatch(/1 host's address isn't known before a run/);
    expect(api.requests("PUT /inventories/1/egress/mode")[0]?.body).toEqual({ restricted: true });

    const extras = screen.getByLabelText("Extra entries");
    await user.type(extras, "pypi.org 443  # packages{Enter}{Enter}::/0");
    await user.click(screen.getByRole("button", { name: "Save entries" }));
    // The server numbers entries; the message names the line (blank lines don't count there).
    expect(await screen.findByText("line 3: ::/0 is every address")).toBeInTheDocument();
    expect(api.requests("PUT /inventories/1/egress/extras")[0]?.body).toEqual({
      extras: [
        { target: "pypi.org", ports: "443", note: "packages" },
        { target: "::/0", ports: null, note: null },
      ],
    });

    api.set({
      "PUT /inventories/:id/egress/extras": [{ target: "pypi.org", ports: [[443, 443]], note: "packages" }],
      "GET /inventories/:id/egress": egressSettings({
        restricted: true,
        extras: [{ target: "pypi.org", ports: [[443, 443]], note: "packages" }],
      }),
    });
    await user.clear(extras);
    await user.type(extras, "pypi.org 443 # packages");
    await user.click(screen.getByRole("button", { name: "Save entries" }));
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    expect(screen.getByLabelText("Extra entries")).toHaveValue("pypi.org 443 # packages");

    confirm.mockReturnValue(false);
    await choose(user, screen.getByLabelText("Network access"), "Any address");
    expect(confirm.mock.calls.at(-1)?.[0]).toMatch(/reach any address again/);
    expect(api.requests("PUT /inventories/1/egress/mode")).toHaveLength(1);
  });

  it("is read-only for everyone else", async () => {
    const { screen } = renderApp("/inventories/1", {
      user: viewerUser(),
      routes: detail({
        "GET /inventories/:id": inventory({ egress_restricted: true }),
        "GET /inventories/:id/egress": egressSettings({
          restricted: true,
          extras: [{ target: "10.9.0.0/24", ports: null, note: null }],
        }),
      }),
    });
    expect(await screen.findByText("Network")).toBeInTheDocument();
    expect(screen.getByText("network restricted")).toBeInTheDocument();
    expect(screen.getByText("Only its hosts")).toBeInTheDocument();
    expect(screen.getByText("10.9.0.0/24 (any port)")).toBeInTheDocument();
    expect(screen.queryByLabelText("Network access")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Extra entries")).not.toBeInTheDocument();
  });
});

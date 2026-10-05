import { act } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { FakeWebSocket } from "@/test/fake-websocket";
import { credential, inventory, playbook, refresh, run, targets, vaultPassword, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

describe("runs list", () => {
  it("lists runs with their target, commit and options", async () => {
    const { screen } = renderApp("/runs", {
      routes: {
        "GET /runs": [
          run({ group_name: "web", git_commit: "0123456789abcdef", become: true, check_mode: true, diff_mode: true }),
          run({ id: 8, status: "timed_out" }),
        ],
      },
    });
    expect(await screen.findByText("site.yml → lab / web")).toBeInTheDocument();
    expect(screen.getByText("01234567")).toBeInTheDocument();
    expect(screen.getByText(/· become · check · diff/)).toBeInTheDocument();
    expect(screen.getByText("timed out")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New Run" })).toBeInTheDocument();
  });

  it("says when there are none, without a New Run button for viewers", async () => {
    const { screen } = renderApp("/runs", { user: viewerUser(), routes: { "GET /runs": [] } });
    expect(await screen.findByText("No runs yet.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "New Run" })).not.toBeInTheDocument();
  });
});

const TRIGGER = {
  "GET /playbooks": [
    playbook(),
    playbook({ id: 2, name: "other-project.yml", project_id: 2 }),
    playbook({ id: 3, name: "gone.yml", missing_at: "2026-10-01T00:00:00Z" }),
    playbook({ id: 4, name: "deploy.yml", source_id: 1, source_name: "infra" }),
  ],
  "GET /inventories": [inventory(), inventory({ id: 2, name: "elsewhere", project_id: 2 })],
  "GET /credentials": [credential(), credential({ id: 2, name: "foreign-key", project_id: 2 })],
  "GET /vault-passwords": [vaultPassword()],
  "GET /inventories/:id/targets": targets({
    has_sources: true,
    hosts: 3,
    snapshot_at: "2026-10-05T12:00:00Z",
    groups: [
      { name: "web", hosts: 1, origin: "static" },
      { name: "site_lab", hosts: 2, origin: "source" },
    ],
    last_refresh: refresh({ status: "failed" }),
  }),
};

describe("new run", () => {
  it("starts a run with every option and opens it", async () => {
    const { api, user, screen } = renderApp("/runs/new", {
      routes: { ...TRIGGER, "POST /runs": run({ id: 42 }), "GET /runs/:id": run({ id: 42 }) },
    });
    await screen.findByRole("heading", { name: "New Run" });
    await user.click(screen.getByLabelText("Playbook"));
    expect(await screen.findByRole("option", { name: "deploy.yml (git: infra)" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "gone.yml" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("option", { name: "site.yml" }));

    await user.click(screen.getByLabelText("Inventory"));
    expect(screen.queryByRole("option", { name: "elsewhere" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("option", { name: "lab" }));
    expect(await screen.findByText(/The last refresh failed: Dynamic hosts as of/)).toBeInTheDocument();
    await choose(user, screen.getByLabelText("Target"), "Group: site_lab (2) · from a source");
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");
    await choose(user, screen.getByLabelText("Vault password (optional)"), "prod-vault");
    await user.type(screen.getByLabelText("Limit (optional)"), " web1 ");
    await user.clear(screen.getByLabelText("Timeout (minutes)"));
    await user.type(screen.getByLabelText("Timeout (minutes)"), "30");
    await user.click(screen.getByRole("checkbox", { name: /Check mode/ }));
    await user.click(screen.getByRole("checkbox", { name: /Diff mode/ }));
    await user.clear(screen.getByLabelText("Extra vars (JSON)"));
    await user.type(screen.getByLabelText("Extra vars (JSON)"), '{{"release": "1.2"}');

    await user.click(screen.getByRole("switch", { name: "Run as admin (become root)" }));
    expect(screen.getByRole("button", { name: "Trigger Run" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I understand this grants root/ }));
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));

    await screen.findByText("Live output");
    expect(api.requests("POST /runs")[0]?.body).toEqual({
      playbook_id: 1,
      inventory_id: 1,
      group_name: "site_lab",
      credential_id: 1,
      vault_password_id: 1,
      become: true,
      check_mode: true,
      diff_mode: true,
      limit: "web1",
      extra_vars: { release: "1.2" },
      timeout_seconds: 1800,
    });
  });

  it("checks extra vars and the timeout, and shows refusals", async () => {
    const { user, screen } = renderApp("/runs/new", {
      routes: {
        ...TRIGGER,
        "GET /inventories/:id/targets": targets({ has_sources: true }),
        "POST /runs": reply(409, { detail: "The inventory has no snapshot yet" }),
      },
    });
    await choose(user, await screen.findByLabelText("Playbook"), "site.yml");
    await choose(user, screen.getByLabelText("Inventory"), "lab");
    expect(await screen.findByText(/haven't been refreshed yet/)).toBeInTheDocument();
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");

    await user.clear(screen.getByLabelText("Extra vars (JSON)"));
    await user.type(screen.getByLabelText("Extra vars (JSON)"), "nope");
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    expect(await screen.findByText("Extra vars must be valid JSON")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Extra vars (JSON)"));
    await user.type(screen.getByLabelText("Extra vars (JSON)"), "{{}");
    await user.clear(screen.getByLabelText("Timeout (minutes)"));
    await user.type(screen.getByLabelText("Timeout (minutes)"), "5000");
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    expect(await screen.findByText(/Timeout must be a whole number of minutes from 1 to 1440/)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Timeout (minutes)"));
    await user.type(screen.getByLabelText("Timeout (minutes)"), "60");
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    expect(await screen.findByText("The inventory has no snapshot yet")).toBeInTheDocument();
  });

  it("clears picks from another project when the playbook changes project", async () => {
    const { user, screen } = renderApp("/runs/new", { routes: TRIGGER });
    await choose(user, await screen.findByLabelText("Playbook"), "site.yml");
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");
    await choose(user, screen.getByLabelText("Playbook"), "other-project.yml");
    expect(screen.getByLabelText("Credential")).toHaveTextContent("Select a credential");
    await user.click(screen.getByLabelText("Credential"));
    expect(await screen.findByRole("option", { name: "foreign-key" })).toBeInTheDocument();
  });
});

describe("run detail", () => {
  it("shows the run's summary, git commit, extra vars and output", async () => {
    const { screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": run({
          vault_password_name: "prod-vault",
          limit: "web1",
          become: true,
          check_mode: true,
          diff_mode: true,
          extra_vars: { release: "1.2", token: "********" },
          hosts_total: 3,
          hosts_ok: 1,
          hosts_changed: 1,
          hosts_failed: 1,
          hosts_unreachable: 0,
          queued_at: "2026-10-05T12:00:00Z",
          started_at: "2026-10-05T12:00:02Z",
          finished_at: "2026-10-05T12:01:35Z",
          return_code: 2,
          status: "failed",
          git_source_name: "infra",
          git_commit: "0123456789abcdef",
          playbook_path: "site.yml",
          commit_url: "https://git.example/infra/commit/0123456789abcdef",
        }),
      },
    });
    expect(await screen.findByText(/vault: prod-vault · become · check · diff · limit: web1/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "01234567" })).toHaveAttribute("href", "https://git.example/infra/commit/0123456789abcdef");
    expect(screen.getByText("3 hosts")).toBeInTheDocument();
    expect(screen.getByText("1 changed")).toBeInTheDocument();
    expect(screen.getByText("waited 2.0 s")).toBeInTheDocument();
    expect(screen.getByText("ran 1 min 33 s")).toBeInTheDocument();
    expect(screen.getByText("exit code 2")).toBeInTheDocument();
    expect(screen.getByText(/"release": "1.2"/)).toBeInTheDocument();

    const socket = FakeWebSocket.instances[0]!;
    expect(socket.url).toContain("/api/runs/7/ws");
    act(() => {
      socket.open();
      socket.emit({ stdout: "\u001b[32mok: [web1]\u001b[0m", counter: 1 });
      socket.emit({ stdout: "", counter: 2 });
      socket.dispatchEvent(new MessageEvent("message", { data: "not json" }));
    });
    expect(await screen.findByText("ok: [web1]")).toBeInTheDocument();
    act(() => socket.close(1000));
  });

  it("explains a queued run, polls it, and cancels it after confirming", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    try {
      const { api, user, screen } = renderApp("/runs/7", {
        routes: {
          "GET /runs/:id": run({ status: "queued", started_at: null, finished_at: null, return_code: null, hosts_total: null, waiting_reason: "Waiting behind run #6 on this inventory" }),
          "POST /runs/:id/cancel": run({ status: "cancelled", status_reason: "Cancelled by admin" }),
        },
      });
      expect(await screen.findByText("Waiting behind run #6 on this inventory")).toBeInTheDocument();
      api.set({ "GET /runs/:id": run({ status: "running", finished_at: null, cancel_requested_at: null }) });
      await vi.advanceTimersByTimeAsync(1100);
      expect(await screen.findByText("running")).toBeInTheDocument();

      api.set({ "GET /runs/:id": run({ status: "cancelled", status_reason: "Cancelled by admin" }) });
      await user.click(screen.getByRole("button", { name: "Cancel run" }));
      expect(await screen.findByText("Cancelled by admin")).toBeInTheDocument();
      expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Ansible is stopped where it is"));
      expect(screen.queryByRole("button", { name: "Cancel run" })).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the run when cancelling isn't confirmed, and shows a refused cancel", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const { api, user, screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": run({ status: "running", finished_at: null, cancel_requested_at: null }),
        "POST /runs/:id/cancel": reply(409, { detail: "The run already finished" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Cancel run" }));
    expect(api.requests("POST /runs/7/cancel")).toHaveLength(0);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Cancel run" }));
    expect(await screen.findByText("The run already finished")).toBeInTheDocument();
  });

  it("shows a cancel in progress, and a run with no output", async () => {
    const { screen } = renderApp("/runs/7", {
      routes: { "GET /runs/:id": run({ status: "running", finished_at: null, cancel_requested_at: "2026-10-05T12:00:05Z" }) },
    });
    expect(await screen.findByRole("button", { name: "Cancelling…" })).toBeDisabled();
    expect(screen.getAllByText("Cancelling…")).toHaveLength(2);
    act(() => FakeWebSocket.instances[0]!.close(1000));
    expect(await screen.findByText("This run produced no output.")).toBeInTheDocument();
  });
});

describe("live output", () => {
  it("reconnects from where it left off, and gives up when access is denied", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { screen } = renderApp("/runs/7", { routes: { "GET /runs/:id": run() } });
      await screen.findByText("Live output");
      const first = FakeWebSocket.instances[0]!;
      act(() => {
        first.open();
        first.emit({ stdout: "line one", counter: 1 });
        first.close(1006);
      });
      expect(await screen.findByText("Connection lost. Reconnecting…")).toBeInTheDocument();
      await vi.advanceTimersByTimeAsync(1100);
      const second = FakeWebSocket.instances[1]!;
      expect(second.url).toContain("from=1");
      act(() => second.close(1008));
      expect(await screen.findByText(/Live output is unavailable/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

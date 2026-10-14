import { act } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { setEditorText } from "@/test/editor";
import { reply } from "@/test/fake-api";
import { FakeWebSocket } from "@/test/fake-websocket";
import { adminUser, credential, inventory, playbook, project, refresh, run, targets, vaultPassword, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

describe("runs list", () => {
  it("lists runs with their target, commit and options", async () => {
    const { screen } = renderApp("/runs", {
      routes: {
        "GET /runs": [
          run({ group_name: "web", git_commit: "0123456789abcdef", become: true, check_mode: true, diff_mode: true, limit: "web1" }),
          run({ id: 8, status: "timed_out", hosts_total: 3, hosts_failed: 1, hosts_unreachable: 1 }),
        ],
      },
    });
    const title = await screen.findByText((_, el) => el?.textContent === "site.yml →\u00a0lab /\u00a0web" && el.tagName === "SPAN");
    expect(title.closest("a")).toHaveAttribute("href", "/runs/7");
    expect(screen.getByText("#7")).toBeInTheDocument();
    expect(screen.getByText("· 01234567")).toBeInTheDocument();
    for (const option of ["become", "check", "diff", "limit: web1"]) expect(screen.getByText(option)).toBeInTheDocument();
    expect(screen.getByText("· 3 hosts, 2 failed")).toHaveClass("text-status-failed");
    expect(screen.getAllByText("· took 0.0 s")).toHaveLength(2);
    expect(screen.getByText("timed out")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New run" })).toBeInTheDocument();
  });

  it("says when there are none, without a New run button for viewers", async () => {
    const { screen } = renderApp("/runs", { user: viewerUser(), routes: { "GET /runs": [] } });
    expect(await screen.findByText("No runs yet.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "New run" })).not.toBeInTheDocument();
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
    await screen.findByRole("heading", { name: "New run" });
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
    setEditorText(screen.getByLabelText("Extra vars (JSON)"), '{"release": "1.2"}');

    await user.click(screen.getByRole("switch", { name: "Run as admin (become root)" }));
    expect(screen.getByRole("button", { name: "Start run" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I understand this grants root/ }));
    await user.click(screen.getByRole("button", { name: "Start run" }));

    await screen.findByText(/^(Live )?[Oo]utput$/);
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
      refresh_first: null,
      env_credential_ids: [],
    });
  });

  it("refreshes the inventory first as the inventory says, unless unticked", async () => {
    const { api, user, screen } = renderApp("/runs/new", {
      routes: {
        ...TRIGGER,
        "GET /inventories/:id/targets": targets({
          has_sources: true,
          snapshot_at: null,
          refresh_before_run: true,
        }),
        "POST /runs": run({ id: 42, refresh_first: true }),
        "GET /runs/:id": run({ id: 42, refresh_first: true, inventory_snapshot_at: "2026-10-14T12:00:00Z" }),
      },
    });
    await screen.findByRole("heading", { name: "New run" });
    await choose(user, screen.getByLabelText("Playbook"), "site.yml");
    await choose(user, screen.getByLabelText("Inventory"), "lab");
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");
    expect(await screen.findByText(/haven't been refreshed yet: refresh them first/)).toBeInTheDocument();
    const box = screen.getByRole("checkbox", { name: /Refresh the dynamic sources first/ });
    expect(box).toBeChecked(); // the inventory's default
    await user.click(box);
    await user.click(box);
    await user.click(screen.getByRole("button", { name: "Start run" }));
    expect(await screen.findByText(/^Inventory sources refreshed for this run: /)).toBeInTheDocument();
    expect(api.requests("POST /runs")[0]?.body).toMatchObject({ refresh_first: true });
  });

  it("gives the run environment credentials of its project", async () => {
    const { api, user, screen } = renderApp("/runs/new", {
      routes: {
        ...TRIGGER,
        "GET /credentials": [
          credential(),
          credential({ id: 5, name: "aws", kind: "env", env_names: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] }),
          credential({ id: 6, name: "foreign-env", kind: "env", project_id: 2 }),
        ],
        "POST /runs": run({ id: 42, env_credential_ids: [5], env_credential_names: ["aws"] }),
        "GET /runs/:id": run({ id: 42, env_credential_ids: [5], env_credential_names: ["aws"] }),
      },
    });
    await screen.findByRole("heading", { name: "New run" });
    await choose(user, screen.getByLabelText("Playbook"), "site.yml");
    await choose(user, screen.getByLabelText("Inventory"), "lab");
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");
    expect(screen.getByText("(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")).toBeInTheDocument();
    expect(screen.queryByText("foreign-env")).not.toBeInTheDocument(); // another project's
    await user.click(screen.getByRole("checkbox", { name: /^aws/ }));
    await user.click(screen.getByRole("button", { name: "Start run" }));
    expect(await screen.findByText(/· environment: aws/)).toBeInTheDocument();
    expect(api.requests("POST /runs")[0]?.body).toMatchObject({ env_credential_ids: [5] });
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

    setEditorText(screen.getByLabelText("Extra vars (JSON)"), "nope");
    await user.click(screen.getByRole("button", { name: "Start run" }));
    expect(await screen.findByText("Extra vars must be valid JSON")).toBeInTheDocument();

    setEditorText(screen.getByLabelText("Extra vars (JSON)"), "{}");
    await user.clear(screen.getByLabelText("Timeout (minutes)"));
    await user.type(screen.getByLabelText("Timeout (minutes)"), "5000");
    await user.click(screen.getByRole("button", { name: "Start run" }));
    expect(await screen.findByText(/Timeout must be a whole number of minutes from 1 to 1440/)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Timeout (minutes)"));
    await user.type(screen.getByLabelText("Timeout (minutes)"), "60");
    await user.click(screen.getByRole("button", { name: "Start run" }));
    expect(await screen.findByText("The inventory has no snapshot yet")).toBeInTheDocument();
  });

  it("clears picks from another project when the playbook changes project", async () => {
    const { user, screen } = renderApp("/runs/new", { routes: TRIGGER });
    await choose(user, await screen.findByLabelText("Playbook"), "site.yml");
    await choose(user, screen.getByLabelText("Credential"), "deploy-key");
    await choose(user, screen.getByLabelText("Playbook"), "other-project.yml");
    // deploy-key (the other project's) is gone; that project's only credential is picked instead
    expect(screen.getByLabelText("Credential")).toHaveTextContent("foreign-key");
    await user.click(screen.getByLabelText("Credential"));
    expect(screen.queryByRole("option", { name: "deploy-key" })).not.toBeInTheDocument();
  });

  it("picks the only choice and says why Start run is disabled", async () => {
    const { screen } = renderApp("/runs/new", {
      routes: { ...TRIGGER, "GET /playbooks": [playbook()], "GET /credentials": [credential()] },
    });
    await vi.waitFor(() => expect(screen.getByLabelText("Playbook")).toHaveTextContent("site.yml"));
    expect(screen.getByLabelText("Credential")).toHaveTextContent("deploy-key");
    expect(screen.getByLabelText("Inventory")).toHaveTextContent("lab");
    expect(await screen.findByRole("button", { name: "Start run" })).toBeEnabled();
    expect(screen.queryByText(/to start a run/)).not.toBeInTheDocument();
  });

  it("keeps Start run disabled, with the reason, until everything is picked", async () => {
    const { user, screen } = renderApp("/runs/new", { routes: { ...TRIGGER, "GET /credentials": [] } });
    await choose(user, await screen.findByLabelText("Playbook"), "site.yml");
    expect(screen.getByLabelText("Inventory")).toHaveTextContent("lab"); // the project's only one
    expect(screen.getByRole("button", { name: "Start run" })).toBeDisabled();
    expect(screen.getByText("Pick a playbook, an inventory and a credential to start a run.")).toBeInTheDocument();
  });
});

describe("run detail", () => {
  it("lists a run's artifacts, downloadable by those who can start runs", async () => {
    const files = { files: [{ path: "reports/web1.txt", size: 2048 }], bytes: 2048, error: null, deleted_at: null };
    const { screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": run({ artifacts_count: 1, artifacts_bytes: 2048 }),
        "GET /runs/:id/artifacts": { ...files, can_download: true },
      },
    });
    expect(await screen.findByRole("link", { name: "Download all (.tar.gz)" })).toHaveAttribute(
      "href",
      "/api/runs/7/artifacts/download",
    );
    expect(screen.getByRole("link", { name: "reports/web1.txt" })).toHaveAttribute(
      "href",
      "/api/runs/7/artifacts/file?path=reports%2Fweb1.txt",
    );
    expect(screen.getByText("2.0 KB")).toBeInTheDocument();
  });

  it("shows artifacts without links to viewers, and why some weren't kept", async () => {
    const { screen } = renderApp("/runs/7", {
      user: viewerUser(),
      routes: {
        "GET /runs/:id": run({ artifacts_count: 1, artifacts_error: null }),
        "GET /runs/:id/artifacts": {
          files: [{ path: "out.json", size: 10 }], bytes: 10, error: null, deleted_at: null, can_download: false,
        },
      },
    });
    expect(await screen.findByText("out.json")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "out.json" })).not.toBeInTheDocument();
    expect(screen.getByText(/Only people who can start runs may download artifacts/)).toBeInTheDocument();
  });

  it("shows hosts whose SSH host key was refused, and how keys were checked", async () => {
    const problems = [
      {
        host: "web1",
        problem: "changed" as const,
        name: "[10.0.0.5]:2222",
        key_type: "ED25519",
        presented: "SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo",
      },
      { host: "web2", problem: "unknown" as const, name: "web2", key_type: "ED25519", presented: null },
    ];
    const { screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": run({
          status: "failed",
          status_reason: "SSH host key changed for web1, web2",
          host_key_problems: problems,
          host_keys_learned: 2,
        }),
      },
    });
    expect(await screen.findByText("A host presented a different SSH host key")).toBeInTheDocument();
    expect(screen.getByText("SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo")).toBeInTheDocument();
    expect(screen.getByText(/no trusted key \(strict mode\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review the inventory's host keys" })).toHaveAttribute(
      "href",
      "/inventories/1#host-keys",
    );
    expect(
      screen.getByText("SSH host keys checked, new hosts learned · 2 new keys learned"),
    ).toBeInTheDocument();
  });

  it("asks a project admin to review host keys when the viewer can't", async () => {
    const { screen } = renderApp("/runs/7", {
      user: viewerUser(),
      routes: {
        "GET /runs/:id": run({
          status: "failed",
          host_key_checking: "strict",
          host_key_problems: [
            { host: "web1", problem: "failed", name: null, key_type: null, presented: null },
          ],
        }),
      },
    });
    expect(await screen.findByText("ssh refused a host's key")).toBeInTheDocument();
    expect(screen.getByText(/Ask a project admin to review the inventory's host keys/)).toBeInTheDocument();
    expect(screen.getByText("SSH host keys checked, confirmed keys only")).toBeInTheDocument();
  });

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
          inventory_snapshot_at: "2026-10-05T11:58:00Z",
          inventory_snapshot_hosts: 12,
        }),
      },
    });
    expect(await screen.findByText(/vault: prod-vault · become · check · diff · limit: web1/)).toBeInTheDocument();
    expect(
      screen.getByText(`Inventory sources as of ${new Date("2026-10-05T11:58:00Z").toLocaleString()} · 12 hosts from them`),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "01234567" })).toHaveAttribute("href", "https://git.example/infra/commit/0123456789abcdef");
    expect(screen.getByText("3 hosts")).toBeInTheDocument();
    expect(screen.getByText("1 changed")).toBeInTheDocument();
    expect(screen.getByText("waited 2.0 s")).toBeInTheDocument();
    expect(screen.getByText("ran 1 min 33 s")).toBeInTheDocument();
    expect(screen.getByText("exit code 2")).toBeInTheDocument();
    expect(screen.getByText(/"release": "1.2"/)).toBeInTheDocument();

    const socket = await FakeWebSocket.opened();
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
    const socket = await FakeWebSocket.opened();
    act(() => socket.close(1000));
    expect(await screen.findByText("This run produced no output.")).toBeInTheDocument();
  });
});

describe("live output", () => {
  it("reconnects from where it left off, and gives up when access is denied", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { screen } = renderApp("/runs/7", { routes: { "GET /runs/:id": run() } });
      await screen.findByText(/^(Live )?[Oo]utput$/);
      const first = await FakeWebSocket.opened();
      act(() => {
        first.open();
        first.emit({ stdout: "line one", counter: 1 });
        first.close(1006);
      });
      expect(await screen.findByText("Connection lost. Reconnecting…")).toBeInTheDocument();
      await vi.advanceTimersByTimeAsync(1100);
      const second = await FakeWebSocket.opened(1);
      expect(second.url).toContain("from=1");
      act(() => second.close(1008));
      expect(await screen.findByText(/Live output is unavailable/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("hostile output", () => {
  it("shows terminal links as text and keeps colours from leaking into later lines", async () => {
    const { screen } = renderApp("/runs/7", { routes: { "GET /runs/:id": run() } });
    await screen.findByText(/^(Live )?[Oo]utput$/);
    const socket = await FakeWebSocket.opened();
    act(() => {
      socket.open();
      // From a managed host's output: a disguised link, then black on black left switched on.
      const link = "\u001b]8;;https://example.invalid/login\u001b\\Click to continue\u001b]8;;\u001b\\";
      socket.emit({ stdout: `see ${link} now`, counter: 1 });
      socket.emit({ stdout: "ok: [web1] \u001b[30;40mdark\nstill hidden?", counter: 2 });
      socket.emit({ stdout: "fatal: [web2]: FAILED!", counter: 3 });
    });
    const linked = await screen.findByText("see Click to continue now");
    expect(linked.querySelector("a") ?? linked.closest("a")).toBeNull(); // text only, no link
    const failed = await screen.findByText("fatal: [web2]: FAILED!");
    expect(failed.closest("span[style]")).toBeNull(); // the next task's line keeps its own colours
    const chunk = screen.getByText(/still hidden\?/);
    expect(chunk.innerHTML).toMatch(/<\/span>\nstill hidden\?$/); // dark ends with its line
    act(() => socket.close(1000));
  });
});

describe("small polish", () => {
  it("opens New run with the playbook picked from its Run button", async () => {
    const { screen } = renderApp("/runs/new?playbook=4", { routes: TRIGGER });
    await vi.waitFor(() => expect(screen.getByLabelText("Playbook")).toHaveTextContent("deploy.yml (git: infra)"));
  });

  it("shows each row's project when viewing all projects", async () => {
    const { screen } = renderApp("/runs", {
      activeProject: null,
      user: adminUser({ projects: [project(), project({ id: 2, name: "Staging" })] }),
      routes: { "GET /runs": [run(), run({ id: 8, project_id: 2 })] },
    });
    expect(await screen.findByText("Default")).toBeInTheDocument();
    expect(screen.getByText("Staging")).toBeInTheDocument();
  });
});

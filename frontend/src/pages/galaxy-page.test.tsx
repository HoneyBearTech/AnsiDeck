import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { viewerUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

function install(overrides = {}) {
  return {
    id: 3,
    status: "success",
    status_reason: null,
    triggered_by: "admin",
    upgrade: false,
    return_code: 0,
    started_at: "2026-10-05T12:00:00Z",
    finished_at: "2026-10-05T12:01:00Z",
    created_at: "2026-10-05T12:00:00Z",
    waiting_for_runs: null,
    requirements_snapshot: "collections: []",
    log: "",
    ...overrides,
  };
}

const BASE = {
  "GET /galaxy/requirements": { content: "collections:\n  - name: community.general\n" },
  "GET /galaxy/installed": { collections: [{ name: "community.general", version: "9.0.0" }], roles: [{ name: "geerlingguy.docker", version: null }] },
  "GET /galaxy/installs": [],
};

describe("galaxy", () => {
  it("saves requirements, installs them and follows the install to the end", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, user, screen } = renderApp("/galaxy", {
        routes: {
          ...BASE,
          "PUT /galaxy/requirements": (r: { body: { content: string } }) => ({ content: r.body.content }),
          "POST /galaxy/installs": install({ status: "queued", waiting_for_runs: 2, log: "" }),
          "GET /galaxy/installs/:id": install({ status: "running", log: "Starting galaxy collection install process\n" }),
        },
      });
      expect(await screen.findByText("community.general")).toBeInTheDocument();
      expect(screen.getByText("unknown version")).toBeInTheDocument();
      const editor = screen.getByLabelText("requirements.yml");
      await user.type(editor, "  - name: ansible.posix\n");
      expect(screen.getByText("Save your changes first.")).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Save" }));
      expect(await screen.findByRole("button", { name: "Saved" })).toBeDisabled();
      expect(api.requests("PUT /galaxy/requirements")[0]?.body).toEqual({
        content: "collections:\n  - name: community.general\n  - name: ansible.posix\n",
      });

      await user.click(screen.getByRole("checkbox", { name: /Upgrade \/ reinstall/ }));
      expect(screen.getByRole("button", { name: "Install" })).toBeDisabled();
      await user.click(screen.getByRole("checkbox", { name: /runs third-party code/ }));
      await user.click(screen.getByRole("button", { name: "Install" }));
      expect(await screen.findByText(/Waiting for 2 running runs to finish/)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Queued…" })).toBeDisabled();
      expect(api.requests("POST /galaxy/installs")[0]?.body).toEqual({ upgrade: true });

      await vi.advanceTimersByTimeAsync(1600);
      expect(await screen.findByText(/Starting galaxy collection install process/)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Installing…" })).toBeDisabled();

      api.set({
        "GET /galaxy/installs/:id": install({ status: "failed", status_reason: "exit code 1", log: "ERROR! not found" }),
        "GET /galaxy/installs": [install({ status: "failed" })],
      });
      await vi.advanceTimersByTimeAsync(1600);
      expect(await screen.findByText("exit code 1")).toBeInTheDocument();
      expect(await screen.findByText(/#3 · admin/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("opens past installs, and explains a refused save or install", async () => {
    const { user, screen } = renderApp("/galaxy", {
      routes: {
        ...BASE,
        "GET /galaxy/installs": [install({ upgrade: true }), install({ id: 4, status: "queued", waiting_for_runs: 1 })],
        "GET /galaxy/installs/:id": (r: { params: { id: string } }) =>
          r.params.id === "3" ? install({ log: "done" }) : install({ id: 4, status: "queued", waiting_for_runs: 1 }),
        "PUT /galaxy/requirements": reply(400, { detail: "Local paths are not allowed" }),
        "POST /galaxy/installs": reply(409, { detail: "An install is already running" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: /#3 · admin .* · upgrade/ }));
    expect(await screen.findByText("done")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /#4 · admin/ }));
    expect(await screen.findByText(/Waiting for 1 running run to finish/)).toBeInTheDocument();

    await user.type(screen.getByLabelText("requirements.yml"), "x");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Local paths are not allowed")).toBeInTheDocument();
  });

  it("shows a refused install", async () => {
    const { user, screen } = renderApp("/galaxy", {
      routes: { ...BASE, "POST /galaxy/installs": reply(409, { detail: "An install is already running" }) },
    });
    await user.click(await screen.findByRole("checkbox", { name: /runs third-party code/ }));
    await user.click(screen.getByRole("button", { name: "Install" }));
    expect(await screen.findByText("An install is already running")).toBeInTheDocument();
  });

  it("is read-only without galaxy:manage", async () => {
    const { screen } = renderApp("/galaxy", {
      user: viewerUser(),
      routes: { ...BASE, "GET /galaxy/installed": { collections: [], roles: [] } },
    });
    expect(await screen.findAllByText("None installed.")).toHaveLength(2);
    expect(screen.getByLabelText("requirements.yml")).toHaveAttribute("readonly");
    expect(screen.queryByRole("button", { name: "Install" })).not.toBeInTheDocument();
  });
});

import { within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { credential, gitSource, playbook, viewerUser } from "@/test/fixtures";
import { choose, renderApp } from "@/test/render";

const SOURCES = "GET /projects/:id/git-sources";

describe("playbooks list", () => {
  it("lists manual and synced playbooks; only manual or removed ones can be deleted", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/playbooks", {
      routes: {
        [SOURCES]: [],
        "GET /playbooks": [
          playbook(),
          playbook({ id: 2, name: "deploy.yml", source_id: 1, source_name: "infra", commit: "0123456789abcdef" }),
          playbook({ id: 3, name: "old.yml", source_id: 1, source_name: "infra", missing_at: "2026-10-01T00:00:00Z" }),
        ],
        "DELETE /playbooks/:id": reply(204),
      },
    });
    expect(await screen.findByText("git · infra @ 01234567")).toBeInTheDocument();
    expect(screen.getByText("removed upstream")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(2);
    expect(screen.getAllByRole("link", { name: "Run" })).toHaveLength(2);

    api.set({ "GET /playbooks": [] });
    await user.click(screen.getAllByRole("button", { name: "Delete" })[0]!);
    await screen.findByText("No playbooks yet.");
    expect(api.requests("DELETE /playbooks/1")).toHaveLength(1);
  });

  it("asks a global admin in all-projects mode to pick a project for git sources", async () => {
    const { screen } = renderApp("/playbooks", { activeProject: null, routes: { "GET /playbooks": [] } });
    expect(await screen.findByText(/Pick a project in the switcher/)).toBeInTheDocument();
  });

  it("shows viewers neither write actions nor an empty git panel", async () => {
    const { screen } = renderApp("/playbooks", {
      user: viewerUser(),
      routes: { [SOURCES]: [], "GET /playbooks": [playbook()] },
    });
    await screen.findByText("site.yml");
    expect(screen.queryByRole("link", { name: "New Playbook" })).not.toBeInTheDocument();
    expect(screen.queryByText("Git sources")).not.toBeInTheDocument();
  });
});

describe("playbook editor", () => {
  it("creates a playbook from an uploaded file and opens it", async () => {
    const { api, user, screen } = renderApp("/playbooks/new", {
      routes: { "POST /playbooks": playbook({ id: 5, name: "web.yml" }), "GET /playbooks/:id": playbook({ id: 5, name: "web.yml" }) },
    });
    await screen.findByRole("heading", { name: "New Playbook" });
    await user.upload(screen.getByLabelText("Upload YAML file"), new File(["- hosts: web\n"], "web.yml"));
    expect(screen.getByLabelText("Name")).toHaveValue("web.yml");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByRole("heading", { name: "Edit Playbook" });
    expect(api.requests("POST /playbooks")[0]?.body).toMatchObject({ name: "web.yml", content: "- hosts: web\n" });
  });

  it("saves edits and shows refusals", async () => {
    const { api, user, screen } = renderApp("/playbooks/1", {
      routes: { "GET /playbooks/:id": playbook(), "PUT /playbooks/:id": reply(400, { detail: "Not valid YAML" }) },
    });
    const content = await screen.findByLabelText("Content");
    await user.type(content, "x");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Not valid YAML")).toBeInTheDocument();
    expect(api.requests("PUT /playbooks/1")).toHaveLength(1);
  });

  it("shows a synced playbook read-only, with its source and commit", async () => {
    const { screen } = renderApp("/playbooks/2", {
      routes: {
        "GET /playbooks/:id": playbook({
          id: 2,
          source_id: 1,
          source_name: "infra",
          repo_path: "site.yml",
          commit: "0123456789abcdef",
          missing_at: "2026-10-01T00:00:00Z",
        }),
      },
    });
    expect(await screen.findByRole("heading", { name: "Playbook" })).toBeInTheDocument();
    expect(screen.getByText(/removed from the repository/)).toBeInTheDocument();
    expect(screen.getByLabelText("Content")).toHaveAttribute("readonly");
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  });
});

describe("git sources", () => {
  it("shows a source's commit, status and warnings, and syncs it", async () => {
    const { api, user, screen } = renderApp("/playbooks", {
      routes: {
        "GET /playbooks": [],
        [SOURCES]: [gitSource({ warnings: ["requirements.yml is not installed automatically"], missing_playbooks: 1 })],
        "POST /projects/:id/git-sources/:sid/sync": { queued: true },
      },
    });
    expect(await screen.findByText("synced")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "01234567" })).toHaveAttribute(
      "href",
      "https://git.example/infra/commit/0123456789abcdef0123456789abcdef01234567",
    );
    expect(screen.getByText(/2 playbooks, 1 removed upstream/)).toBeInTheDocument();
    expect(screen.getByText("requirements.yml is not installed automatically")).toBeInTheDocument();

    api.set({ [SOURCES]: [gitSource({ sync_requested_at: "2026-10-05T12:01:00Z" })] });
    await user.click(screen.getByRole("button", { name: "Sync now" }));
    expect(await screen.findByRole("button", { name: "Syncing…" })).toBeDisabled();
    expect(api.requests("POST /projects/1/git-sources/1/sync")).toHaveLength(1);
  });

  it("reloads playbooks when a running sync finishes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, screen } = renderApp("/playbooks", {
        routes: {
          "GET /playbooks": [],
          [SOURCES]: [gitSource({ last_sync_status: "running" })],
        },
      });
      await screen.findByText("syncing");
      api.set({ [SOURCES]: [gitSource()], "GET /playbooks": [playbook({ source_id: 1, source_name: "infra" })] });
      await vi.advanceTimersByTimeAsync(3500);
      expect(await screen.findByText("site.yml")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("adds an HTTPS source with a token", async () => {
    const { api, user, screen } = renderApp("/playbooks", {
      routes: {
        "GET /playbooks": [],
        [SOURCES]: [],
        "GET /credentials": [],
        "POST /projects/:id/git-sources": gitSource(),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Add git source" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "infra");
    await user.type(dialog.getByLabelText("Repository URL"), "http://gitea.lan/org/infra.git");
    await user.clear(dialog.getByLabelText("Branch"));
    await user.type(dialog.getByLabelText("Branch"), "prod");
    await user.type(dialog.getByLabelText("Subdirectory (optional)"), "ansible");
    await user.clear(dialog.getByLabelText("Playbook files"));
    await user.type(dialog.getByLabelText("Playbook files"), "site.yml, deploy/*.yml");
    await choose(user, dialog.getByLabelText("Authentication"), "User name and token (HTTPS)");
    await user.type(dialog.getByLabelText("User name"), "bot");
    await user.type(dialog.getByLabelText("Token"), "t0ken");
    expect(dialog.getByText(/Plain http:\/\/ sends the token unencrypted/)).toBeInTheDocument();
    await choose(user, dialog.getByLabelText("Sync"), "Every hour");
    await user.type(dialog.getByLabelText("Web URL for commit links (optional)"), "https://gitea.lan/org/infra");
    await user.click(dialog.getByRole("switch"));
    api.set({ [SOURCES]: [gitSource({ enabled: false })] });
    await user.click(dialog.getByRole("button", { name: "Add source" }));

    expect(await screen.findByText("off")).toBeInTheDocument();
    expect(api.requests("POST /projects/1/git-sources")[0]?.body).toEqual({
      name: "infra",
      url: "http://gitea.lan/org/infra.git",
      branch: "prod",
      subdir: "ansible",
      web_url: "https://gitea.lan/org/infra",
      playbook_globs: ["site.yml", "deploy/*.yml"],
      auth_kind: "https_token",
      credential_id: null,
      https_username: "bot",
      token: "t0ken",
      auto_sync_seconds: 3600,
      enabled: false,
    });
  });

  it("adds an SSH source with a deploy key, then trusts its host key", async () => {
    const ssh = gitSource({ url: "git@gitea.lan:org/infra.git", auth_kind: "ssh_key", credential_id: 1, commit: null, last_sync_status: null, last_sync_finished_at: null });
    const { api, user, screen } = renderApp("/playbooks", {
      routes: {
        "GET /playbooks": [],
        [SOURCES]: [],
        "GET /credentials": [credential(), credential({ id: 9, name: "other-project", project_id: 2 })],
        "POST /projects/:id/git-sources": ssh,
        "POST /projects/:id/git-sources/:sid/test": {
          ok: true,
          error: null,
          default_branch: "main",
          branch_exists: true,
          host_keys: [{ type: "ssh-ed25519", fingerprint: "SHA256:abc", trusted: false }],
          host_key_trusted: false,
        },
        "POST /projects/:id/git-sources/:sid/trust-host-key": ssh,
      },
    });
    await user.click(await screen.findByRole("button", { name: "Add git source" }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText("Name"), "infra");
    await user.type(dialog.getByLabelText("Repository URL"), "git@gitea.lan:org/infra.git");
    expect(dialog.getByRole("button", { name: "Add source" })).toBeDisabled();
    await choose(user, dialog.getByLabelText("Deploy key"), "deploy-key");
    expect(screen.queryByRole("option", { name: "other-project" })).not.toBeInTheDocument();
    api.set({ [SOURCES]: [ssh] });
    await user.click(dialog.getByRole("button", { name: "Add source" }));

    expect(await screen.findByText(/trust the server's SSH host key before the first sync/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sync now" })).toBeDisabled();
    expect(api.requests("POST /projects/1/git-sources")[0]?.body).toMatchObject({ auth_kind: "ssh_key", credential_id: 1 });

    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Connected: branch “main” exists \(the default branch is “main”\)/)).toBeInTheDocument();
    api.set({ [SOURCES]: [{ ...ssh, host_keys: [{ type: "ssh-ed25519", fingerprint: "SHA256:abc" }] }] });
    await user.click(screen.getByRole("button", { name: "Trust" }));
    expect(await screen.findByText(/Trusted host key:/)).toBeInTheDocument();
    expect(api.requests("POST /projects/1/git-sources/1/trust-host-key")[0]?.body).toEqual({ fingerprint: "SHA256:abc" });
  });

  it("trusts a pasted known_hosts line, shows failures, edits and deletes", async () => {
    const ssh = gitSource({ url: "ssh://git@gitea.lan/org/infra.git", auth_kind: "ssh_key", credential_id: 1, last_sync_status: "failed", last_sync_error: "fatal: repository not found", auto_sync_seconds: 120 });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/playbooks", {
      routes: {
        "GET /playbooks": [],
        [SOURCES]: [ssh],
        "GET /credentials": [credential()],
        "POST /projects/:id/git-sources/:sid/trust-host-key": reply(400, { detail: "No valid host key line" }),
        "POST /projects/:id/git-sources/:sid/test": { ok: false, error: "Host unreachable", default_branch: null, branch_exists: null, host_keys: [], host_key_trusted: null },
        "PATCH /projects/:id/git-sources/:sid": ssh,
        "DELETE /projects/:id/git-sources/:sid": reply(204),
      },
    });
    expect(await screen.findByText("fatal: repository not found")).toBeInTheDocument();
    expect(screen.getByText("· every 120 s")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("Host unreachable")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Paste a known_hosts line instead" }));
    await user.type(screen.getByPlaceholderText(/git.example.com ssh-ed25519/), "gitea.lan ssh-ed25519 AAAA");
    await user.click(screen.getByRole("button", { name: "Trust these keys" }));
    expect(await screen.findByText("No valid host key line")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Edit" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByLabelText("Name")).toHaveValue("infra");
    await user.clear(dialog.getByLabelText("Repository URL"));
    await user.type(dialog.getByLabelText("Repository URL"), "git@other.lan:org/infra.git");
    expect(dialog.getByText("A new host needs its SSH host key trusted again.")).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Save" }));
    await screen.findByText("fatal: repository not found");
    expect(api.requests("PATCH /projects/1/git-sources/1")[0]?.body).toMatchObject({ url: "git@other.lan:org/infra.git", auto_sync_seconds: 120 });

    api.set({ [SOURCES]: [] });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await screen.findByRole("button", { name: "Add git source" });
    expect(api.requests("DELETE /projects/1/git-sources/1")).toHaveLength(1);
  });
});

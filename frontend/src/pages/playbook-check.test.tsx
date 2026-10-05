import { describe, expect, it, vi } from "vitest";

import { editorText, setEditorText } from "@/test/editor";
import { reply } from "@/test/fake-api";
import { FQCN_FINDING, lintJob, playbook, viewerUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const CONTENT = "- hosts: all\n  shell: echo hi\n";
const SYNCED = playbook({ id: 2, source_id: 1, source_name: "infra", repo_path: "site.yml", commit: "0123456789abcdef" });

describe("checking a playbook", () => {
  it("checks the unsaved text, follows the check and marks what it found", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, user, screen, container } = renderApp("/playbooks/1", {
        routes: {
          "GET /playbooks/:id": playbook({ content: "- hosts: all\n" }),
          "POST /playbooks/lint": lintJob({ status: "queued", wait_reason: "Waiting for a worker…", finished_at: null }),
          "GET /lint-jobs/:id": lintJob({ status: "running", finished_at: null }),
        },
      });
      const editor = await screen.findByRole("textbox", { name: "Content" });
      setEditorText(editor, CONTENT);
      await user.click(screen.getByRole("button", { name: "Check" }));
      expect(api.requests("POST /playbooks/lint")[0]?.body).toEqual({ content: CONTENT, project_id: 1 });
      expect(await screen.findByText("Waiting to check: Waiting for a worker…")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Checking…" })).toBeInTheDocument();

      await vi.advanceTimersByTimeAsync(1100);
      expect(await screen.findByText("Checking with ansible-lint…")).toBeInTheDocument();

      api.set({
        "GET /lint-jobs/:id": lintJob({
          findings: [
            FQCN_FINDING,
            { ...FQCN_FINDING, rule: "no-changed-when", level: "warning", message: "Commands should not change things.", details: null, url: null, line: 2, column: null },
            { ...FQCN_FINDING, rule: "risky-file-permissions", path: "roles/web/tasks/main.yml", in_target: false, line: 4 },
          ],
          total: 5,
          truncated: true,
          external: 2,
          scrubbed: true,
        }),
      });
      await vi.advanceTimersByTimeAsync(1100);
      expect(await screen.findByText("2 errors, 1 warning found.")).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "fqcn[action-core]" })).toHaveAttribute(
        "href",
        "https://docs.ansible.com/projects/lint/rules/fqcn/",
      );
      expect(screen.getByText("roles/web/tasks/main.yml:4:3")).toBeInTheDocument();
      expect(screen.getByText(/ansible-lint 26\.9\.0 · default rules · showing the first 3 of 5 · 2 findings in installed collections not shown · a secret's value was removed/)).toBeInTheDocument();
      // marked in the editor (only findings in this file)
      expect(container.querySelector(".cm-lintRange-error")).toHaveTextContent("shell:");
      expect(screen.getAllByRole("button", { name: /Go to line/ })).toHaveLength(2);
      await user.click(screen.getAllByRole("button", { name: "Go to line 2" })[0]!);
      expect(editor).toHaveFocus();

      setEditorText(editor, `${CONTENT}# edited\n`);
      expect(screen.getByText(/The text has changed since this check/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("says when nothing was found, and when a check failed or couldn't start", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, user, screen } = renderApp("/playbooks/1", {
        routes: {
          "GET /playbooks/:id": playbook({ content: CONTENT }),
          "POST /playbooks/lint": lintJob(),
        },
      });
      await user.click(await screen.findByRole("button", { name: "Check" }));
      expect(await screen.findByText("No problems found.")).toBeInTheDocument();

      api.set({ "POST /playbooks/lint": lintJob({ id: 12, status: "failed", error: "ansible-lint failed (exit 1): boom", findings: [] }) });
      await user.click(screen.getByRole("button", { name: "Check" }));
      expect(await screen.findByText("The check failed: ansible-lint failed (exit 1): boom")).toBeInTheDocument();

      api.set({ "POST /playbooks/lint": lintJob({ id: 13, status: "timed_out", error: "timed out after 2 min" }) });
      await user.click(screen.getByRole("button", { name: "Check" }));
      expect(await screen.findByText("The check timed out: timed out after 2 min")).toBeInTheDocument();

      api.set({ "POST /playbooks/lint": lintJob({ id: 14, status: "cancelled" }) });
      await user.click(screen.getByRole("button", { name: "Check" }));
      expect(await screen.findByText("Replaced by a newer check.")).toBeInTheDocument();

      api.set({ "POST /playbooks/lint": reply(413, { detail: "The playbook is too large to check (over 1024 KiB)" }) });
      await user.click(screen.getByRole("button", { name: "Check" }));
      expect(await screen.findByText("The playbook is too large to check (over 1024 KiB)")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows a polling error", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { user, screen } = renderApp("/playbooks/1", {
        routes: {
          "GET /playbooks/:id": playbook({ content: CONTENT }),
          "POST /playbooks/lint": lintJob({ status: "queued", finished_at: null }),
          "GET /lint-jobs/:id": reply(404, { detail: "Check not found" }),
        },
      });
      await user.click(await screen.findByRole("button", { name: "Check" }));
      await vi.advanceTimersByTimeAsync(1100);
      expect(await screen.findByText("Check not found")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("checks a synced playbook in its repository", async () => {
    const { api, user, screen } = renderApp("/playbooks/2", {
      routes: {
        "GET /playbooks/:id": SYNCED,
        "POST /playbooks/:id/lint": lintJob({
          target: "site.yml",
          commit: "0123456789abcdef",
          repo_config: true,
          findings: [{ ...FQCN_FINDING, path: "roles/web/tasks/main.yml", in_target: false }],
          total: 1,
        }),
      },
    });
    expect(await screen.findByText(/the playbook in its repository/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check" }));
    expect(api.requests("POST /playbooks/2/lint")).toHaveLength(1);
    expect(await screen.findByText(/with the repository's ansible-lint config · at 01234567/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Go to line/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  });

  it("can't check a synced playbook that's gone from its repository", async () => {
    const { screen } = renderApp("/playbooks/2", {
      routes: { "GET /playbooks/:id": { ...SYNCED, missing_at: "2026-10-01T00:00:00Z" } },
    });
    expect(await screen.findByRole("button", { name: "Check" })).toBeDisabled();
  });

  it("saves while a check is still running", async () => {
    const { api, user, screen } = renderApp("/playbooks/1", {
      routes: {
        "GET /playbooks/:id": playbook({ content: CONTENT }),
        "POST /playbooks/lint": lintJob({ status: "running", finished_at: null }),
        "GET /lint-jobs/:id": lintJob({ status: "running", finished_at: null }),
        "PUT /playbooks/:id": playbook({ content: CONTENT }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Check" }));
    await screen.findByRole("button", { name: "Checking…" });
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(api.requests("PUT /playbooks/1")).toHaveLength(1);
  });

  it("is not offered to viewers or on a new playbook", async () => {
    const { screen } = renderApp("/playbooks/1", { user: viewerUser(), routes: { "GET /playbooks/:id": playbook() } });
    await screen.findByRole("heading", { name: "Playbook" });
    expect(screen.queryByRole("button", { name: "Check" })).not.toBeInTheDocument();
    expect(editorText(screen.getByRole("textbox", { name: "Content" }))).toContain("hosts: all");
  });

  it("checks a new playbook's text in the active project, once there is some", async () => {
    const { api, user, screen } = renderApp("/playbooks/new", { routes: { "POST /playbooks/lint": lintJob() } });
    await screen.findByRole("heading", { name: "New Playbook" });
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
    setEditorText(screen.getByRole("textbox", { name: "Content" }), CONTENT);
    await user.click(screen.getByRole("button", { name: "Check" }));
    expect(await screen.findByText("No problems found.")).toBeInTheDocument();
    expect(api.requests("POST /playbooks/lint")[0]?.body).toEqual({ content: CONTENT, project_id: 1 });
  });
});

describe("file picker", () => {
  it("is a button-styled, labelled file input that names the chosen file", async () => {
    const { user, screen } = renderApp("/playbooks/new");
    await screen.findByRole("heading", { name: "New Playbook" });
    expect(screen.getByText("No file chosen")).toBeInTheDocument();
    const input = screen.getByLabelText("Upload YAML file");
    expect(input).toHaveAttribute("type", "file");
    expect(input).toHaveAttribute("accept", ".yml,.yaml");
    await user.upload(input, new File(["- hosts: db\n"], "db.yml"));
    expect(screen.getByText("db.yml")).toBeInTheDocument();
    await vi.waitFor(() => expect(editorText(screen.getByRole("textbox", { name: "Content" }))).toBe("- hosts: db\n"));
  });
});

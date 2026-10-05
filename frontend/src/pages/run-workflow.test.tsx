import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import {
  ALL_PERMISSIONS,
  credential,
  inventory,
  playbook,
  project,
  run,
  runTemplate,
  targets,
  vaultPassword,
  viewerUser,
  adminUser,
} from "@/test/fixtures";
import { renderApp } from "@/test/render";

// An operator: everything but become (and the global-only permissions).
const OPERATOR_PERMISSIONS = ALL_PERMISSIONS.filter((p) => p !== "runs:become");
const operatorUser = () =>
  adminUser({
    username: "op",
    role: "operator",
    permissions: OPERATOR_PERMISSIONS,
    projects: [project({ role: "operator", permissions: OPERATOR_PERMISSIONS })],
  });

const FORM = {
  "GET /playbooks": [playbook()],
  "GET /inventories": [inventory()],
  "GET /credentials": [credential()],
  "GET /vault-passwords": [vaultPassword()],
  "GET /inventories/:id/targets": targets(),
};

describe("run again", () => {
  it("starts the same run after confirming what it runs, and opens it", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": ({ params }: { params: Record<string, string> }) =>
          run({ id: Number(params["id"]), group_name: "web", become: true }),
        "POST /runs/:id/rerun": run({ id: 8 }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Run again" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Run site.yml on lab / web again"));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("It runs as root (become)."));
    expect(api.requests("POST /runs/7/rerun")).toHaveLength(1);
    await vi.waitFor(() => expect(api.requests("GET /runs/8").length).toBeGreaterThan(0));
  });

  it("does nothing unless confirmed, and shows a refusal", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const { api, user, screen } = renderApp("/runs/7", {
      routes: {
        "GET /runs/:id": run(),
        "POST /runs/:id/rerun": reply(409, { detail: "Run #7 can't be started: its credential has been deleted" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Run again" }));
    expect(api.requests("POST /runs/7/rerun")).toHaveLength(0);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Run again" }));
    expect(await screen.findByText(/its credential has been deleted/)).toBeInTheDocument();
  });

  it("is disabled when something the run used was deleted", async () => {
    const { screen } = renderApp("/runs/7", {
      routes: { "GET /runs/:id": run({ credential_id: null, vault_password_name: "prod-vault" }) },
    });
    expect(await screen.findByRole("button", { name: "Run again" })).toBeDisabled();
    expect(
      screen.getByText("Can't run again as it was: its credential, vault password have been deleted."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Edit and run" })).toHaveAttribute("href", "/runs/new?from_run=7");
  });

  it("isn't offered to viewers, who can still download the log", async () => {
    const { screen } = renderApp("/runs/7", { user: viewerUser(), routes: { "GET /runs/:id": run() } });
    expect(await screen.findByRole("link", { name: "text" })).toHaveAttribute("href", "/api/runs/7/log?format=text");
    expect(screen.getByRole("link", { name: "JSON lines" })).toHaveAttribute("href", "/api/runs/7/log?format=jsonl");
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Edit and run" })).not.toBeInTheDocument();
  });

  it("offers no download before a run has started", async () => {
    const { screen } = renderApp("/runs/7", {
      routes: { "GET /runs/:id": run({ status: "queued", started_at: null, finished_at: null }) },
    });
    await screen.findByText("Live output");
    expect(screen.queryByRole("link", { name: "text" })).not.toBeInTheDocument();
  });
});

describe("edit and run", () => {
  it("fills the form in from the run and starts the edited run", async () => {
    const { api, user, screen } = renderApp("/runs/new?from_run=7", {
      routes: {
        ...FORM,
        "GET /runs/:id": run({
          group_name: "web",
          vault_password_id: 1,
          vault_password_name: "prod-vault",
          check_mode: true,
          limit: "web1",
          timeout_seconds: 1750,
          extra_vars: { release: "1.2" },
        }),
        "POST /runs": run({ id: 9 }),
      },
    });
    expect(await screen.findByText("Filled in from run #7.")).toBeInTheDocument();
    await vi.waitFor(() => expect(screen.getByLabelText("Target")).toHaveTextContent("Group: web (1)"));
    expect(screen.getByLabelText("Playbook")).toHaveTextContent("site.yml");
    expect(screen.getByLabelText("Credential")).toHaveTextContent("deploy-key");
    expect(screen.getByLabelText("Vault password (optional)")).toHaveTextContent("prod-vault");
    expect(screen.getByLabelText("Limit (optional)")).toHaveValue("web1");
    expect(screen.getByLabelText("Timeout (minutes)")).toHaveValue(30);

    await user.clear(screen.getByLabelText("Limit (optional)"));
    await user.type(screen.getByLabelText("Limit (optional)"), "web2");
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    await screen.findByText("Live output");
    expect(api.requests("POST /runs")[0]?.body).toEqual({
      playbook_id: 1,
      inventory_id: 1,
      group_name: "web",
      credential_id: 1,
      vault_password_id: 1,
      become: false,
      check_mode: true,
      diff_mode: false,
      limit: "web2",
      extra_vars: { release: "1.2" },
      timeout_seconds: 1800,
    });
  });

  it("says what can't be copied: deleted items, become, masked extra vars, a gone group", async () => {
    const { api, user, screen } = renderApp("/runs/new?from_run=7", {
      user: operatorUser(),
      routes: {
        ...FORM,
        "GET /runs/:id": run({
          credential_id: null,
          group_name: "db",
          become: true,
          extra_vars: { db_password: "[REDACTED]" },
        }),
      },
    });
    expect(await screen.findByText("Pick again: its credential has been deleted.")).toBeInTheDocument();
    expect(screen.getByText(/It ran as root \(become\), which you may not use/)).toBeInTheDocument();
    expect(screen.getByText(/Some extra vars show \[REDACTED\] or \[HIDDEN\]/)).toBeInTheDocument();
    expect(await screen.findByText("The group db is no longer in this inventory: pick a target.")).toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "Run as admin (become root)" })).not.toBeInTheDocument();

    await user.click(screen.getByLabelText("Credential"));
    await user.click(await screen.findByRole("option", { name: "deploy-key" }));
    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    expect(await screen.findByText(/Extra vars still contain \[REDACTED\] or \[HIDDEN\]: enter the real values\./)).toBeInTheDocument();
    expect(api.requests("POST /runs")).toHaveLength(0);
  });

  it("turns become on for people allowed to use it, still asking to confirm", async () => {
    const { screen } = renderApp("/runs/new?from_run=7", {
      routes: { ...FORM, "GET /runs/:id": run({ become: true }) },
    });
    expect(await screen.findByRole("checkbox", { name: /I understand this grants root/ })).not.toBeChecked();
    expect(screen.getByRole("switch", { name: "Run as admin (become root)" })).toBeChecked();
    expect(screen.getByRole("button", { name: "Trigger Run" })).toBeDisabled();
  });

  it("shows why the run couldn't be loaded", async () => {
    const { screen } = renderApp("/runs/new?from_run=99", {
      routes: { ...FORM, "GET /runs/:id": reply(404, { detail: "Run not found" }) },
    });
    expect(await screen.findByText("Run not found")).toBeInTheDocument();
  });
});

describe("saving templates from the form", () => {
  it("saves the form as a new template and opens the list", async () => {
    const { api, user, screen } = renderApp("/runs/new?from_run=7", {
      routes: {
        ...FORM,
        "GET /runs/:id": run({ extra_vars: { release: "1.2" } }),
        "POST /run-templates": runTemplate(),
        "GET /run-templates": [runTemplate()],
      },
    });
    await screen.findByText("Filled in from run #7.");
    await user.click(await screen.findByRole("button", { name: "Save as template" }));
    expect(screen.getByRole("button", { name: "Save template" })).toBeDisabled();
    await user.type(screen.getByLabelText("Name"), "Nightly patch");
    await user.type(screen.getByLabelText("Description (optional)"), "every night");
    await user.click(screen.getByRole("button", { name: "Save template" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Run templates" })).toBeInTheDocument();
    expect(api.requests("POST /run-templates")[0]?.body).toMatchObject({
      name: "Nightly patch",
      description: "every night",
      playbook_id: 1,
      inventory_id: 1,
      group_name: null,
      credential_id: 1,
      extra_vars: { release: "1.2" },
    });
  });

  it("keeps the dialog open with the reason a save was refused", async () => {
    const { user, screen } = renderApp("/runs/new?from_run=7", {
      routes: {
        ...FORM,
        "GET /runs/:id": run(),
        "POST /run-templates": reply(400, { detail: "A template with this name already exists in the project" }),
      },
    });
    await screen.findByText("Filled in from run #7.");
    await user.click(await screen.findByRole("button", { name: "Save as template" }));
    await user.type(screen.getByLabelText("Name"), "Nightly patch");
    await user.click(screen.getByRole("button", { name: "Save template" }));
    expect(await screen.findByText("A template with this name already exists in the project")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("checks the form before saving", async () => {
    const { api, user, screen } = renderApp("/runs/new?from_run=7", {
      routes: { ...FORM, "GET /runs/:id": run() },
    });
    await screen.findByText("Filled in from run #7.");
    await user.clear(screen.getByLabelText("Extra vars (JSON)"));
    await user.type(screen.getByLabelText("Extra vars (JSON)"), "nope");
    await user.click(await screen.findByRole("button", { name: "Save as template" }));
    await user.type(screen.getByLabelText("Name"), "x");
    await user.click(screen.getByRole("button", { name: "Save template" }));
    expect(await screen.findByText("Extra vars must be valid JSON")).toBeInTheDocument();
    expect(api.requests("POST /run-templates")).toHaveLength(0);
  });

  it("isn't offered without content:write", async () => {
    const triggerOnly = ["content:read", "runs:trigger", "secrets:list"];
    const { screen } = renderApp("/runs/new?from_run=7", {
      user: adminUser({ role: "viewer", permissions: triggerOnly, projects: [project({ role: "viewer", permissions: triggerOnly })] }),
      routes: { ...FORM, "GET /runs/:id": run() },
    });
    await screen.findByText("Filled in from run #7.");
    await screen.findByRole("button", { name: "Trigger Run" });
    expect(screen.queryByRole("button", { name: "Save as template" })).not.toBeInTheDocument();
  });

  it("updates a template opened for editing, sending masked values back unchanged", async () => {
    const template = runTemplate({ extra_vars: { greeting: "hi", db_password: "[REDACTED]" } });
    const { api, user, screen } = renderApp("/runs/new?template=3", {
      routes: {
        ...FORM,
        "GET /run-templates/:id": template,
        "PUT /run-templates/:id": template,
        "GET /run-templates": [template],
      },
    });
    expect(await screen.findByText(/From the template/)).toHaveTextContent("Nightly patch");
    await vi.waitFor(() => expect(screen.getByLabelText("Target")).toHaveTextContent("Group: web (1)"));
    expect(screen.getByRole("checkbox", { name: /Diff mode/ })).toBeChecked();
    expect(screen.getByLabelText("Timeout (minutes)")).toHaveValue(60);

    await user.click(screen.getByRole("button", { name: "Trigger Run" }));
    expect(
      await screen.findByText(/or run the template from the Templates page, which keeps them\./),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Update template" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Run templates" })).toBeInTheDocument();
    expect(api.requests("PUT /run-templates/3")[0]?.body).toEqual({
      name: "Nightly patch",
      description: "Patches the lab every night",
      playbook_id: 1,
      inventory_id: 1,
      group_name: "web",
      credential_id: 1,
      vault_password_id: null,
      become: false,
      check_mode: false,
      diff_mode: true,
      limit: null,
      extra_vars: { greeting: "hi", db_password: "[REDACTED]" },
      timeout_seconds: 3600,
    });
  });

  it("shows a refused update", async () => {
    const { user, screen } = renderApp("/runs/new?template=3", {
      routes: {
        ...FORM,
        "GET /run-templates/:id": runTemplate(),
        "PUT /run-templates/:id": reply(403, { detail: "You may not save a template that runs as root (become)" }),
      },
    });
    await screen.findByText(/From the template/);
    await user.click(await screen.findByRole("button", { name: "Update template" }));
    expect(await screen.findByText("You may not save a template that runs as root (become)")).toBeInTheDocument();
  });
});

describe("templates page", () => {
  it("lists templates with their target, options and missing items", async () => {
    const { screen } = renderApp("/templates", {
      routes: {
        "GET /run-templates": [
          runTemplate({ become: true, check_mode: true, limit: "web1", vault_password_name: "prod-vault" }),
          runTemplate({
            id: 4,
            name: "Broken",
            description: null,
            playbook_id: null,
            playbook_name: null,
            credential_id: null,
            credential_name: null,
            group_name: null,
            missing: ["playbook", "credential"],
          }),
        ],
      },
    });
    expect(await screen.findByText("Nightly patch")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
    expect(
      screen.getByText("site.yml → lab / web · credential deploy-key · become · check · diff · limit: web1 · vault: prod-vault"),
    ).toBeInTheDocument();
    expect(screen.getByText("(deleted playbook) → lab · credential (deleted) · diff")).toBeInTheDocument();
    expect(
      screen.getByText("Can't run: its playbook, credential have been deleted. Edit it to pick another."),
    ).toBeInTheDocument();
    const runButtons = screen.getAllByRole("button", { name: "Run" });
    expect(runButtons[1]).toBeDisabled();
    expect(screen.getByRole("link", { name: "Edit Broken" })).toHaveAttribute("href", "/runs/new?template=4");
  });

  it("launches a template with a changed limit and check mode, and opens the run", async () => {
    const { api, user, screen } = renderApp("/templates", {
      routes: {
        "GET /run-templates": [runTemplate({ limit: "web*", become: true })],
        "POST /run-templates/:id/launch": run({ id: 12 }),
        "GET /runs/:id": run({ id: 12 }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Run" }));
    expect(screen.getByRole("heading", { name: "Run Nightly patch" })).toBeInTheDocument();
    expect(screen.getByText(/runs with root privileges/)).toBeInTheDocument();
    expect(screen.getByLabelText("Limit (optional, this run only)")).toHaveValue("web*");
    await user.clear(screen.getByLabelText("Limit (optional, this run only)"));
    await user.type(screen.getByLabelText("Limit (optional, this run only)"), "web1");
    await user.click(screen.getByRole("checkbox", { name: /Check mode/ }));
    await user.click(screen.getByRole("button", { name: "Run as root" }));
    await screen.findByText("Live output");
    expect(api.requests("POST /run-templates/3/launch")[0]?.body).toEqual({ limit: "web1", check_mode: true });
  });

  it("shows a refused launch and closes the dialog", async () => {
    const { user, screen } = renderApp("/templates", {
      routes: {
        "GET /run-templates": [runTemplate()],
        "POST /run-templates/:id/launch": reply(409, { detail: "The git source has not synced yet" }),
      },
    });
    await user.click(await screen.findByRole("button", { name: "Run" }));
    await user.click(screen.getAllByRole("button", { name: "Run" }).at(-1)!);
    expect(await screen.findByText("The git source has not synced yet")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("deletes a template after confirming", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const { api, user, screen } = renderApp("/templates", {
      routes: { "GET /run-templates": [runTemplate()], "DELETE /run-templates/:id": reply(204) },
    });
    await screen.findByText("Nightly patch");
    api.set({ "GET /run-templates": [] });
    await user.click(screen.getByRole("button", { name: "Delete Nightly patch" }));
    expect(confirm).toHaveBeenCalledWith('Delete the template "Nightly patch"? Runs started from it are kept.');
    expect(await screen.findByText("No templates yet.")).toBeInTheDocument();
    expect(api.requests("DELETE /run-templates/3")).toHaveLength(1);
  });

  it("only lets viewers look", async () => {
    const { screen } = renderApp("/templates", {
      user: viewerUser(),
      routes: { "GET /run-templates": [runTemplate()] },
    });
    expect(await screen.findByText("Nightly patch")).toBeInTheDocument();
    for (const name of ["Run", "Delete Nightly patch", "New Run"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole("link", { name: "Edit Nightly patch" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Templates" })).toHaveAttribute("href", "/templates");
  });
});

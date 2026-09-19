import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type ApiKey,
  type ApiKeyCreated,
  type ApiKeyPreset,
  type ProjectMember,
  type ProjectSummary,
} from "@/lib/api";

const ROLES: ProjectMember["role"][] = ["admin", "operator", "viewer"];

const ROLE_HELP: Record<ProjectMember["role"], string> = {
  admin: "Manages members and secrets in this project, plus everything an operator can do.",
  operator: "Edits playbooks and inventories, triggers runs. Can pick credentials but not manage them.",
  viewer: "Read-only: playbooks, inventories, run history and output.",
};

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function ProjectFormDialog({ project, onSaved }: { project?: ProjectSummary; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState(project?.name ?? "");
  const [description, setDescription] = React.useState(project?.description ?? "");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      if (project) {
        await api.updateProject(project.id, { name, description });
      } else {
        await api.createProject(name, description || undefined);
        setName("");
        setDescription("");
      }
      setOpen(false);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {project ? (
          <Button variant="outline" size="sm">
            Rename
          </Button>
        ) : (
          <Button>New Project</Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{project ? "Edit project" : "New project"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="project-name">Name</Label>
            <Input id="project-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="project-description">Description</Label>
            <Input
              id="project-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving || !name.trim()}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function MembersPanel({ project }: { project: ProjectSummary }) {
  const { user } = useAuth();
  const isGlobalAdmin = user?.role === "admin";
  const [members, setMembers] = React.useState<ProjectMember[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [username, setUsername] = React.useState("");
  const [role, setRole] = React.useState<ProjectMember["role"]>("viewer");

  const refresh = React.useCallback(() => {
    api
      .listProjectMembers(project.id)
      .then(setMembers)
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false));
  }, [project.id]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleAdd() {
    await run(async () => {
      await api.addProjectMember(project.id, username.trim(), role);
      setUsername("");
    });
  }

  return (
    <div className="flex flex-col gap-3 border-t border-border pt-4">
      {loading && <p className="text-sm text-muted-foreground">Loading members…</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}
      {!loading && members.length === 0 && <p className="text-sm text-muted-foreground">No members yet.</p>}

      {members.map((member) => {
        const isSelf = member.username === user?.username;
        const locked = isSelf && !isGlobalAdmin;
        return (
          <div key={member.user_id} className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-sm">
              <span className="font-medium">{member.username}</span>
              {isSelf && <Badge variant="outline">you</Badge>}
              {!member.is_active && <Badge variant="failed">deactivated</Badge>}
            </div>
            <div className="flex items-center gap-2">
              <Select
                value={member.role}
                disabled={locked}
                onValueChange={(value) =>
                  run(() =>
                    api.setProjectMemberRole(project.id, member.user_id, value as ProjectMember["role"]),
                  )
                }
              >
                <SelectTrigger className="h-8 w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {!locked && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => run(() => api.removeProjectMember(project.id, member.user_id))}
                >
                  Remove
                </Button>
              )}
            </div>
          </div>
        );
      })}

      <div className="flex flex-wrap items-end gap-2 pt-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor={`add-member-${project.id}`}>Add an existing user</Label>
          <Input
            id={`add-member-${project.id}`}
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <Select value={role} onValueChange={(v) => setRole(v as ProjectMember["role"])}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ROLES.map((r) => (
              <SelectItem key={r} value={r}>
                {r}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={handleAdd} disabled={!username.trim()}>
          Add
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{ROLE_HELP[role]}</p>
    </div>
  );
}

const KEY_PRESETS: ApiKeyPreset[] = ["trigger", "read-only"];

const KEY_PRESET_HELP: Record<ApiKeyPreset, string> = {
  trigger:
    "Starts runs and reads run status and output in this project. Never runs as root and never edits anything.",
  "read-only": "Reads run status and output in this project. Cannot start runs.",
};

const KEY_EXPIRY_OPTIONS = [
  { days: "30", label: "30 days" },
  { days: "90", label: "90 days" },
  { days: "365", label: "1 year" },
];

const KEY_STATUS_VARIANT = { active: "ok", expired: "skipped", revoked: "failed" } as const;

// Mirrors the server's rule; it stays the real check.
const KEY_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

function formatWhen(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "never";
}

function ApiKeysPanel({ project }: { project: ProjectSummary }) {
  const [keys, setKeys] = React.useState<ApiKey[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [name, setName] = React.useState("");
  const [preset, setPreset] = React.useState<ApiKeyPreset>("trigger");
  const [days, setDays] = React.useState("90");
  const [creating, setCreating] = React.useState(false);
  // The plaintext token lives only here, only until the dialog is closed.
  const [created, setCreated] = React.useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = React.useState(false);

  const refresh = React.useCallback(() => {
    api
      .listApiKeys(project.id)
      .then(setKeys)
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false));
  }, [project.id]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleCreate() {
    setError(null);
    setCreating(true);
    try {
      const key = await api.createApiKey(project.id, name.trim(), preset, Number(days));
      setName("");
      setCopied(false);
      setCreated(key);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(key: ApiKey) {
    if (!window.confirm(`Revoke "${key.name}"? Anything using it stops working immediately.`)) return;
    setError(null);
    try {
      await api.revokeApiKey(project.id, key.id);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleCopy() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setError("Couldn't copy automatically. Select the key and copy it by hand.");
    }
  }

  return (
    <div className="flex flex-col gap-3 border-t border-border pt-4">
      <p className="text-xs text-muted-foreground">
        API keys let CI/CD start runs and read their status without a login. A key belongs to this project, is
        shown once, and stops working when it expires or is revoked.
      </p>
      {loading && <p className="text-sm text-muted-foreground">Loading API keys…</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}
      {!loading && keys.length === 0 && <p className="text-sm text-muted-foreground">No API keys yet.</p>}

      {keys.map((key) => (
        <div key={key.id} className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-col gap-0.5">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-medium">{key.name}</span>
              <Badge variant="outline">{key.preset}</Badge>
              <Badge variant={KEY_STATUS_VARIANT[key.status]}>{key.status}</Badge>
            </div>
            <span className="font-mono text-xs text-muted-foreground">ansd_{key.prefix}_…</span>
            <span className="text-xs text-muted-foreground">
              created by {key.created_by} · last used {formatWhen(key.last_used_at)} · expires{" "}
              {formatWhen(key.expires_at)}
            </span>
          </div>
          {key.status === "active" && (
            <Button variant="outline" size="sm" onClick={() => handleRevoke(key)}>
              Revoke
            </Button>
          )}
        </div>
      ))}

      <div className="flex flex-wrap items-end gap-2 pt-2">
        <div className="flex flex-col gap-1">
          <Label htmlFor={`key-name-${project.id}`}>New API key</Label>
          <Input
            id={`key-name-${project.id}`}
            placeholder="e.g. ci-deploy"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <Select value={preset} onValueChange={(v) => setPreset(v as ApiKeyPreset)}>
          <SelectTrigger className="w-32" aria-label="Key permissions">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KEY_PRESETS.map((p) => (
              <SelectItem key={p} value={p}>
                {p}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={days} onValueChange={setDays}>
          <SelectTrigger className="w-32" aria-label="Key lifetime">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KEY_EXPIRY_OPTIONS.map((o) => (
              <SelectItem key={o.days} value={o.days}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={handleCreate} disabled={creating || !KEY_NAME_PATTERN.test(name.trim())}>
          Create key
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        {KEY_PRESET_HELP[preset]} Names use letters, digits, dots, dashes and underscores.
      </p>

      <Dialog open={created !== null} onOpenChange={(open) => !open && setCreated(null)}>
        {created && (
          <DialogContent>
            <DialogHeader>
              <DialogTitle>API key created</DialogTitle>
              <DialogDescription>
                Copy this key now. It won&apos;t be shown again. Anyone who has it can{" "}
                {created.preset === "trigger" ? "start and read runs" : "read runs"} in {project.name} until
                it expires or is revoked.
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-start gap-2">
              <code
                data-testid="new-api-key"
                className="flex-1 break-all rounded-md border border-border bg-input p-2 font-mono text-xs"
              >
                {created.token}
              </code>
              <Button variant="outline" onClick={handleCopy}>
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Send it as <span className="font-mono">Authorization: Bearer &lt;key&gt;</span>, over HTTPS
              only.
            </p>
            <DialogFooter>
              <Button onClick={() => setCreated(null)}>Done</Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}

export function ProjectsPage() {
  const { user, canInProject, refreshUser } = useAuth();
  const isGlobalAdmin = user?.role === "admin";
  const [projects, setProjects] = React.useState<ProjectSummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());

  const refresh = React.useCallback(() => {
    api
      .listProjects()
      .then(setProjects)
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  // Keep the project switcher and permissions in sync after any change here.
  const changed = React.useCallback(() => {
    refresh();
    refreshUser();
  }, [refresh, refreshUser]);

  async function handleDelete(project: ProjectSummary) {
    if (
      !window.confirm(
        `Delete "${project.name}"? Only empty projects can be deleted; its run history is removed with it.`,
      )
    ) {
      return;
    }
    setError(null);
    try {
      await api.deleteProject(project.id);
      changed();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  function toggle(panelKey: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(panelKey)) next.delete(panelKey);
      else next.add(panelKey);
      return next;
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Projects</h1>
        {isGlobalAdmin && <ProjectFormDialog onSaved={changed} />}
      </div>

      <p className="text-sm text-muted-foreground">
        Projects separate who can see and change playbooks, inventories, credentials and runs. They are access
        control, not isolation: every run executes in the same container, so only give people who can write
        playbooks and trigger runs a role you trust them with.
      </p>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}

      <div className="flex flex-col gap-3">
        {projects.map((project) => {
          const canManageMembers = canInProject(project.id, "members:manage");
          const canManageKeys = canInProject(project.id, "api_keys:manage");
          const membersKey = `members-${project.id}`;
          const keysKey = `keys-${project.id}`;
          return (
            <Card key={project.id}>
              <CardContent className="flex flex-col gap-3 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{project.name}</span>
                      {project.my_role && <Badge variant="outline">{project.my_role}</Badge>}
                    </div>
                    {project.description && (
                      <span className="text-xs text-muted-foreground">{project.description}</span>
                    )}
                  </div>
                  <div className="flex gap-2">
                    {canManageMembers && (
                      <Button variant="outline" size="sm" onClick={() => toggle(membersKey)}>
                        {expanded.has(membersKey) ? "Hide members" : "Members"}
                      </Button>
                    )}
                    {canManageKeys && (
                      <Button variant="outline" size="sm" onClick={() => toggle(keysKey)}>
                        {expanded.has(keysKey) ? "Hide API keys" : "API keys"}
                      </Button>
                    )}
                    {isGlobalAdmin && (
                      <>
                        <ProjectFormDialog project={project} onSaved={changed} />
                        <Button variant="outline" size="sm" onClick={() => handleDelete(project)}>
                          Delete
                        </Button>
                      </>
                    )}
                  </div>
                </div>
                {expanded.has(membersKey) && <MembersPanel project={project} />}
                {expanded.has(keysKey) && <ApiKeysPanel project={project} />}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

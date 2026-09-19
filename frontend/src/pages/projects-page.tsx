import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type ProjectMember, type ProjectSummary } from "@/lib/api";

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

export function ProjectsPage() {
  const { user, canInProject, refreshUser } = useAuth();
  const isGlobalAdmin = user?.role === "admin";
  const [projects, setProjects] = React.useState<ProjectSummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<Set<number>>(new Set());

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

  function toggle(projectId: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(projectId)) next.delete(projectId);
      else next.add(projectId);
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
                      <Button variant="outline" size="sm" onClick={() => toggle(project.id)}>
                        {expanded.has(project.id) ? "Hide members" : "Members"}
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
                {expanded.has(project.id) && <MembersPanel project={project} />}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

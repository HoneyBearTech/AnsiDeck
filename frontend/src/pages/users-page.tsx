import * as React from "react";
import { Link } from "react-router-dom";

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
import { api, ApiError, type AdminUser } from "@/lib/api";

const ROLES: AdminUser["role"][] = ["admin", "operator", "viewer"];

const ROLE_HELP: Record<AdminUser["role"], string> = {
  admin: "Everything, including users, credentials, vault decrypt, galaxy installs and become runs.",
  operator:
    "Edit playbooks/inventories and trigger runs. No credential management, decrypt, installs or become.",
  viewer: "Read-only: playbooks, inventories, run history and output.",
};

const NO_PROJECT = "__none__";

function CreateUserDialog({ onCreated }: { onCreated: () => void }) {
  const { user, activeProjectId } = useAuth();
  const [open, setOpen] = React.useState(false);
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<AdminUser["role"]>("viewer");
  const [projectId, setProjectId] = React.useState<string>(
    activeProjectId === null ? NO_PROJECT : String(activeProjectId),
  );
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleCreate() {
    setError(null);
    setSaving(true);
    try {
      await api.createUser(
        username,
        password,
        role,
        role === "admin" || projectId === NO_PROJECT ? null : Number(projectId),
        email.trim() || null,
      );
      setUsername("");
      setPassword("");
      setEmail("");
      setRole("viewer");
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>New User</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New User</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="new-username">Username</Label>
            <Input
              id="new-username"
              value={username}
              autoComplete="off"
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="new-user-password">Initial password</Label>
            <Input
              id="new-user-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">At least 12 characters.</p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="new-user-email">Email (optional)</Label>
            <Input
              id="new-user-email"
              type="email"
              autoComplete="off"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Lets this person sign in with SSO: their first SSO sign-in is matched to this address.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as AdminUser["role"])}>
              <SelectTrigger>
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
            <p className="text-xs text-muted-foreground">{ROLE_HELP[role]}</p>
          </div>
          {role !== "admin" && (
            <div className="flex flex-col gap-2">
              <Label>Add to project</Label>
              <Select value={projectId} onValueChange={setProjectId}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_PROJECT}>None (no access yet)</SelectItem>
                  {user?.projects.map((project) => (
                    <SelectItem key={project.id} value={String(project.id)}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Non-admin users only see the projects they are members of, with this role.
              </p>
            </div>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleCreate} disabled={saving || !username || password.length < 12}>
            {saving ? "Saving…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EmailDialog({ user, onDone }: { user: AdminUser; onDone: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [email, setEmail] = React.useState(user.email ?? "");
  const [error, setError] = React.useState<string | null>(null);

  async function handleSave() {
    setError(null);
    try {
      await api.updateUser(user.id, { email: email.trim() || null });
      setOpen(false);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) setEmail(user.email ?? "");
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          Email
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Email for {user.username}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor={`email-${user.id}`}>Email address</Label>
          <Input
            id={`email-${user.id}`}
            type="email"
            autoComplete="off"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            Used to link this account to their SSO identity on first sign-in. Leave empty to remove it. Global
            admins cannot sign in with SSO unless the server allows it.
          </p>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordDialog({ user, onDone }: { user: AdminUser; onDone: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  async function handleReset() {
    setError(null);
    try {
      await api.updateUser(user.id, { password });
      setPassword("");
      setOpen(false);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          Reset password
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password for {user.username}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor="reset-password">New password</Label>
          <Input
            id="reset-password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            At least 12 characters. All of this user's sessions are signed out.
          </p>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleReset} disabled={password.length < 12}>
            Reset
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function UsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = React.useState<AdminUser[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(() => {
    api.listUsers().then((u) => {
      setUsers(u);
      setLoading(false);
    });
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Users</h1>
        <CreateUserDialog onCreated={refresh} />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}

      <div className="flex flex-col gap-2">
        {users.map((u) => {
          const isSelf = u.username === me?.username;
          return (
            <Card key={u.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{u.username}</span>
                    {isSelf && <Badge variant="outline">you</Badge>}
                    {!u.is_active && <Badge variant="failed">deactivated</Badge>}
                    {u.sso_linked && <Badge variant="ok">{u.sso_provider ?? "SSO"}</Badge>}
                    {u.totp_enabled && <Badge variant="ok">2FA</Badge>}
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {u.email ? `${u.email} · ` : ""}
                    Created {new Date(u.created_at).toLocaleDateString()}
                    {u.created_by && ` by ${u.created_by}`}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select
                    value={u.role}
                    disabled={isSelf}
                    onValueChange={(role) =>
                      run(() =>
                        api.updateUser(u.id, {
                          role: role as AdminUser["role"],
                        }),
                      )
                    }
                  >
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
                  <EmailDialog user={u} onDone={refresh} />
                  {u.sso_linked && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Unlink ${u.username}'s SSO identity? Their next SSO sign-in links again by email.`,
                          )
                        ) {
                          run(() => api.unlinkSso(u.id));
                        }
                      }}
                    >
                      Unlink SSO
                    </Button>
                  )}
                  {isSelf ? (
                    <Button variant="outline" size="sm" asChild>
                      <Link to="/account">Change password</Link>
                    </Button>
                  ) : (
                    <ResetPasswordDialog user={u} onDone={refresh} />
                  )}
                  {!isSelf && u.totp_enabled && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Turn off two-factor login for ${u.username}? Use this when they lost their authenticator and recovery codes. They are signed out and can set it up again.`,
                          )
                        ) {
                          run(() => api.resetUserTotp(u.id));
                        }
                      }}
                    >
                      Reset 2FA
                    </Button>
                  )}
                  {!isSelf && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => run(() => api.updateUser(u.id, { is_active: !u.is_active }))}
                    >
                      {u.is_active ? "Deactivate" : "Activate"}
                    </Button>
                  )}
                  {!isSelf && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Delete ${u.username}? Deactivating is usually better — run history keeps their name either way.`,
                          )
                        ) {
                          run(() => api.deleteUser(u.id));
                        }
                      }}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <p className="text-xs text-muted-foreground">
        Changing a role, deactivating, or resetting a password signs that user out immediately. A non-admin
        user's role here only seeds new memberships; per-project roles are set on the Projects page.
      </p>
    </div>
  );
}

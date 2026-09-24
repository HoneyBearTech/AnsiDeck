import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError } from "@/lib/api";

// Mirrors the backend's ChangePasswordRequest limits and username check.
function newPasswordProblem(password: string, confirm: string, username: string): string | null {
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Use at most 128 characters.";
  if (password.toLowerCase() === username.toLowerCase()) return "Don't use your username.";
  if (confirm && confirm !== password) return "The new passwords don't match.";
  return null;
}

function ChangePasswordCard({ username }: { username: string }) {
  const [current, setCurrent] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [done, setDone] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const problem = password ? newPasswordProblem(password, confirm, username) : null;
  const ready = !!current && !!password && confirm === password && !problem;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setDone(false);
    setSaving(true);
    try {
      await api.changePassword(current, password);
      setCurrent("");
      setPassword("");
      setConfirm("");
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>Your other sessions are signed out; this one stays signed in.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="flex max-w-sm flex-col gap-4">
          {/* Lets password managers file the new password under the right account. */}
          <input type="text" autoComplete="username" value={username} readOnly hidden />
          <div className="flex flex-col gap-2">
            <Label htmlFor="current-password">Current password</Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="new-password">New password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-describedby="new-password-hint"
            />
            <p id="new-password-hint" className="text-xs text-muted-foreground">
              At least 12 characters, and not your username.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>
          {problem && <p className="text-sm text-destructive">{problem}</p>}
          {error && <p className="text-sm text-destructive">{error}</p>}
          {done && (
            <p className="text-sm text-status-ok" role="status">
              Password changed. Your other sessions have been signed out.
            </p>
          )}
          <Button type="submit" disabled={saving || !ready} className="self-start">
            {saving ? "Saving…" : "Change password"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export function AccountPage() {
  const { user } = useAuth();
  if (!user) return null;

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Account</h1>
      <Card>
        <CardContent className="flex flex-col gap-3 p-4">
          <div className="flex items-center gap-2">
            <span className="font-medium">{user.username}</span>
            {user.role === "admin" && <Badge variant="outline">global admin</Badge>}
          </div>
          {user.projects.length > 0 && (
            <div className="flex flex-wrap gap-2 text-sm text-muted-foreground">
              {user.projects.map((project) => (
                <span key={project.id}>
                  {project.name}: {project.role}
                </span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      <ChangePasswordCard username={user.username} />
    </div>
  );
}

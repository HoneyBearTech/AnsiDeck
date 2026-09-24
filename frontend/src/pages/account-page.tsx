import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type TotpSetup } from "@/lib/api";

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

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = React.useState(false);
  const text = codes.join("\n") + "\n";

  async function handleCopy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function handleDownload() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "ansideck-recovery-codes.txt";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm">
        Save these recovery codes somewhere safe. Each one signs you in once if you lose your authenticator.
        They won't be shown again.
      </p>
      <ul className="grid max-w-sm grid-cols-2 gap-x-6 gap-y-1 rounded-md border border-border bg-muted p-4 font-mono text-sm">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={handleCopy}>
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button variant="outline" size="sm" onClick={handleDownload}>
          Download .txt
        </Button>
        <Button size="sm" onClick={onDone}>
          I've saved them
        </Button>
      </div>
    </div>
  );
}

type TwoFactorStep =
  | { kind: "idle" }
  | { kind: "password"; purpose: "setup" | "regenerate" | "disable" }
  | { kind: "scan"; setup: TotpSetup }
  | { kind: "codes"; codes: string[] };

function TwoFactorCard({ username, enabled }: { username: string; enabled: boolean }) {
  const { refreshUser } = useAuth();
  const [step, setStep] = React.useState<TwoFactorStep>({ kind: "idle" });
  const [password, setPassword] = React.useState("");
  const [code, setCode] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);

  function goTo(next: TwoFactorStep) {
    setStep(next);
    setPassword("");
    setCode("");
    setError(null);
  }

  async function attempt(action: () => Promise<void>) {
    setError(null);
    setWorking(true);
    try {
      await action();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setWorking(false);
    }
  }

  function handlePassword(event: React.FormEvent) {
    event.preventDefault();
    if (step.kind !== "password") return;
    void attempt(async () => {
      if (step.purpose === "setup") {
        goTo({ kind: "scan", setup: await api.totpSetup(password) });
      } else if (step.purpose === "regenerate") {
        const { recovery_codes } = await api.totpRegenerateRecoveryCodes(password);
        goTo({ kind: "codes", codes: recovery_codes });
      } else {
        await api.totpDisable(password, code);
        await refreshUser();
        goTo({ kind: "idle" });
      }
    });
  }

  function handleEnable(event: React.FormEvent) {
    event.preventDefault();
    void attempt(async () => {
      const { recovery_codes } = await api.totpEnable(code);
      await refreshUser();
      goTo({ kind: "codes", codes: recovery_codes });
    });
  }

  let body: React.ReactNode;
  if (step.kind === "codes") {
    body = <RecoveryCodes codes={step.codes} onDone={() => goTo({ kind: "idle" })} />;
  } else if (step.kind === "scan") {
    body = (
      <form onSubmit={handleEnable} className="flex max-w-sm flex-col gap-4">
        <p className="text-sm">Scan this with your authenticator app, then enter the code it shows.</p>
        <img src={step.setup.qr} alt="QR code for your authenticator app" className="h-48 w-48 rounded-md" />
        <div className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">Can't scan it? Enter this key instead:</span>
          <code className="font-mono text-sm break-all select-all">
            {step.setup.secret.match(/.{1,4}/g)?.join(" ")}
          </code>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="totp-enable-code">Code from the app</Label>
          <Input
            id="totp-enable-code"
            autoComplete="one-time-code"
            inputMode="numeric"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex gap-2">
          <Button type="submit" disabled={working || !code.trim()}>
            {working ? "Checking…" : "Turn on"}
          </Button>
          <Button type="button" variant="outline" onClick={() => goTo({ kind: "idle" })}>
            Cancel
          </Button>
        </div>
      </form>
    );
  } else if (step.kind === "password") {
    const disabling = step.purpose === "disable";
    body = (
      <form onSubmit={handlePassword} className="flex max-w-sm flex-col gap-4">
        <input type="text" autoComplete="username" value={username} readOnly hidden />
        <div className="flex flex-col gap-2">
          <Label htmlFor="totp-password">Current password</Label>
          <Input
            id="totp-password"
            type="password"
            autoComplete="current-password"
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {disabling && (
          <div className="flex flex-col gap-2">
            <Label htmlFor="totp-disable-code">Authentication code or recovery code</Label>
            <Input
              id="totp-disable-code"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </div>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex gap-2">
          <Button
            type="submit"
            variant={disabling ? "destructive" : "default"}
            disabled={working || !password || (disabling && !code.trim())}
          >
            {working
              ? "Checking…"
              : disabling
                ? "Turn off"
                : step.purpose === "setup"
                  ? "Continue"
                  : "Create new codes"}
          </Button>
          <Button type="button" variant="outline" onClick={() => goTo({ kind: "idle" })}>
            Cancel
          </Button>
        </div>
      </form>
    );
  } else if (enabled) {
    body = (
      <div className="flex flex-col gap-4">
        <p className="text-sm">
          <span className="text-status-ok">On.</span> After your password you're asked for a code from your
          authenticator app.
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => goTo({ kind: "password", purpose: "regenerate" })}
          >
            New recovery codes
          </Button>
          <Button variant="outline" size="sm" onClick={() => goTo({ kind: "password", purpose: "disable" })}>
            Turn off
          </Button>
        </div>
      </div>
    );
  } else {
    body = (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">
          Off. Turn it on to be asked for a code from an authenticator app (such as 1Password, Google
          Authenticator or Aegis) after your password.
        </p>
        <Button className="self-start" onClick={() => goTo({ kind: "password", purpose: "setup" })}>
          Set up two-factor login
        </Button>
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Two-factor login</CardTitle>
        <CardDescription>
          Applies to password sign-ins. SSO and GitHub sign-ins use your provider's own MFA instead.
        </CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
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
            {user.totp_enabled && <Badge variant="ok">2FA</Badge>}
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
      <TwoFactorCard username={user.username} enabled={user.totp_enabled} />
    </div>
  );
}

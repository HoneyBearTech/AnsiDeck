import * as React from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  GITHUB_LOGIN_URL,
  SSO_LOGIN_URL,
  type AuthProviders,
  type MfaMethod,
} from "@/lib/api";
import { getPasskey, passkeyProblem, passkeysSupported } from "@/lib/webauthn";

// The server only ever sends a generic code; the real reason is in the audit log.
const SSO_MESSAGES: Record<string, string> & { failed: string } = {
  not_linked: "No AnsiDeck account is linked to this identity. Ask an admin to add you.",
  not_allowed:
    "Your GitHub account isn't in an organization or team allowed here. If your organization " +
    "restricts third-party apps, ask an owner to approve AnsiDeck.",
  failed: "SSO sign-in failed. Try again, or sign in with your password.",
};

type Mode = "passkey" | "totp" | "recovery_code";

function SecondFactorForm({ methods, onStartOver }: { methods: MfaMethod[]; onStartOver: () => void }) {
  const { completeMfa } = useAuth();
  const navigate = useNavigate();
  const canUsePasskey = methods.includes("passkey") && passkeysSupported();
  const [mode, setMode] = React.useState<Mode>(
    canUsePasskey ? "passkey" : methods.includes("totp") ? "totp" : "recovery_code",
  );
  const [value, setValue] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  async function finish(second: () => Promise<Parameters<typeof completeMfa>[0]>) {
    setError(null);
    setSubmitting(true);
    try {
      await completeMfa(await second());
      navigate("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (passkeyProblem(err) ?? "Something went wrong"));
      setValue("");
    } finally {
      setSubmitting(false);
    }
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (mode === "passkey") {
      void finish(async () => ({ passkey: await getPasskey((await api.loginPasskeyOptions()).options) }));
    } else {
      void finish(async () => (mode === "recovery_code" ? { recovery_code: value } : { code: value }));
    }
  }

  function switchTo(next: Mode) {
    setMode(next);
    setValue("");
    setError(null);
  }

  const others = (
    [
      ["passkey", "Use a passkey", canUsePasskey],
      ["totp", "Use an authenticator code", methods.includes("totp")],
      ["recovery_code", "Use a recovery code instead", true],
    ] as const
  ).filter(([key, , offered]) => offered && key !== mode);

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      {mode === "passkey" ? (
        <p className="text-sm">
          Confirm it's you with your passkey: your fingerprint, face, screen lock or security key.
        </p>
      ) : (
        <div className="flex flex-col gap-2">
          <Label htmlFor="second-factor">
            {mode === "recovery_code" ? "Recovery code" : "Authentication code"}
          </Label>
          <Input
            id="second-factor"
            key={mode}
            // oxlint-disable-next-line jsx-a11y/no-autofocus -- second sign-in step; focus follows the user's own submit
            autoFocus
            autoComplete={mode === "recovery_code" ? "off" : "one-time-code"}
            inputMode={mode === "recovery_code" ? "text" : "numeric"}
            placeholder={mode === "recovery_code" ? "xxxxx-xxxxx" : "123456"}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            required
          />
          <p className="text-xs text-muted-foreground">
            {mode === "recovery_code"
              ? "Each recovery code works once."
              : "Enter the 6-digit code from your authenticator app."}
          </p>
        </div>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
      {mode === "passkey" ? (
        // oxlint-disable-next-line jsx-a11y/no-autofocus -- second sign-in step; focus follows the user's own submit
        <Button type="submit" disabled={submitting} className="mt-2" autoFocus>
          {submitting ? "Waiting for your passkey…" : "Use a passkey"}
        </Button>
      ) : (
        <Button type="submit" disabled={submitting || !value.trim()} className="mt-2">
          {submitting ? "Checking…" : "Verify"}
        </Button>
      )}
      <div className="flex flex-wrap justify-between gap-x-4 gap-y-2 text-sm">
        <div className="flex flex-col items-start gap-2">
          {others.map(([key, label]) => (
            <button
              key={key}
              type="button"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => switchTo(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <button type="button" className="text-muted-foreground hover:text-foreground" onClick={onStartOver}>
          Start over
        </button>
      </div>
    </form>
  );
}

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  // The second factors to finish with, once the password was right.
  const [secondFactor, setSecondFactor] = React.useState<MfaMethod[] | null>(null);
  const needsSecondFactor = secondFactor !== null;
  const [providers, setProviders] = React.useState<AuthProviders | null>(null);
  const [searchParams] = useSearchParams();
  const ssoError = searchParams.get("sso_error");

  React.useEffect(() => {
    api
      .getAuthProviders()
      .then(setProviders)
      .catch(() => setProviders(null)); // no SSO button rather than a broken login page
  }, []);

  if (user) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const methods = await login(username, password);
      if (methods) {
        setPassword("");
        setSecondFactor(methods);
      } else {
        navigate("/");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <h1 className="font-mono text-xl font-semibold leading-none tracking-tight text-primary">AnsiDeck</h1>
          <CardDescription>
            {needsSecondFactor
              ? "Two-factor login is on for this account."
              : "Sign in to run playbooks against your infrastructure."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {needsSecondFactor ? (
            <SecondFactorForm methods={secondFactor} onStartOver={() => setSecondFactor(null)} />
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
              </div>
              {(error || ssoError) && (
                <p className="text-sm text-destructive">
                  {error ?? SSO_MESSAGES[ssoError ?? ""] ?? SSO_MESSAGES.failed}
                </p>
              )}
              <Button type="submit" disabled={submitting} className="mt-2">
                {submitting ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          )}
          {!needsSecondFactor && (providers?.oidc.enabled || providers?.github.enabled) && (
            <div className="mt-4 flex flex-col gap-3">
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                or
                <span className="h-px flex-1 bg-border" />
              </div>
              {providers.oidc.enabled && (
                <Button type="button" variant="outline" onClick={() => window.location.assign(SSO_LOGIN_URL)}>
                  Sign in with {providers.oidc.label}
                </Button>
              )}
              {providers.github.enabled && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => window.location.assign(GITHUB_LOGIN_URL)}
                >
                  Sign in with {providers.github.label}
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

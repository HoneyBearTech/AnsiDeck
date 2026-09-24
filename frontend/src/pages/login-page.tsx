import * as React from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, GITHUB_LOGIN_URL, SSO_LOGIN_URL, type AuthProviders } from "@/lib/api";

// The server only ever sends a generic code; the real reason is in the audit log.
const SSO_MESSAGES: Record<string, string> = {
  not_linked: "No AnsiDeck account is linked to this identity. Ask an admin to add you.",
  failed: "SSO sign-in failed. Try again, or sign in with your password.",
};

function SecondFactorForm({ onStartOver }: { onStartOver: () => void }) {
  const { completeMfa } = useAuth();
  const navigate = useNavigate();
  const [useRecovery, setUseRecovery] = React.useState(false);
  const [value, setValue] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await completeMfa(useRecovery ? { recovery_code: value } : { code: value });
      navigate("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
      setValue("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <Label htmlFor="second-factor">{useRecovery ? "Recovery code" : "Authentication code"}</Label>
        <Input
          id="second-factor"
          key={useRecovery ? "recovery" : "code"}
          autoFocus
          autoComplete={useRecovery ? "off" : "one-time-code"}
          inputMode={useRecovery ? "text" : "numeric"}
          placeholder={useRecovery ? "xxxxx-xxxxx" : "123456"}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          required
        />
        <p className="text-xs text-muted-foreground">
          {useRecovery
            ? "Each recovery code works once."
            : "Enter the 6-digit code from your authenticator app."}
        </p>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <Button type="submit" disabled={submitting || !value.trim()} className="mt-2">
        {submitting ? "Checking…" : "Verify"}
      </Button>
      <div className="flex justify-between text-sm">
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground"
          onClick={() => {
            setUseRecovery(!useRecovery);
            setValue("");
            setError(null);
          }}
        >
          {useRecovery ? "Use an authenticator code" : "Use a recovery code instead"}
        </button>
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
  const [needsSecondFactor, setNeedsSecondFactor] = React.useState(false);
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
      if ((await login(username, password)) === "mfa") {
        setPassword("");
        setNeedsSecondFactor(true);
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
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="font-mono text-xl text-primary">AnsiDeck</CardTitle>
          <CardDescription>
            {needsSecondFactor
              ? "Two-factor login is on for this account."
              : "Sign in to run playbooks against your infrastructure."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {needsSecondFactor ? (
            <SecondFactorForm onStartOver={() => setNeedsSecondFactor(false)} />
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
    </div>
  );
}

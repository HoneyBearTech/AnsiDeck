import * as React from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, SSO_LOGIN_URL, type AuthProviders } from "@/lib/api";

// The server only ever sends a generic code; the real reason is in the audit log.
const SSO_MESSAGES: Record<string, string> = {
  not_linked: "No AnsiDeck account is linked to this identity. Ask an admin to add you.",
  failed: "SSO sign-in failed. Try again, or sign in with your password.",
};

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
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
      await login(username, password);
      navigate("/");
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
          <CardDescription>Sign in to run playbooks against your infrastructure.</CardDescription>
        </CardHeader>
        <CardContent>
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
          {providers?.oidc.enabled && (
            <div className="mt-4 flex flex-col gap-3">
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                or
                <span className="h-px flex-1 bg-border" />
              </div>
              <Button type="button" variant="outline" onClick={() => window.location.assign(SSO_LOGIN_URL)}>
                Sign in with {providers.oidc.label}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type User } from "@/lib/api";

import { problemMessage, RecoveryCodes } from "./recovery-codes";

/** New recovery codes (for the authenticator app and passkeys alike); the old ones stop working. */
export function RecoveryCodesCard({ user }: { user: User }) {
  const [step, setStep] = React.useState<"idle" | "password" | string[]>("idle");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);

  function goTo(next: typeof step) {
    setStep(next);
    setPassword("");
    setError(null);
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setWorking(true);
    try {
      goTo((await api.regenerateRecoveryCodes(password)).recovery_codes);
    } catch (err) {
      setError(problemMessage(err));
    } finally {
      setWorking(false);
    }
  }

  let body: React.ReactNode;
  if (Array.isArray(step)) {
    body = <RecoveryCodes codes={step} onDone={() => goTo("idle")} />;
  } else if (step === "password") {
    body = (
      <form onSubmit={handleSubmit} className="flex max-w-md flex-col gap-4">
        <input type="text" autoComplete="username" value={user.username} readOnly hidden />
        <div className="flex flex-col gap-2">
          <Label htmlFor="recovery-password">Current password</Label>
          <Input
            id="recovery-password"
            type="password"
            autoComplete="current-password"
            // oxlint-disable-next-line jsx-a11y/no-autofocus -- shown after the user asked for new codes; the field is the next step
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex gap-2">
          <Button type="submit" disabled={working || !password}>
            {working ? "Checking…" : "Create new codes"}
          </Button>
          <Button type="button" variant="outline" onClick={() => goTo("idle")}>
            Cancel
          </Button>
        </div>
      </form>
    );
  } else {
    body = (
      <Button variant="outline" size="sm" className="self-start" onClick={() => goTo("password")}>
        New recovery codes
      </Button>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recovery codes</CardTitle>
        <CardDescription>
          Each one signs you in once in place of your authenticator app or a passkey. New codes replace the
          old ones.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col">{body}</CardContent>
    </Card>
  );
}

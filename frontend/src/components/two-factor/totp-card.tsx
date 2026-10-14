import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, type TotpSetup, type User } from "@/lib/api";

import { problemMessage, RecoveryCodes } from "./recovery-codes";
import { SecondFactorProofForm } from "./second-factor-proof";

type Step =
  | { kind: "idle" }
  | { kind: "password" }
  | { kind: "scan"; setup: TotpSetup }
  | { kind: "codes"; codes: string[] }
  | { kind: "disable" };

/** An authenticator app (TOTP): set up, or turn off with the password and a current second factor. */
export function TotpCard({ user }: { user: User }) {
  const { refreshUser } = useAuth();
  const [step, setStep] = React.useState<Step>({ kind: "idle" });
  const [password, setPassword] = React.useState("");
  const [code, setCode] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);
  const enabled = user.totp_enabled;

  function goTo(next: Step) {
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
      setError(problemMessage(err));
    } finally {
      setWorking(false);
    }
  }

  function handlePassword(event: React.FormEvent) {
    event.preventDefault();
    void attempt(async () => goTo({ kind: "scan", setup: await api.totpSetup(password) }));
  }

  function handleEnable(event: React.FormEvent) {
    event.preventDefault();
    void attempt(async () => {
      const { recovery_codes } = await api.totpEnable(code);
      if (recovery_codes) {
        // The account changes (and, during required setup, the page) once they're saved.
        goTo({ kind: "codes", codes: recovery_codes });
      } else {
        await refreshUser();
        goTo({ kind: "idle" });
      }
    });
  }

  let body: React.ReactNode;
  if (step.kind === "codes") {
    body = (
      <RecoveryCodes
        codes={step.codes}
        onDone={() => {
          goTo({ kind: "idle" });
          void refreshUser();
        }}
      />
    );
  } else if (step.kind === "scan") {
    body = (
      <form onSubmit={handleEnable} className="flex max-w-md flex-col gap-4">
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
    body = (
      <form onSubmit={handlePassword} className="flex max-w-md flex-col gap-4">
        <input type="text" autoComplete="username" value={user.username} readOnly hidden />
        <div className="flex flex-col gap-2">
          <Label htmlFor="totp-password">Current password</Label>
          <Input
            id="totp-password"
            type="password"
            autoComplete="current-password"
            // oxlint-disable-next-line jsx-a11y/no-autofocus -- shown after the user starts 2FA setup; the field is the next step
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex gap-2">
          <Button type="submit" disabled={working || !password}>
            {working ? "Checking…" : "Continue"}
          </Button>
          <Button type="button" variant="outline" onClick={() => goTo({ kind: "idle" })}>
            Cancel
          </Button>
        </div>
      </form>
    );
  } else if (step.kind === "disable") {
    body = (
      <SecondFactorProofForm
        idPrefix="totp"
        username={user.username}
        hasTotp
        hasPasskeys={(user.passkey_count ?? 0) > 0}
        submitLabel="Turn off"
        onSubmit={async (currentPassword, proof) => {
          await api.totpDisable(currentPassword, proof);
          await refreshUser();
          goTo({ kind: "idle" });
        }}
        onCancel={() => goTo({ kind: "idle" })}
      />
    );
  } else if (enabled) {
    body = (
      <div className="flex flex-col gap-4">
        <p className="text-sm">
          <span className="text-status-ok">On.</span> After your password you can enter a code from your
          authenticator app.
        </p>
        <Button variant="outline" size="sm" className="self-start" onClick={() => goTo({ kind: "disable" })}>
          Turn off
        </Button>
      </div>
    );
  } else {
    body = (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">
          Off. Turn it on to sign in with a code from an authenticator app (such as 1Password, Google
          Authenticator or Aegis) after your password.
        </p>
        <Button className="self-start" onClick={() => goTo({ kind: "password" })}>
          Set up an authenticator app
        </Button>
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Authenticator app
          {enabled && <Badge variant="ok">on</Badge>}
        </CardTitle>
        <CardDescription>Six-digit codes that change every 30 seconds.</CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  );
}

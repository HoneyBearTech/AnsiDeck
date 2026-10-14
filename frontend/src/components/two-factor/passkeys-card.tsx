import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, type AuthProviders, type Passkey, type User } from "@/lib/api";
import { createPasskey, passkeysSupported } from "@/lib/webauthn";

import { problemMessage, RecoveryCodes } from "./recovery-codes";
import { SecondFactorProofForm } from "./second-factor-proof";

type Step =
  | { kind: "idle" }
  | { kind: "add" }
  | { kind: "codes"; codes: string[] }
  | { kind: "rename"; passkey: Passkey }
  | { kind: "remove"; passkey: Passkey };

function when(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "never";
}

// Why passkeys can't be added here, if they can't.
function unavailable(providers: AuthProviders | null): string | null {
  const passkeys = providers?.passkeys;
  if (!passkeys?.enabled || !passkeys.origin) {
    return "Passkeys aren't available on this server: an admin needs to set PUBLIC_URL to its https:// address.";
  }
  if (passkeys.origin !== window.location.origin) {
    return `Passkeys work at ${passkeys.origin} only. Open AnsiDeck there to add or use one.`;
  }
  if (!passkeysSupported()) return "This browser doesn't support passkeys.";
  return null;
}

function nextName(passkeys: Passkey[]): string {
  const names = new Set(passkeys.map((p) => p.name));
  let n = passkeys.length + 1;
  while (names.has(`Passkey ${n}`)) n++;
  return `Passkey ${n}`;
}

/** Passkeys: a second factor from the device's own unlock (Touch ID, Windows Hello, a phone, a security
 * key). Adding one asks for the password; removing one for the password and a current second factor. */
export function PasskeysCard({ user, providers }: { user: User; providers: AuthProviders | null }) {
  const { refreshUser } = useAuth();
  const [passkeys, setPasskeys] = React.useState<Passkey[] | null>(null);
  const [step, setStep] = React.useState<Step>({ kind: "idle" });
  const [password, setPassword] = React.useState("");
  const [name, setName] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);
  const problem = unavailable(providers);

  const load = React.useCallback(async () => {
    setPasskeys(await api.listPasskeys());
  }, []);

  React.useEffect(() => {
    api
      .listPasskeys()
      .then(setPasskeys)
      .catch((err: unknown) => setError(problemMessage(err)));
  }, []);

  function goTo(next: Step) {
    setStep(next);
    setPassword("");
    setName(next.kind === "add" ? nextName(passkeys ?? []) : next.kind === "rename" ? next.passkey.name : "");
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

  function handleAdd(event: React.FormEvent) {
    event.preventDefault();
    void attempt(async () => {
      const { options } = await api.passkeyRegistrationOptions(password);
      const credential = await createPasskey(options);
      const { recovery_codes } = await api.addPasskey(name.trim(), credential);
      await load();
      if (recovery_codes) {
        // The account changes (and, during required setup, the page) once they're saved.
        goTo({ kind: "codes", codes: recovery_codes });
      } else {
        await refreshUser();
        goTo({ kind: "idle" });
      }
    });
  }

  function handleRename(event: React.FormEvent) {
    event.preventDefault();
    if (step.kind !== "rename") return;
    void attempt(async () => {
      await api.renamePasskey(step.passkey.id, name.trim());
      await load();
      goTo({ kind: "idle" });
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
  } else if (step.kind === "add") {
    body = (
      <form onSubmit={handleAdd} className="flex max-w-md flex-col gap-4">
        <input type="text" autoComplete="username" value={user.username} readOnly hidden />
        <div className="flex flex-col gap-2">
          <Label htmlFor="passkey-password">Current password</Label>
          <Input
            id="passkey-password"
            type="password"
            autoComplete="current-password"
            // oxlint-disable-next-line jsx-a11y/no-autofocus -- shown after the user chose to add a passkey; the field is the next step
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="passkey-name">Name</Label>
          <Input
            id="passkey-name"
            maxLength={64}
            value={name}
            onChange={(e) => setName(e.target.value)}
            aria-describedby="passkey-name-hint"
          />
          <p id="passkey-name-hint" className="text-xs text-muted-foreground">
            To tell your passkeys apart, e.g. "Work laptop" or "YubiKey".
          </p>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex gap-2">
          <Button type="submit" disabled={working || !password || !name.trim()}>
            {working ? "Waiting for your passkey…" : "Add passkey"}
          </Button>
          <Button type="button" variant="outline" onClick={() => goTo({ kind: "idle" })}>
            Cancel
          </Button>
        </div>
      </form>
    );
  } else if (step.kind === "remove") {
    body = (
      <SecondFactorProofForm
        idPrefix="passkey-remove"
        username={user.username}
        hasTotp={user.totp_enabled}
        hasPasskeys
        intro={
          <p className="text-sm">
            Remove <span className="font-medium">{step.passkey.name}</span>? It can't sign you in any more.
          </p>
        }
        submitLabel="Remove"
        onSubmit={async (currentPassword, proof) => {
          await api.removePasskey(step.passkey.id, currentPassword, proof);
          await load();
          await refreshUser();
          goTo({ kind: "idle" });
        }}
        onCancel={() => goTo({ kind: "idle" })}
      />
    );
  } else {
    body = (
      <div className="flex flex-col gap-4">
        {passkeys && passkeys.length > 0 ? (
          <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
            {passkeys.map((passkey) => (
              <li key={passkey.id} className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center">
                {step.kind === "rename" && step.passkey.id === passkey.id ? (
                  <form onSubmit={handleRename} className="flex flex-1 flex-wrap items-center gap-2">
                    <Label htmlFor="passkey-rename" className="sr-only">
                      New name
                    </Label>
                    <Input
                      id="passkey-rename"
                      className="max-w-xs"
                      maxLength={64}
                      // oxlint-disable-next-line jsx-a11y/no-autofocus -- the user just chose Rename
                      autoFocus
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                    <Button type="submit" size="sm" disabled={working || !name.trim()}>
                      Save
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => goTo({ kind: "idle" })}>
                      Cancel
                    </Button>
                  </form>
                ) : (
                  <>
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-medium break-all">{passkey.name}</span>
                        {passkey.synced && <Badge variant="outline">synced</Badge>}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        added {when(passkey.created_at)} · last used {when(passkey.last_used_at)}
                      </span>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        aria-label={`Rename ${passkey.name}`}
                        onClick={() => goTo({ kind: "rename", passkey })}
                      >
                        Rename
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        aria-label={`Remove ${passkey.name}`}
                        onClick={() => goTo({ kind: "remove", passkey })}
                      >
                        Remove
                      </Button>
                    </div>
                  </>
                )}
              </li>
            ))}
          </ul>
        ) : (
          passkeys && (
            <p className="text-sm text-muted-foreground">
              None yet. A passkey confirms it's you with your device's own unlock (Touch ID, Windows Hello,
              your phone, or a security key) after your password.
            </p>
          )
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        {problem ? (
          <p className="text-sm text-muted-foreground">{problem}</p>
        ) : (
          <Button className="self-start" onClick={() => goTo({ kind: "add" })}>
            Add a passkey
          </Button>
        )}
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Passkeys
          {(user.passkey_count ?? 0) > 0 && <Badge variant="ok">on</Badge>}
        </CardTitle>
        <CardDescription>Your fingerprint, face, screen lock or a security key.</CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  );
}

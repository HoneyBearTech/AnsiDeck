import * as React from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type SecondFactorProof } from "@/lib/api";
import { getPasskey, passkeysSupported } from "@/lib/webauthn";

import { problemMessage } from "./recovery-codes";

async function passkeyProof(): Promise<SecondFactorProof> {
  const { options } = await api.passkeyStepUpOptions();
  return { passkey: await getPasskey(options) };
}

/** Turning a second factor off: the current password and a current second factor (a code, a recovery
 * code, or one of your passkeys). */
export function SecondFactorProofForm({
  idPrefix,
  username,
  hasTotp,
  hasPasskeys,
  intro,
  submitLabel,
  onSubmit,
  onCancel,
}: {
  idPrefix: string;
  username: string;
  hasTotp: boolean;
  hasPasskeys: boolean;
  intro?: React.ReactNode;
  submitLabel: string;
  onSubmit: (password: string, proof: SecondFactorProof) => Promise<void>;
  onCancel: () => void;
}) {
  const [password, setPassword] = React.useState("");
  const [code, setCode] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);
  const canUsePasskey = hasPasskeys && passkeysSupported();

  async function attempt(proof: () => Promise<SecondFactorProof>) {
    setError(null);
    setWorking(true);
    try {
      await onSubmit(password, await proof());
    } catch (err) {
      setError(problemMessage(err));
    } finally {
      setWorking(false);
    }
  }

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    void attempt(async () => ({ code: code.trim() }));
  }

  return (
    <form onSubmit={handleSubmit} className="flex max-w-md flex-col gap-4">
      {intro}
      <input type="text" autoComplete="username" value={username} readOnly hidden />
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${idPrefix}-password`}>Current password</Label>
        <Input
          id={`${idPrefix}-password`}
          type="password"
          autoComplete="current-password"
          // oxlint-disable-next-line jsx-a11y/no-autofocus -- shown after the user chose to turn something off; the field is the next step
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${idPrefix}-code`}>
          {hasTotp ? "Authentication code or recovery code" : "Recovery code"}
        </Label>
        <Input
          id={`${idPrefix}-code`}
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          aria-describedby={canUsePasskey ? `${idPrefix}-code-hint` : undefined}
        />
        {canUsePasskey && (
          <p id={`${idPrefix}-code-hint`} className="text-xs text-muted-foreground">
            Or confirm with one of your passkeys instead.
          </p>
        )}
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="destructive" disabled={working || !password || !code.trim()}>
          {working ? "Checking…" : submitLabel}
        </Button>
        {canUsePasskey && (
          <Button
            type="button"
            variant="outline"
            disabled={working || !password}
            onClick={() => void attempt(passkeyProof)}
          >
            Use a passkey
          </Button>
        )}
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, type SecretCheck, type SecretRef, type SecretStoreInfo } from "@/lib/api";

export type SourceMode = "ansideck" | "external";

/** "Stored in AnsiDeck" or "In OpenBao at <project's base path>/<path>#<key>". */
export function SecretSourcePicker({
  info,
  mode,
  onModeChange,
  path,
  onPathChange,
  secretKey,
  onSecretKeyChange,
  idPrefix,
}: {
  info: SecretStoreInfo | null;
  mode: SourceMode;
  onModeChange: (mode: SourceMode) => void;
  path: string;
  onPathChange: (path: string) => void;
  secretKey: string;
  onSecretKeyChange: (key: string) => void;
  idPrefix: string;
}) {
  if (!info?.enabled) return null;
  return (
    <div className="flex flex-col gap-3 rounded-md border border-border p-3">
      <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Where the secret lives">
        {(["ansideck", "external"] as const).map((value) => (
          <Button
            key={value}
            type="button"
            size="sm"
            role="radio"
            aria-checked={mode === value}
            variant={mode === value ? "default" : "outline"}
            onClick={() => onModeChange(value)}
          >
            {value === "ansideck" ? "Stored in AnsiDeck (encrypted)" : `In ${info.label}`}
          </Button>
        ))}
      </div>
      {mode === "external" && (
        <>
          <div className="flex flex-col gap-2">
            <Label htmlFor={`${idPrefix}-store-path`}>Path in {info.label}</Label>
            <div className="flex items-center rounded-md border border-input bg-background font-mono text-sm">
              <span className="whitespace-nowrap border-r border-border px-2 py-2 text-muted-foreground">
                {info.base_path}
              </span>
              <input
                id={`${idPrefix}-store-path`}
                value={path}
                onChange={(e) => onPathChange(e.target.value)}
                placeholder="web/ssh"
                spellCheck={false}
                className="min-w-0 flex-1 bg-transparent px-2 py-2 outline-none"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Under this project's subtree only: {info.path_rules}.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor={`${idPrefix}-store-key`}>Key in that secret</Label>
            <Input
              id={`${idPrefix}-store-key`}
              value={secretKey}
              onChange={(e) => onSecretKeyChange(e.target.value)}
              className="font-mono"
              spellCheck={false}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            AnsiDeck reads the value once now to check it, and again whenever a run needs it; it never stores
            it. Rotate it in {info.label}: the next run uses the new version.
          </p>
        </>
      )}
    </div>
  );
}

/** Where a secret lives, for list cards. */
export function SecretLocation({ row, label }: { row: SecretRef; label: string | undefined }) {
  if (row.store !== "external") return null;
  return (
    <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <Badge variant="outline">{label ?? "secret store"}</Badge>
      <span className="font-mono">{row.store_location}</span>
    </span>
  );
}

/** "Test": can AnsiDeck read the stored secret right now (never shows it). */
export function SecretCheckButton({ check }: { check: () => Promise<SecretCheck> }) {
  const [result, setResult] = React.useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = React.useState(false);

  async function handleCheck() {
    setBusy(true);
    setResult(null);
    try {
      const outcome = await check();
      setResult(
        outcome.ok
          ? { ok: true, text: outcome.version ? `Readable (version ${outcome.version})` : "Readable" }
          : { ok: false, text: outcome.error ?? "Can't be read" },
      );
    } catch (err) {
      setResult({ ok: false, text: err instanceof ApiError ? err.message : "Something went wrong" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="flex items-center gap-2">
      {result && (
        <span className={result.ok ? "text-xs text-status-ok" : "text-xs text-destructive"}>
          {result.text}
        </span>
      )}
      <Button variant="outline" size="sm" disabled={busy} onClick={handleCheck}>
        {busy ? "Testing…" : "Test"}
      </Button>
    </span>
  );
}

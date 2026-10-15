import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  type ReferenceUpdate,
  type SecretCheck,
  type SecretRef,
  type SecretStoreInfo,
} from "@/lib/api";

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
  /** Omitted for an env credential: every key of the secret becomes a variable. */
  secretKey?: string;
  onSecretKeyChange?: (key: string) => void;
  idPrefix: string;
}) {
  if (!info?.enabled) return null;
  return (
    <div className="flex flex-col gap-3 rounded-md border border-border p-3">
      <fieldset className="flex flex-wrap gap-2">
        <legend className="sr-only">Where the secret lives</legend>
        {(["ansideck", "external"] as const).map((value) => (
          <Button
            key={value}
            type="button"
            size="sm"
            aria-pressed={mode === value}
            variant={mode === value ? "default" : "outline"}
            onClick={() => onModeChange(value)}
          >
            {value === "ansideck" ? "Stored in AnsiDeck (encrypted)" : `In ${info.label}`}
          </Button>
        ))}
      </fieldset>
      {mode === "external" && (
        <StorePathFields
          info={info}
          path={path}
          onPathChange={onPathChange}
          secretKey={secretKey}
          onSecretKeyChange={onSecretKeyChange}
          idPrefix={idPrefix}
        />
      )}
    </div>
  );
}

/** Where in the store: a path under the project's subtree and (unless the whole secret is
 * meant, for an env credential) a key in that secret. */
export function StorePathFields({
  info,
  path,
  onPathChange,
  secretKey,
  onSecretKeyChange,
  idPrefix,
}: {
  info: SecretStoreInfo;
  path: string;
  onPathChange: (path: string) => void;
  secretKey?: string | undefined;
  onSecretKeyChange?: ((key: string) => void) | undefined;
  idPrefix: string;
}) {
  const wholeSecret = onSecretKeyChange === undefined;
  return (
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
        <p className="text-xs text-muted-foreground">Under this project's subtree only: {info.path_rules}.</p>
      </div>
      {wholeSecret ? (
        <p className="text-xs text-muted-foreground">
          Every key in that secret becomes an environment variable of the same name.
        </p>
      ) : (
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
      )}
      <p className="text-xs text-muted-foreground">
        AnsiDeck reads the value once now to check it, and again whenever a run needs it; it never stores it.
        Rotate it in {info.label}: the next run uses the new version.
      </p>
    </>
  );
}

/** "Edit reference": points a secret in the store at another path or key. The server reads it
 * once to check it; queued runs then use the new reference. */
export function EditReferenceDialog({
  row,
  info,
  wholeSecret = false,
  save,
  onSaved,
  idPrefix,
}: {
  row: SecretRef & { name: string };
  info: SecretStoreInfo | null;
  /** An env credential: the whole secret, no key. */
  wholeSecret?: boolean;
  save: (update: ReferenceUpdate) => Promise<unknown>;
  onSaved: () => void;
  idPrefix: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [path, setPath] = React.useState(row.store_path ?? "");
  const [key, setKey] = React.useState(row.store_key ?? "");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  function handleOpenChange(next: boolean) {
    if (next) {
      setPath(row.store_path ?? "");
      setKey(row.store_key ?? "");
      setError(null);
    }
    setOpen(next);
  }

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      await save(
        wholeSecret ? { store_path: path.trim() } : { store_path: path.trim(), store_key: key.trim() },
      );
      setOpen(false);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  if (!info?.enabled || row.store !== "external" || row.store_path === null) return null;
  const unchanged = path.trim() === row.store_path && (wholeSecret || key.trim() === row.store_key);
  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          Edit reference
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit the reference of "{row.name}"</DialogTitle>
          <DialogDescription>
            Now at <span className="font-mono wrap-anywhere">{row.store_location}</span>. Queued runs use the
            new reference when they start.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <StorePathFields
            info={info}
            path={path}
            onPathChange={setPath}
            secretKey={wholeSecret ? undefined : key}
            onSecretKeyChange={wholeSecret ? undefined : setKey}
            idPrefix={idPrefix}
          />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button
            onClick={handleSave}
            disabled={saving || unchanged || !path.trim() || (!wholeSecret && !key.trim())}
          >
            {saving ? "Checking…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
export function SecretCheckButton({
  check,
  describe,
}: {
  check: () => Promise<SecretCheck>;
  /** What a successful check says (default: "Readable", with the secret's version). */
  describe?: ((outcome: SecretCheck) => string) | undefined;
}) {
  const [result, setResult] = React.useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = React.useState(false);

  async function handleCheck() {
    setBusy(true);
    setResult(null);
    try {
      const outcome = await check();
      setResult(
        outcome.ok
          ? {
              ok: true,
              text: describe
                ? describe(outcome)
                : outcome.version
                  ? `Readable (version ${outcome.version})`
                  : "Readable",
            }
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

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  SecretCheckButton,
  SecretLocation,
  SecretSourcePicker,
  type SourceMode,
} from "@/components/secret-source";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type Credential, type CredentialKind, type SecretStoreInfo } from "@/lib/api";
import { useSecretStoreInfo } from "@/lib/secret-store";

type EnvRow = { name: string; value: string };

const KIND_LABELS: Record<CredentialKind, string> = {
  ssh: "SSH key",
  env: "Environment variables",
};

/** Name/value rows for an env credential; values are never shown again once saved. */
function EnvRows({ rows, onChange }: { rows: EnvRow[]; onChange: (rows: EnvRow[]) => void }) {
  function update(index: number, change: Partial<EnvRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...change } : row)));
  }
  return (
    <div className="flex flex-col gap-2">
      <Label>Variables</Label>
      {rows.map((row, index) => (
        <div key={index} className="flex items-center gap-2">
          <Input
            aria-label={`Variable ${index + 1} name`}
            value={row.name}
            onChange={(e) => update(index, { name: e.target.value.toUpperCase() })}
            placeholder="NETBOX_TOKEN"
            className="font-mono"
            spellCheck={false}
          />
          <Input
            aria-label={`Variable ${index + 1} value`}
            type="password"
            autoComplete="off"
            value={row.value}
            onChange={(e) => update(index, { value: e.target.value })}
            placeholder="value"
          />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            aria-label={`Remove variable ${index + 1}`}
            disabled={rows.length === 1}
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
          >
            ×
          </Button>
        </div>
      ))}
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange([...rows, { name: "", value: "" }])}
        >
          Add variable
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Stored encrypted and given only to inventory sources that use this credential (for example a NetBox
        token as NETBOX_TOKEN); values are never shown again. Put settings that aren&apos;t secret in the
        source&apos;s config instead.
      </p>
    </div>
  );
}

function CreateCredentialDialog({
  onCreated,
  store,
}: {
  onCreated: () => void;
  store: SecretStoreInfo | null;
}) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [privateKey, setPrivateKey] = React.useState("");
  const [kind, setKind] = React.useState<CredentialKind>("ssh");
  const [envRows, setEnvRows] = React.useState<EnvRow[]>([{ name: "", value: "" }]);
  const [mode, setMode] = React.useState<SourceMode>("ansideck");
  const [storePath, setStorePath] = React.useState("");
  const [storeKey, setStoreKey] = React.useState("private_key");
  const external = mode === "external" && !!store?.enabled;
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setPrivateKey(await file.text());
  }

  async function handleCreate() {
    setError(null);
    setSaving(true);
    try {
      if (kind === "env") {
        await api.createEnvCredential(
          name,
          external
            ? { kind: "external", path: storePath.trim() }
            : {
                kind: "ansideck",
                env: Object.fromEntries(envRows.map((row) => [row.name.trim(), row.value])),
              },
          description || undefined,
        );
      } else {
        await api.createCredential(
          name,
          external
            ? { kind: "external", path: storePath.trim(), key: storeKey.trim() }
            : { kind: "ansideck", value: privateKey },
          description || undefined,
        );
      }
      setName("");
      setDescription("");
      setPrivateKey("");
      setEnvRows([{ name: "", value: "" }]);
      setStorePath("");
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>New Credential</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Credential</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="credential-name">Name</Label>
            <Input id="credential-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="credential-description">Description</Label>
            <Input
              id="credential-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Credential kind">
            {(["ssh", "env"] as const).map((value) => (
              <Button
                key={value}
                type="button"
                size="sm"
                role="radio"
                aria-checked={kind === value}
                variant={kind === value ? "default" : "outline"}
                onClick={() => setKind(value)}
              >
                {KIND_LABELS[value]}
              </Button>
            ))}
          </div>
          {kind === "ssh" ? (
            <SecretSourcePicker
              info={store}
              mode={mode}
              onModeChange={setMode}
              path={storePath}
              onPathChange={setStorePath}
              secretKey={storeKey}
              onSecretKeyChange={setStoreKey}
              idPrefix="credential"
            />
          ) : (
            <SecretSourcePicker
              info={store}
              mode={mode}
              onModeChange={setMode}
              path={storePath}
              onPathChange={setStorePath}
              idPrefix="credential"
            />
          )}
          {kind === "env" && !external && <EnvRows rows={envRows} onChange={setEnvRows} />}
          {kind === "ssh" && !external && (
            <>
              <div className="flex flex-col gap-2">
                <Label htmlFor="credential-file">Upload private key file</Label>
                <input
                  id="credential-file"
                  type="file"
                  onChange={handleFileUpload}
                  className="text-sm text-muted-foreground"
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="credential-key">Private key (PEM)</Label>
                <Textarea
                  id="credential-key"
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  className="min-h-40 font-mono"
                  spellCheck={false}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...&#10;-----END OPENSSH PRIVATE KEY-----"
                />
                <p className="text-xs text-muted-foreground">
                  Passphrase-protected keys aren't supported yet — use an unencrypted key.
                </p>
              </div>
            </>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button
            onClick={handleCreate}
            disabled={
              saving ||
              !name ||
              (external
                ? !storePath.trim() || (kind === "ssh" && !storeKey.trim())
                : kind === "ssh"
                  ? !privateKey
                  : envRows.some((row) => !row.name.trim() || !row.value))
            }
          >
            {saving ? "Saving…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function CredentialsPage() {
  const { can } = useAuth();
  const canManage = can("secrets:manage");
  const store = useSecretStoreInfo();
  const [credentials, setCredentials] = React.useState<Credential[]>([]);
  const [loading, setLoading] = React.useState(true);

  const refresh = React.useCallback(() => {
    api.listCredentials().then((c) => {
      setCredentials(c);
      setLoading(false);
    });
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleDelete(id: number) {
    await api.deleteCredential(id);
    refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Credentials</h1>
        {canManage && <CreateCredentialDialog onCreated={refresh} store={store} />}
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && credentials.length === 0 && (
        <p className="text-sm text-muted-foreground">No credentials yet.</p>
      )}

      <div className="flex flex-col gap-2">
        {credentials.map((credential) => (
          <Card key={credential.id}>
            <CardContent className="flex items-center justify-between p-4">
              <div className="flex flex-col gap-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{credential.name}</span>
                  <Badge variant="outline">{KIND_LABELS[credential.kind]}</Badge>
                </span>
                {credential.description && (
                  <span className="text-xs text-muted-foreground">{credential.description}</span>
                )}
                <SecretLocation row={credential} label={store?.label} />
                {credential.env_names && (
                  <span className="font-mono text-xs text-muted-foreground">
                    {credential.env_names.join(" · ")}
                  </span>
                )}
              </div>
              {canManage && (
                <div className="flex items-center gap-2">
                  {credential.store === "external" && (
                    <SecretCheckButton check={() => api.checkCredential(credential.id)} />
                  )}
                  <Button variant="outline" size="sm" onClick={() => handleDelete(credential.id)}>
                    Delete
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

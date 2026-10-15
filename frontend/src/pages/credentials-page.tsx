import * as React from "react";

import { PageHeader } from "@/components/page-header";
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
import { FilePicker } from "@/components/ui/file-picker";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  EditReferenceDialog,
  MoveToStoreDialog,
  SecretCheckButton,
  SecretLocation,
  SecretSourcePicker,
  type SourceMode,
} from "@/components/secret-source";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type Credential,
  type CredentialKind,
  type SecretCheck,
  type SecretStoreInfo,
} from "@/lib/api";
import { useSecretStoreInfo } from "@/lib/secret-store";
import { useConfirmedAction } from "@/lib/use-confirmed-action";

type EnvRow = { id: number; name: string; value: string };

let nextRowId = 0;
const newEnvRow = (): EnvRow => ({ id: nextRowId++, name: "", value: "" });

const KIND_LABELS: Record<CredentialKind, string> = {
  ssh: "SSH key",
  env: "Environment variables",
  ssh_cert: "SSH certificate",
};

/** Principals as typed: separated by commas or spaces. */
function splitPrincipals(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))];
}

/** An SSH certificate credential's settings: the store's SSH engine mount, the role and principals. */
function SshCertFields({
  store,
  mount,
  onMountChange,
  role,
  onRoleChange,
  principals,
  onPrincipalsChange,
}: {
  store: SecretStoreInfo;
  mount: string;
  onMountChange: (mount: string) => void;
  role: string;
  onRoleChange: (role: string) => void;
  principals: string;
  onPrincipalsChange: (principals: string) => void;
}) {
  const mounts = store.ssh_mounts ?? [];
  const users = splitPrincipals(principals);
  return (
    <div className="flex flex-col gap-3 rounded-md border border-border p-3">
      {mounts.length > 1 ? (
        <div className="flex flex-col gap-2">
          <Label htmlFor="credential-ssh-mount">SSH engine mount</Label>
          <Select value={mount} onValueChange={onMountChange}>
            <SelectTrigger id="credential-ssh-mount">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {mounts.map((value) => (
                <SelectItem key={value} value={value}>
                  {value}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          SSH engine mount: <span className="font-mono">{mount}</span>
        </p>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="credential-ssh-role">Role in {store.label}</Label>
        <div className="flex items-center rounded-md border border-input bg-background font-mono text-sm">
          <span className="whitespace-nowrap border-r border-border px-2 py-2 text-muted-foreground">
            {store.ssh_role_prefix}
          </span>
          <input
            id="credential-ssh-role"
            value={role}
            onChange={(e) => onRoleChange(e.target.value)}
            placeholder="web"
            spellCheck={false}
            className="min-w-0 flex-1 bg-transparent px-2 py-2 outline-none"
          />
        </div>
        <p className="text-xs text-muted-foreground">
          A project signs only with its own roles: the role&apos;s name in {store.label} starts with this
          prefix.
        </p>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="credential-ssh-principals">Principals</Label>
        <Input
          id="credential-ssh-principals"
          value={principals}
          onChange={(e) => onPrincipalsChange(e.target.value)}
          placeholder="deploy, ansible"
          className="font-mono"
          spellCheck={false}
        />
        {users.length > 0 && (
          <span className="flex flex-wrap gap-1">
            {users.map((user) => (
              <Badge key={user} variant="outline" className="font-mono wrap-anywhere">
                {user}
              </Badge>
            ))}
          </span>
        )}
        <p className="text-xs text-muted-foreground">
          The users the certificate may log in as (separate them with commas or spaces): the inventory&apos;s
          ansible_user must be one of them, and the role must allow them all.
        </p>
      </div>
      <p className="text-xs text-muted-foreground">
        No key is stored: each run gets a new key and a certificate valid for its timeout plus 5 minutes.
        AnsiDeck signs a throwaway key once now to check the role. Targets trust the store&apos;s CA with
        sshd&apos;s TrustedUserCAKeys.
      </p>
    </div>
  );
}

/** What a Test shows for an SSH certificate credential. */
function certificateCheckText(outcome: SecretCheck): string {
  const certificate = outcome.certificate;
  if (!certificate) return "Signed a test certificate";
  return `Signed a test certificate: serial ${certificate.serial}, CA ${certificate.ca_fingerprint}`;
}

/** Name/value rows for an env credential; values are never shown again once saved. */
function EnvRows({ rows, onChange }: { rows: EnvRow[]; onChange: (rows: EnvRow[]) => void }) {
  function update(index: number, change: Partial<EnvRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...change } : row)));
  }
  return (
    <div className="flex flex-col gap-2">
      <Label>Variables</Label>
      {rows.map((row, index) => (
        <div key={row.id} className="flex items-center gap-2">
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
          onClick={() => onChange([...rows, newEnvRow()])}
        >
          Add variable
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Stored encrypted and given only to the inventory sources and runs that use this credential (for example
        a NetBox token as NETBOX_TOKEN, or AWS keys for cloud modules); values are never shown again, and are
        removed from output. Put settings that aren&apos;t secret in the source&apos;s config or the playbook
        instead.
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
  const [envRows, setEnvRows] = React.useState<EnvRow[]>(() => [newEnvRow()]);
  const [mode, setMode] = React.useState<SourceMode>("ansideck");
  const [storePath, setStorePath] = React.useState("");
  const [storeKey, setStoreKey] = React.useState("private_key");
  const [sshMount, setSshMount] = React.useState("");
  const [sshRole, setSshRole] = React.useState("");
  const [sshPrincipals, setSshPrincipals] = React.useState("");
  const sshMounts = store?.enabled ? (store.ssh_mounts ?? []) : [];
  const mount = sshMounts.includes(sshMount) ? sshMount : (sshMounts[0] ?? "");
  const kinds: CredentialKind[] = sshMounts.length > 0 ? ["ssh", "ssh_cert", "env"] : ["ssh", "env"];
  const external = mode === "external" && !!store?.enabled;
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleFile(file: File) {
    setPrivateKey(await file.text());
  }

  async function handleCreate() {
    setError(null);
    setSaving(true);
    try {
      if (kind === "ssh_cert") {
        await api.createSshCertCredential(
          name,
          { mount, role: sshRole.trim(), principals: splitPrincipals(sshPrincipals) },
          description || undefined,
        );
      } else if (kind === "env") {
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
      setEnvRows([newEnvRow()]);
      setStorePath("");
      setSshRole("");
      setSshPrincipals("");
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
        <Button>New credential</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New credential</DialogTitle>
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
          <fieldset className="flex flex-wrap gap-2">
            <legend className="sr-only">Credential kind</legend>
            {kinds.map((value) => (
              <Button
                key={value}
                type="button"
                size="sm"
                aria-pressed={kind === value}
                variant={kind === value ? "default" : "outline"}
                onClick={() => setKind(value)}
              >
                {value === "ssh_cert" ? `SSH certificate (from ${store?.label})` : KIND_LABELS[value]}
              </Button>
            ))}
          </fieldset>
          {kind === "ssh_cert" && store ? (
            <SshCertFields
              store={store}
              mount={mount}
              onMountChange={setSshMount}
              role={sshRole}
              onRoleChange={setSshRole}
              principals={sshPrincipals}
              onPrincipalsChange={setSshPrincipals}
            />
          ) : kind === "ssh" ? (
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
              <FilePicker id="credential-file" label="Upload private key file" onFile={handleFile} />
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
              (kind === "ssh_cert"
                ? !mount || !sshRole.trim() || splitPrincipals(sshPrincipals).length === 0
                : external
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

  const deletion = useConfirmedAction(refresh);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Credentials"
        description="SSH keys (or short-lived SSH certificates) that runs connect with, and environment variables for inventory plugins and playbooks. Stored values are never shown again."
        actions={canManage && <CreateCredentialDialog onCreated={refresh} store={store} />}
      />

      {deletion.error && <p className="text-sm text-destructive">{deletion.error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && credentials.length === 0 && (
        <p className="text-sm text-muted-foreground">No credentials yet.</p>
      )}

      <div className="flex flex-col gap-2">
        {credentials.map((credential) => (
          <Card key={credential.id}>
            <CardContent className="flex flex-wrap items-center justify-between gap-2 p-4">
              <div className="flex min-w-0 flex-col gap-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="min-w-0 font-medium wrap-anywhere">{credential.name}</span>
                  <Badge variant="outline">{KIND_LABELS[credential.kind]}</Badge>
                </span>
                {credential.description && (
                  <span className="text-xs text-muted-foreground">{credential.description}</span>
                )}
                <SecretLocation row={credential} label={store?.label} />
                {credential.env_names && (
                  <span className="font-mono text-xs text-muted-foreground wrap-anywhere">
                    {credential.env_names.join(" · ")}
                  </span>
                )}
                {credential.ssh_principals && (
                  <span className="text-xs text-muted-foreground wrap-anywhere">
                    Logs in as <span className="font-mono">{credential.ssh_principals.join(" · ")}</span>
                  </span>
                )}
              </div>
              {canManage && (
                <div className="flex items-center gap-2">
                  {credential.store === "external" && (
                    <SecretCheckButton
                      check={() => api.checkCredential(credential.id)}
                      describe={credential.kind === "ssh_cert" ? certificateCheckText : undefined}
                    />
                  )}
                  {credential.kind !== "ssh_cert" && (
                    <MoveToStoreDialog
                      row={credential}
                      info={store}
                      defaultKey="private_key"
                      wholeSecret={credential.kind === "env"}
                      keys={credential.env_names}
                      move={(update) => api.moveCredentialToStore(credential.id, update)}
                      onMoved={refresh}
                      idPrefix={`move-${credential.id}`}
                    />
                  )}
                  <EditReferenceDialog
                    row={credential}
                    info={store}
                    wholeSecret={credential.kind === "env"}
                    save={(update) => api.updateCredentialReference(credential.id, update)}
                    onSaved={refresh}
                    idPrefix={`edit-${credential.id}`}
                  />
                  <Button variant="destructive-outline" size="sm" onClick={() =>
                      deletion.run(
                        credential.kind === "ssh_cert"
                          ? `Delete the credential "${credential.name}"? Certificates already issued stay valid until they expire.`
                          : credential.store === "external"
                          ? `Delete the credential "${credential.name}"? AnsiDeck forgets the reference; the secret stays in ${store?.label ?? "the secret store"}.`
                          : `Delete the credential "${credential.name}"? Its secret is deleted for good and can't be recovered.`,
                        () => api.deleteCredential(credential.id),
                      )
                    }>
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

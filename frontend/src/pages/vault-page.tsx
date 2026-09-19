import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError, type VaultEncryptResult, type VaultPassword } from "@/lib/api";

function CreateVaultPasswordDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleCreate() {
    setError(null);
    setSaving(true);
    try {
      await api.createVaultPassword(name, password, description || undefined);
      setName("");
      setDescription("");
      setPassword("");
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
        <Button>New Vault Password</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Vault Password</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="vault-name">Name</Label>
            <Input id="vault-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="vault-description">Description</Label>
            <Input
              id="vault-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="vault-password">Vault password</Label>
            <Input
              id="vault-password"
              type="password"
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Stored encrypted and never shown again. It can only be used to run playbooks and to
              encrypt/decrypt values here.
            </p>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleCreate} disabled={saving || !name || !password}>
            {saving ? "Saving…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CopyableOutput({ label, hint, value }: { label: string; hint: string; value: string }) {
  const [copied, setCopied] = React.useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <div>
          <Label>{label}</Label>
          <p className="text-xs text-muted-foreground">{hint}</p>
        </div>
        <Button variant="outline" size="sm" onClick={handleCopy}>
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <Textarea readOnly value={value} className="min-h-28 font-mono" spellCheck={false} />
    </div>
  );
}

function VaultPasswordSelect({
  vaultPasswords,
  value,
  onChange,
}: {
  vaultPasswords: VaultPassword[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger>
        <SelectValue placeholder="Select a vault password" />
      </SelectTrigger>
      <SelectContent>
        {vaultPasswords.map((vaultPassword) => (
          <SelectItem key={vaultPassword.id} value={String(vaultPassword.id)}>
            {vaultPassword.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function EncryptCard({ vaultPasswords }: { vaultPasswords: VaultPassword[] }) {
  const [vaultPasswordId, setVaultPasswordId] = React.useState("");
  const [varName, setVarName] = React.useState("");
  const [plaintext, setPlaintext] = React.useState("");
  const [result, setResult] = React.useState<VaultEncryptResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);

  async function handleEncrypt() {
    setError(null);
    setWorking(true);
    try {
      setResult(
        await api.encryptVaultString(Number(vaultPasswordId), plaintext, varName.trim() || undefined),
      );
      setPlaintext("");
    } catch (err) {
      setResult(null);
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setWorking(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Encrypt a value</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label>Vault password</Label>
          <VaultPasswordSelect
            vaultPasswords={vaultPasswords}
            value={vaultPasswordId}
            onChange={setVaultPasswordId}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="encrypt-var-name">Variable name (optional)</Label>
          <Input
            id="encrypt-var-name"
            placeholder="e.g. db_password"
            value={varName}
            onChange={(e) => setVarName(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="encrypt-plaintext">Value to encrypt</Label>
          <Textarea
            id="encrypt-plaintext"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            className="min-h-24 font-mono"
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div>
          <Button onClick={handleEncrypt} disabled={working || !vaultPasswordId || !plaintext}>
            {working ? "Encrypting…" : "Encrypt"}
          </Button>
        </div>

        {result && (
          <div className="flex flex-col gap-4 border-t border-border pt-4">
            <CopyableOutput
              label="For playbook YAML"
              hint="Paste under a play's vars: (or vars_files). Needs a vault password when the run is triggered."
              value={result.yaml_block}
            />
            <CopyableOutput
              label="For extra-vars JSON"
              hint="Use as a plain string value in the run's Extra vars JSON."
              value={result.vault_text}
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function DecryptCard({ vaultPasswords }: { vaultPasswords: VaultPassword[] }) {
  const [vaultPasswordId, setVaultPasswordId] = React.useState("");
  const [ciphertext, setCiphertext] = React.useState("");
  const [plaintext, setPlaintext] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [working, setWorking] = React.useState(false);

  async function handleDecrypt() {
    setError(null);
    setWorking(true);
    try {
      const result = await api.decryptVaultString(Number(vaultPasswordId), ciphertext);
      setPlaintext(result.plaintext);
    } catch (err) {
      setPlaintext(null);
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setWorking(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Decrypt a value</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label>Vault password</Label>
          <VaultPasswordSelect
            vaultPasswords={vaultPasswords}
            value={vaultPasswordId}
            onChange={setVaultPasswordId}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="decrypt-ciphertext">Encrypted value</Label>
          <Textarea
            id="decrypt-ciphertext"
            value={ciphertext}
            onChange={(e) => setCiphertext(e.target.value)}
            className="min-h-28 font-mono"
            spellCheck={false}
            placeholder="Paste a $ANSIBLE_VAULT;… envelope, or a full `name: !vault |` block"
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div>
          <Button onClick={handleDecrypt} disabled={working || !vaultPasswordId || !ciphertext}>
            {working ? "Decrypting…" : "Decrypt"}
          </Button>
        </div>

        {plaintext !== null && (
          <div className="border-t border-border pt-4">
            <CopyableOutput label="Decrypted value" hint="Shown only in this page." value={plaintext} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function VaultPage() {
  const [vaultPasswords, setVaultPasswords] = React.useState<VaultPassword[]>([]);
  const [loading, setLoading] = React.useState(true);

  const refresh = React.useCallback(() => {
    api.listVaultPasswords().then((v) => {
      setVaultPasswords(v);
      setLoading(false);
    });
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleDelete(id: number) {
    await api.deleteVaultPassword(id);
    refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Vault</h1>
        <CreateVaultPasswordDialog onCreated={refresh} />
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && vaultPasswords.length === 0 && (
        <p className="text-sm text-muted-foreground">
          No vault passwords yet. Add one to encrypt values and to decrypt them during runs.
        </p>
      )}

      <div className="flex flex-col gap-2">
        {vaultPasswords.map((vaultPassword) => (
          <Card key={vaultPassword.id}>
            <CardContent className="flex items-center justify-between p-4">
              <div className="flex flex-col gap-1">
                <span className="font-medium">{vaultPassword.name}</span>
                {vaultPassword.description && (
                  <span className="text-xs text-muted-foreground">{vaultPassword.description}</span>
                )}
              </div>
              <Button variant="outline" size="sm" onClick={() => handleDelete(vaultPassword.id)}>
                Delete
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {vaultPasswords.length > 0 && (
        <div className="grid gap-6 md:grid-cols-2">
          <EncryptCard vaultPasswords={vaultPasswords} />
          <DecryptCard vaultPasswords={vaultPasswords} />
        </div>
      )}
    </div>
  );
}

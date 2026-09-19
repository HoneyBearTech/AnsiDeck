import * as React from "react";

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
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type Credential } from "@/lib/api";

function CreateCredentialDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [privateKey, setPrivateKey] = React.useState("");
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
      await api.createCredential(name, privateKey, description || undefined);
      setName("");
      setDescription("");
      setPrivateKey("");
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
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleCreate} disabled={saving || !name || !privateKey}>
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
        {canManage && <CreateCredentialDialog onCreated={refresh} />}
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
                <span className="font-medium">{credential.name}</span>
                {credential.description && (
                  <span className="text-xs text-muted-foreground">{credential.description}</span>
                )}
              </div>
              {canManage && (
                <Button variant="outline" size="sm" onClick={() => handleDelete(credential.id)}>
                  Delete
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

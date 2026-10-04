import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/auth-context";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError, type PlaybookDetail } from "@/lib/api";

export function PlaybookDetailPage() {
  const { can } = useAuth();
  const [synced, setSynced] = React.useState<PlaybookDetail | null>(null);
  const canWrite = can("content:write") && synced === null;
  const params = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isNew = params.id === undefined;
  const playbookId = params.id ? Number(params.id) : null;

  const [name, setName] = React.useState("");
  const [content, setContent] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [loading, setLoading] = React.useState(!isNew);

  React.useEffect(() => {
    if (playbookId === null) return;
    api.getPlaybook(playbookId).then((playbook) => {
      setName(playbook.name);
      setContent(playbook.content);
      setSynced(playbook.source_id !== null ? playbook : null);
      setLoading(false);
    });
  }, [playbookId]);

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setContent(text);
    if (!name) setName(file.name);
  }

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      if (playbookId === null) {
        const created = await api.createPlaybook(name, content);
        navigate(`/playbooks/${created.id}`);
      } else {
        await api.updatePlaybook(playbookId, { name, content });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">
        {isNew ? "New Playbook" : canWrite ? "Edit Playbook" : "Playbook"}
      </h1>

      {synced && (
        <p className="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
          Synced from the git source <span className="font-medium text-foreground">{synced.source_name}</span>{" "}
          (<span className="font-mono">{synced.repo_path}</span>
          {synced.commit && (
            <>
              {" "}
              at <span className="font-mono">{synced.commit.slice(0, 8)}</span>
            </>
          )}
          ). It is read-only here: change it in the repository.
          {synced.missing_at && " It has been removed from the repository, so it can no longer run."}
        </p>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-name">Name</Label>
        <Input
          id="playbook-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          readOnly={!canWrite}
        />
      </div>

      {canWrite && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="playbook-file">Upload YAML file</Label>
          <input
            id="playbook-file"
            type="file"
            accept=".yml,.yaml"
            onChange={handleFileUpload}
            className="text-sm text-muted-foreground"
          />
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-content">Content</Label>
        <Textarea
          id="playbook-content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          readOnly={!canWrite}
          className="min-h-96 font-mono"
          spellCheck={false}
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {canWrite && (
        <div>
          <Button onClick={handleSave} disabled={saving || !name || !content}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </div>
      )}
    </div>
  );
}
